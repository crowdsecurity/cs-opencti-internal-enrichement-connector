# -*- coding: utf-8 -*-
"""CrowdSec internal enrichment module."""
import os
from pathlib import Path
from typing import Dict, Any
from urllib.parse import urljoin

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

from .builder import CrowdSecBuilder
from .client import CrowdSecClient, QuotaExceedException
from .constants import CTI_URL
from .helper import clean_config


class CrowdSecConnector:

    def __init__(self):
        # Instantiate the connector helper from config
        self.crowdsec_ent = None

        config_file_path = Path(__file__).parent.parent.resolve() / "config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.crowdsec_cti_key = clean_config(
            get_config_variable("CROWDSEC_KEY", ["crowdsec", "key"], config)
        )
        self.crowdsec_api_version = clean_config(
            get_config_variable("CROWDSEC_VERSION", ["crowdsec", "api_version"], config)
        )

        self.max_tlp = clean_config(
            get_config_variable("CROWDSEC_MAX_TLP", ["crowdsec", "max_tlp"], config)
        )
        raw_indicator_create_from = clean_config(
            get_config_variable(
                "CROWDSEC_INDICATOR_CREATE_FROM",
                ["crowdsec", "indicator_create_from"],
                config,
                default="",
            )
        )

        self.indicator_create_from = raw_indicator_create_from.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE",
            ["crowdsec", "attack_pattern_create_from_mitre"],
            config,
            default=False,
        )

        if self.crowdsec_api_version != "v2":
            raise Exception(
                f"crowdsec api version '{self.crowdsec_api_version}' is not supported "
            )
        else:
            self.api_base_url = (
                f"https://cti.api.crowdsec.net/{self.crowdsec_api_version}/"
            )

        self.client = CrowdSecClient(
            helper=self.helper,
            url=self.api_base_url,
            api_key=self.crowdsec_cti_key,
        )
        self.builder = CrowdSecBuilder(self.helper, config)

    def enrich_observable(self, observable: dict, stix_observable: dict):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        observable_id = observable["standard_id"]
        ip = observable["value"]
        observable_markings = [
            objectMarking["standard_id"]
            for objectMarking in observable["objectMarking"]
        ]
        indicator = None
        # Initialize bundle with observable
        self.builder.add_to_bundle([stix_observable])
        # Retrieve CrowdSec CTI data for IP
        try:
            cti_data: Dict[str, Any] = self.client.get_crowdsec_cti_for_ip(ip)
        except QuotaExceedException as ex:
            raise ex

        if not cti_data:
            return

        # Add CTI url as external reference to observable
        cti_external_reference = self.builder.add_external_reference_to_target(
            target=stix_observable,
            source_name="CrowdSec CTI",
            url=urljoin(CTI_URL, ip),
            description="CrowdSec CTI url for this IP",
        )
        # Initialize external reference for sightings
        sighting_ext_refs = [cti_external_reference]
        # Parse data from CTI response
        behaviors = cti_data.get("behaviors", [])
        references = cti_data.get("references", [])
        mitre_techniques = cti_data.get("mitre_techniques", [])
        attack_details = cti_data.get("attack_details", [])
        cves = cti_data.get("cves", [])
        reputation = cti_data.get("reputation", "")
        confidence = cti_data.get("confidence", "")
        first_seen = cti_data.get("history", {}).get("first_seen", "")
        last_seen = cti_data.get("history", {}).get("last_seen", "")
        target_countries = cti_data.get("target_countries", {})
        origin_country = cti_data.get("location", {}).get("country", "")
        origin_city = cti_data.get("location", {}).get("city", "")

        # Handle labels
        self.builder.handle_labels(
            reputation=reputation,
            cves=cves,
            behaviors=behaviors,
            attack_details=attack_details,
            mitre_techniques=mitre_techniques,
            observable_id=observable_id,
        )

        # Start Bundle creation
        # Handle reputation
        if reputation in self.indicator_create_from:
            pattern = f"[ipv4-addr:value = '{ip}']"
            indicator = self.builder.add_indicator_based_on(
                observable_id,
                stix_observable,
                ip,
                pattern,
                observable_markings,
                reputation,
                confidence,
                last_seen,
                references,
            )
        # Handle mitre_techniques
        attack_patterns = []
        for mitre_technique in mitre_techniques:
            mitre_external_reference = self.builder.create_external_ref_for_mitre(
                mitre_technique
            )
            sighting_ext_refs.append(mitre_external_reference)
            # Create attack pattern
            if indicator and self.attack_pattern_create_from_mitre:
                attack_pattern = self.builder.add_attack_pattern_for_mitre(
                    mitre_technique=mitre_technique,
                    observable_markings=observable_markings,
                    indicator=indicator,
                    external_references=[mitre_external_reference],
                )
                attack_patterns.append(attack_pattern.id)
        # Handle CVEs
        for cve in cves:
            # Create vulnerability
            self.builder.add_vulnerability_from_cve(
                cve, observable_markings, observable_id
            )
        # Handle target countries
        if attack_patterns:
            self.builder.handle_target_countries(
                target_countries, attack_patterns, observable_markings
            )
        # Add note
        self.builder.add_note(
            observable_id=observable_id,
            ip=ip,
            reputation=reputation,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            origin_country=origin_country,
            origin_city=origin_city,
            behaviors=behaviors,
            target_countries=target_countries,
            observable_markings=observable_markings,
        )
        # Create sightings relationship between CrowdSec organisation and observable
        self.builder.add_sighting(
            observable_id=observable_id,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=confidence,
            observable_markings=observable_markings,
            sighting_ext_refs=sighting_ext_refs,
            indicator=indicator if indicator else None,
        )
        # End of Bundle creation
        # Send Bundle to OpenCTI workers
        self.builder.send_bundle()

        self.helper.metric.state("idle")
        return f"CrowdSec enrichment completed for {ip}"

    def _process_message(self, data: Dict):

        observable = data["enrichment_entity"]
        stix_observable = data["stix_entity"]

        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

        self.enrich_observable(observable, stix_observable)

    def start(self) -> None:
        self.helper.log_info("CrowdSec connector started")
        self.helper.listen(message_callback=self._process_message)
