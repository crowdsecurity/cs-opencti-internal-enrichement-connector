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
        self.config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(self.config)
        self.crowdsec_cti_key = clean_config(
            get_config_variable("CROWDSEC_KEY", ["crowdsec", "key"], self.config)
        )
        self.crowdsec_api_version = clean_config(
            get_config_variable(
                "CROWDSEC_VERSION",
                ["crowdsec", "api_version"],
                self.config,
                default="v2",
            )
        )

        self.max_tlp = clean_config(
            get_config_variable(
                "CROWDSEC_MAX_TLP",
                ["crowdsec", "max_tlp"],
                self.config,
                default="TLP:AMBER",
            )
        )
        raw_indicator_create_from = clean_config(
            get_config_variable(
                "CROWDSEC_INDICATOR_CREATE_FROM",
                ["crowdsec", "indicator_create_from"],
                self.config,
                default="",
            )
        )

        self.indicator_create_from = raw_indicator_create_from.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "CROWDSEC_ATTACK_PATTERN_CREATE_FROM_MITRE",
            ["crowdsec", "attack_pattern_create_from_mitre"],
            self.config,
            default=False,
        )

        self.create_note = get_config_variable(
            "CROWDSEC_CREATE_NOTE",
            ["crowdsec", "create_note"],
            self.config,
            default=False,
        )

        self.create_sighting = get_config_variable(
            "CROWDSEC_CREATE_SIGHTING",
            ["crowdsec", "create_sighting"],
            self.config,
            default=True,
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
        self.builder = None

    def enrich_observable(self, observable: Dict, stix_observable: Dict):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        self.helper.log_debug(f"Processing observable {observable}")
        self.helper.log_debug(f"Processing stix_observable {stix_observable}")
        observable_id = observable["standard_id"]
        ip = observable["value"]
        observable_markings = [
            objectMarking["standard_id"]
            for objectMarking in observable["objectMarking"]
        ]
        indicator = None
        # Retrieve CrowdSec CTI data for IP
        try:
            cti_data: Dict[str, Any] = self.client.get_crowdsec_cti_for_ip(ip)
        except QuotaExceedException as ex:
            raise ex

        if not cti_data:
            return

        # Retrieve specific data from CTI
        self.helper.log_debug(f"CTI data for {ip}: {cti_data}")
        reputation = cti_data.get("reputation", "")
        mitre_techniques = cti_data.get("mitre_techniques", [])
        cves = cti_data.get("cves", [])

        # Initialize builder
        self.builder = CrowdSecBuilder(self.helper, self.config, cti_data)
        # Add CTI url as external reference to observable
        cti_external_reference = self.builder.add_external_reference_to_observable(
            stix_observable=stix_observable,
            source_name="CrowdSec CTI",
            url=urljoin(CTI_URL, ip),
            description="CrowdSec CTI url for this IP",
        )
        # Initialize external reference for sightings
        sighting_ext_refs = [cti_external_reference]
        # Handle labels
        self.builder.handle_labels(observable_id=observable_id)
        # Start Bundle creation
        # Initialize bundle with observable
        self.builder.add_to_bundle([stix_observable])
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
            self.builder.handle_target_countries(attack_patterns, observable_markings)
        # Add note
        if self.create_note:
            self.builder.add_note(
                observable_id=observable_id,
                observable_markings=observable_markings,
            )
        # Create sightings relationship between CrowdSec organisation and observable
        if self.create_sighting:
            self.builder.add_sighting(
                observable_id=observable_id,
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
