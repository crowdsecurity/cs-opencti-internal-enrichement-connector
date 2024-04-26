import itertools
import os
import re
from time import sleep

from typing import Dict, Any
from urllib.parse import urljoin

import pycountry
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _get_confidence_level(confidence):
    if confidence == "high":
        return 90
    elif confidence == "medium":
        return 60
    elif confidence == "low":
        return 30
    else:
        return 0


class QuotaExceedException(Exception):
    pass


class CrowdSecConnector:

    def __init__(self):
        # Instantiate the connector helper from config
        self.crowdsec_id = None
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.crowdsec_cti_key = get_config_variable(
            "CROWDSEC_KEY", ["crowdsec", "key"], config
        )
        self.crowdsec_api_version = get_config_variable(
            "CROWDSEC_VERSION", ["crowdsec", "api_version"], config
        )
        self.crowdsec_ent_name = get_config_variable(
            "CROWDSEC_NAME", ["crowdsec", "name"], config
        )
        self.crowdsec_ent_desc = get_config_variable(
            "CROWDSEC_DESCRIPTION", ["crowdsec", "description"], config
        )
        self.max_tlp = get_config_variable(
            "CROWDSEC_MAX_TLP", ["crowdsec", "max_tlp"], config
        )
        self.labels_scenario_use = get_config_variable(
            "LABELS_SCENARIO_USE",
            ["crowdsec", "labels_scenario_use"],
            config,
            default=True,
        )
        self.labels_scenario_only_name = get_config_variable(
            "LABELS_SCENARIO_ONLY_NAME",
            ["crowdsec", "labels_scenario_only_name"],
            config,
            default=False,
        )
        self.labels_scenario_color = get_config_variable(
            "LABELS_SCENARIO_COLOR",
            ["crowdsec", "labels_scenario_color"],
            config,
            default="#2E2A14",
        )
        self.labels_cve_use = get_config_variable(
            "LABELS_CVE_USE", ["crowdsec", "labels_cve_use"], config, default=False
        )
        self.labels_cve_color = get_config_variable(
            "LABELS_SCENARIO_COLOR",
            ["crowdsec", "labels_scenario_color"],
            config,
            default="#800080",
        )
        self.labels_behavior_use = get_config_variable(
            "LABELS_BEHAVIOR_USE",
            ["crowdsec", "labels_behavior_use"],
            config,
            default=False,
        )
        self.labels_behavior_color = get_config_variable(
            "LABELS_BEHAVIOR_COLOR",
            ["crowdsec", "labels_behavior_color"],
            config,
            default="#808000",
        )
        self.labels_mitre_use = get_config_variable(
            "LABELS_MITRE_USE", ["crowdsec", "labels_mitre_use"], config, default=False
        )
        self.labels_mitre_color = get_config_variable(
            "LABELS_MITRE_COLOR",
            ["crowdsec", "labels_mitre_color"],
            config,
            default="#000080",
        )
        self.labels_reputation_use = get_config_variable(
            "LABELS_REPUTATION_USE",
            ["crowdsec", "labels_reputation_use"],
            config,
            default=False,
        )
        self.labels_reputation_malicious_color = get_config_variable(
            "LABELS_REPUTATION_MALICIOUS_COLOR",
            ["crowdsec", "labels_reputation_malicious_color"],
            config,
            default="#FF0000",
        )
        self.labels_reputation_suspicious_color = get_config_variable(
            "LABELS_REPUTATION_SUSPICIOUS_COLOR",
            ["crowdsec", "labels_reputation_suspicious_color"],
            config,
            default="#FFA500",
        )
        self.labels_reputation_safe_color = get_config_variable(
            "LABELS_REPUTATION_SAFE_COLOR",
            ["crowdsec", "labels_reputation_safe_color"],
            config,
            default="#00BFFF",
        )
        self.labels_reputation_known_color = get_config_variable(
            "LABELS_REPUTATION_KNOWN_COLOR",
            ["crowdsec", "labels_reputation_known_color"],
            config,
            default="#808080",
        )

        raw_indicator_create_from = get_config_variable(
            "INDICATOR_CREATE_FROM",
            ["crowdsec", "indicator_create_from"],
            config,
            default="malicious,suspicious,known",
        )

        self.indicator_create_from = raw_indicator_create_from.split(",")

        self.attack_pattern_create_from_mitre = get_config_variable(
            "ATTACK_PATTERN_CREATE_FROM_MITRE",
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

        self.mitre_techniques_url = f"http://attack.mitre.org/techniques/"
        self.public_cti_url = f"https://app.crowdsec.net/cti/"

    def get_crowdsec_cti_for_ip(self, ip):
        for i in itertools.count(1, 1):
            resp = requests.get(
                urljoin(self.api_base_url, f"smoke/{ip}"),
                headers={
                    "x-api-key": self.crowdsec_cti_key,
                    "User-Agent": "crowdsec-opencti/v1.1.0",
                },
            )
            if resp.status_code == 404:
                return {"reputation": "unknown"}
            elif resp.status_code == 429:
                raise QuotaExceedException(
                    (
                        "Quota exceeded for CrowdSec CTI API. "
                        "Please visit https://www.crowdsec.net/pricing to upgrade your plan."
                    )
                )
            elif resp.status_code == 200:
                return resp.json()
            else:
                self.helper.log_info(f"CrowdSec CTI response {resp.text}")
                self.helper.log_warning(
                    f"CrowdSec CTI returned {resp.status_code} response status code. Retrying.."
                )
            sleep(2**i)

    def get_or_create_crowdsec_ent_id(self) -> int:
        if getattr(self, "crowdsec_id", None) is not None:
            return self.crowdsec_id
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_id = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )["id"]
        else:
            self.crowdsec_id = crowdsec_ent["id"]
        return self.crowdsec_id

    def enrich_observable(self, observable):
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")
        observable_id = observable["standard_id"]
        ip = observable["value"]
        indicator = None

        try:
            cti_data: Dict[str, Any] = self.get_crowdsec_cti_for_ip(ip)
        except QuotaExceedException as ex:
            raise ex

        if not cti_data:
            return

        cti_external_reference = self.helper.api.external_reference.create(
            source_name="CrowdSec CTI",
            url=urljoin(self.public_cti_url, ip),
            description="CrowdSec CTI url for this IP",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable_id, external_reference_id=cti_external_reference["id"]
        )
        # Initialize external reference ids with cti enrichment id
        external_reference_ids = [cti_external_reference["id"]]
        # Retrieve data
        behaviors = cti_data.get("behaviors", [])
        references = cti_data.get("references", [])
        mitre_techniques = cti_data.get("mitre_techniques", [])
        attack_details = cti_data.get("attack_details", [])
        cves = cti_data.get("cves", [])
        reputation = cti_data.get("reputation", None)
        confidence = cti_data.get("confidence", "")
        first_seen = cti_data.get("history", {}).get("first_seen", "")
        last_seen = cti_data.get("history", {}).get("last_seen", "")
        target_countries = cti_data.get("target_countries", {})
        origin_country = cti_data.get("location", {}).get("country", None)
        origin_city = cti_data.get("location", {}).get("city", None)

        # Initialize labels and label colors
        labels = []
        labels_mitre_color = self.labels_mitre_color
        scenario_label_color = self.labels_scenario_color
        labels_cve_color = self.labels_cve_color
        labels_behavior_color = self.labels_behavior_color
        # Handle reputation
        if reputation in self.indicator_create_from:
            indicator = self.helper.api.indicator.create(
                name=f"CrowdSec CTI ({reputation})",
                description=f"CrowdSec CTI detection for {ip}",
                pattern_type="stix",
                x_opencti_main_observable_type="IPv4-Addr",
                pattern=f"[ipv4-addr:value = '{ip}']",
                valid_from=first_seen,
                valid_until=last_seen,
                confidence=_get_confidence_level(confidence),
                indicator_types=(
                    ["malicious-activity"] if reputation == "malicious" else []
                ),
                createdBy=self.get_or_create_crowdsec_ent_id(),
                objectMarking=observable["objectMarkingIds"],
                update=True,
            )
            self.helper.api.indicator.add_stix_cyber_observable(
                id=indicator["id"], stix_cyber_observable_id=observable_id
            )

        # Handle mitre_techniques
        attack_patterns = []
        for mitre_technique in mitre_techniques:
            description = (
                f"{mitre_technique['label']}: {mitre_technique['description']}"
            )
            name = f"MITRE ATT&CK ({mitre_technique['label']})"
            # External reference
            mitre_external_reference = self.helper.api.external_reference.create(
                source_name=name,
                url=f"{self.mitre_techniques_url}{mitre_technique['name']}",
                description=description,
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable_id, external_reference_id=mitre_external_reference["id"]
            )
            external_reference_ids.append(mitre_external_reference["id"])
            # Create attack pattern
            if indicator and self.attack_pattern_create_from_mitre:
                attack_pattern = self.helper.api.attack_pattern.create(
                    name=name,
                    x_mitre_id=mitre_technique["name"],
                    description=description,
                    createdBy=self.get_or_create_crowdsec_ent_id(),
                    objectMarking=observable["objectMarkingIds"],
                    update=True,
                    externalReferences=[mitre_external_reference["id"]],
                )
                attack_patterns.append(attack_pattern["id"])
                self.helper.api.stix_core_relationship.create(
                    fromId=indicator["id"],
                    toId=attack_pattern["id"],
                    relationship_type="indicates",
                    confidence=self.helper.connect_confidence_level,
                )
            # Mitre techniques labels
            if self.labels_mitre_use:
                labels.append((mitre_technique["name"], labels_mitre_color))
        # Handle references
        for reference in references:
            if (
                reference.get("references")
                and isinstance(reference["references"], list)
                and reference["references"][0].startswith("http")
            ):
                first_reference = reference["references"][0]
                reference_external_reference = (
                    self.helper.api.external_reference.create(
                        source_name=reference["label"],
                        url=first_reference,
                        description=reference["description"],
                    )
                )
                self.helper.api.stix_cyber_observable.add_external_reference(
                    id=observable_id,
                    external_reference_id=reference_external_reference["id"],
                )
                external_reference_ids.append(reference_external_reference["id"])

        # Reputation labels
        if self.labels_reputation_use and reputation:
            color_attribute = f"labels_reputation_{reputation}_color"
            color = getattr(self, color_attribute, None)
            if reputation != "unknown" and color is not None:
                labels.append((reputation, color))
        # Scenarios labels
        if self.labels_scenario_use:
            # We handle CVE labels separately to avoid duplicates
            filtered_scenarios = [
                scenario
                for scenario in attack_details
                if not CVE_REGEX.search(scenario["name"])
            ]

            scenario_names = [
                (attack["name"], scenario_label_color) for attack in filtered_scenarios
            ]
            labels.extend(scenario_names)
            if not self.labels_scenario_only_name:
                scenario_labels = [
                    (attack["label"], scenario_label_color)
                    for attack in filtered_scenarios
                ]
                labels.extend(scenario_labels)

        # Handle CVEs
        for cve in cves:
            # Create vulnerability
            vuln = self.helper.api.vulnerability.create(name=cve.upper())
            self.helper.api.stix_core_relationship.create(
                fromId=observable_id,
                toId=vuln["id"],
                relationship_type="related-to",
                confidence=self.helper.connect_confidence_level,
            )
            # CVE labels
            if self.labels_cve_use:
                labels.append((cve.upper(), labels_cve_color))

        # Handle target countries
        if attack_patterns:
            for country_alpha_2, val in target_countries.items():
                country_info = pycountry.countries.get(alpha_2=country_alpha_2)
                country = self.helper.api.location.create(
                    name=country_info.name,
                    type="Country",
                    country=(
                        country_info.official_name
                        if hasattr(country_info, "official_name")
                        else country_info.name
                    ),
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [
                            (
                                country_info.official_name
                                if hasattr(country_info, "official_name")
                                else country_info.name
                            )
                        ],
                    },
                )
                # Create relationship between country and attack pattern
                for attack_pattern_id in attack_patterns:
                    self.helper.api.stix_core_relationship.create(
                        fromId=attack_pattern_id,
                        toId=country["id"],
                        relationship_type="targets",
                        confidence=self.helper.connect_confidence_level,
                    )

        # Create labels
        for value, color in labels:
            label = self.helper.api.label.read_or_create_unchecked(
                value=value, color=color
            )
            if label is not None:
                self.helper.api.stix_cyber_observable.add_label(
                    id=observable_id, label_id=label["id"]
                )

        # Create note
        if reputation == "unknown":
            content = f"This is was not found in CrowdSec CTI. \n\n"
        else:
            content = f"**Reputation**: {reputation} \n\n"
            content += f"**Confidence**: {confidence} \n\n"
            content += f"**First Seen**: {first_seen} \n\n"
            content += f"**Last Seen**: {last_seen} \n\n"
            if origin_country and origin_city:
                content += f"**Origin**: {origin_country} ({origin_city}) \n\n"
            if behaviors:
                content += f"**Behaviors**: \n\n"
                for behavior in behaviors:
                    content += (
                        "- "
                        + behavior["label"]
                        + ": "
                        + behavior["description"]
                        + "\n\n"
                    )
                    if self.labels_behavior_use:
                        labels.append((behavior["name"], labels_behavior_color))

            if target_countries:
                content += f"**Most targeted countries**: \n\n"
                for country_alpha_2, val in target_countries.items():
                    country_info = pycountry.countries.get(alpha_2=country_alpha_2)
                    content += "- " + country_info.name + f" ({val}%)" + "\n\n"

        note = self.helper.api.note.create(
            authors=[self.get_or_create_crowdsec_ent_id()],
            content=content,
            createdBy=self.get_or_create_crowdsec_ent_id(),
            objectMarking=observable["objectMarkingIds"],
            abstract=f"CrowdSec enrichment",
            note_types=["external"],
            update=False,
        )
        self.helper.api.note.add_stix_object_or_stix_relationship(
            id=note["id"], stixObjectOrStixRelationshipId=observable_id
        )

        # Create sightings relationship between CrowdSec organisation and observable
        if reputation not in ["unknown"]:
            self.helper.api.stix_sighting_relationship.create(
                fromId=observable_id,
                toId=self.get_or_create_crowdsec_ent_id(),
                createdBy=self.get_or_create_crowdsec_ent_id(),
                description=self.crowdsec_ent_desc,
                first_seen=first_seen if first_seen else None,
                last_seen=last_seen if last_seen else None,
                confidence=_get_confidence_level(confidence),
                externalReferences=external_reference_ids,
                count=1,
            )

        self.helper.metric.state("idle")
        return f"CrowdSec enrichment completed for {ip}"

    def _process_message(self, data: Dict):
        observable = data["enrichment_entity"]

        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        self.enrich_observable(observable)

    def start(self) -> None:
        self.helper.log_info("CrowdSec connector started")
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        crowdsec_connector = CrowdSecConnector()
        crowdsec_connector.start()
    except Exception as e:
        print(e)
        sleep(10)
        exit(0)
