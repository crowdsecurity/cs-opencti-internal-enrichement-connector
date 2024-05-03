# -*- coding: utf-8 -*-
"""CrowdSec builder module."""

from typing import List, Dict

import pycountry
from dateutil.parser import parse
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    StixCoreRelationship,
    OpenCTIStix2,
    STIX_EXT_OCTI_SCO,
)
from stix2 import (
    Relationship,
    Indicator,
    Identity,
    AttackPattern,
    Vulnerability,
    Location,
    Note,
    Sighting,
)

from .constants import MITRE_URL, CVE_REGEX


def _get_confidence_level(confidence: str) -> int:
    if confidence == "high":
        return 90
    elif confidence == "medium":
        return 60
    elif confidence == "low":
        return 30
    else:
        return 0


class CrowdSecBuilder:
    """CrowdSec builder."""

    helper: OpenCTIConnectorHelper

    def __init__(self, helper: OpenCTIConnectorHelper, config) -> None:
        self.helper = helper
        self.crowdsec_ent_name = get_config_variable(
            "CROWDSEC_NAME", ["crowdsec", "name"], config
        )
        self.crowdsec_ent_desc = get_config_variable(
            "CROWDSEC_DESCRIPTION", ["crowdsec", "description"], config
        )
        self.crowdsec_ent = None
        self.bundle_objects = []
        self.labels_scenario_use = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_USE",
            ["crowdsec", "labels_scenario_use"],
            config,
            default=True,
        )
        self.labels_scenario_only_name = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_ONLY_NAME",
            ["crowdsec", "labels_scenario_only_name"],
            config,
            default=False,
        )
        self.labels_scenario_color = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_COLOR",
            ["crowdsec", "labels_scenario_color"],
            config,
            default="#2E2A14",
        )
        self.labels_cve_use = get_config_variable(
            "CROWDSEC_LABELS_CVE_USE",
            ["crowdsec", "labels_cve_use"],
            config,
            default=False,
        )
        self.labels_cve_color = get_config_variable(
            "CROWDSEC_LABELS_SCENARIO_COLOR",
            ["crowdsec", "labels_scenario_color"],
            config,
            default="#800080",
        )
        self.labels_behavior_use = get_config_variable(
            "CROWDSEC_LABELS_BEHAVIOR_USE",
            ["crowdsec", "labels_behavior_use"],
            config,
            default=False,
        )
        self.labels_behavior_color = get_config_variable(
            "CROWDSEC_LABELS_BEHAVIOR_COLOR",
            ["crowdsec", "labels_behavior_color"],
            config,
            default="#808000",
        )
        self.labels_mitre_use = get_config_variable(
            "CROWDSEC_LABELS_MITRE_USE",
            ["crowdsec", "labels_mitre_use"],
            config,
            default=False,
        )
        self.labels_mitre_color = get_config_variable(
            "CROWDSEC_LABELS_MITRE_COLOR",
            ["crowdsec", "labels_mitre_color"],
            config,
            default="#000080",
        )
        self.labels_reputation_use = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION_USE",
            ["crowdsec", "labels_reputation_use"],
            config,
            default=False,
        )
        self.labels_reputation_malicious_color = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR",
            ["crowdsec", "labels_reputation_malicious_color"],
            config,
            default="#FF0000",
        )
        self.labels_reputation_suspicious_color = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR",
            ["crowdsec", "labels_reputation_suspicious_color"],
            config,
            default="#FFA500",
        )
        self.labels_reputation_safe_color = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION_SAFE_COLOR",
            ["crowdsec", "labels_reputation_safe_color"],
            config,
            default="#00BFFF",
        )
        self.labels_reputation_known_color = get_config_variable(
            "CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR",
            ["crowdsec", "labels_reputation_known_color"],
            config,
            default="#808080",
        )

    def add_to_bundle(self, objects: List) -> List[object]:
        for obj in objects:
            self.bundle_objects.append(obj)
        return self.bundle_objects

    def add_external_reference_to_target(
        self, target: object, source_name: str, url: str, description: str
    ) -> Dict:

        ext_ref_dict = {
            "source_name": source_name,
            "url": url,
            "description": description,
        }
        # We have to create the external reference physically as creating the object only may lead to data loss
        self.helper.api.external_reference.create(**ext_ref_dict)

        OpenCTIStix2.put_attribute_in_extension(
            target,
            STIX_EXT_OCTI_SCO,
            "external_references",
            ext_ref_dict,
            True,
        )

        return ext_ref_dict

    def get_or_create_crowdsec_ent(self) -> Identity:
        if getattr(self, "crowdsec_ent", None) is not None:
            return self.crowdsec_ent
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_ent = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )
        else:
            self.crowdsec_ent = crowdsec_ent
        return self.crowdsec_ent

    def add_indicator_based_on(
        self,
        observable_id: str,
        ip: str,
        pattern: str,
        observable_markings: List,
        reputation: str,
        confidence: str,
        last_seen: str,
        references: List,
    ) -> Indicator:
        indicator = Indicator(
            id=self.helper.api.indicator.generate_id(pattern),
            name=f"CrowdSec CTI ({reputation} IP: {ip})",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            description=f"CrowdSec CTI detection for {ip}",
            pattern=pattern,
            pattern_type="stix",
            #  We do not use first_seen as OpenCTI will add some duration to define valid_until
            valid_from=self.helper.api.stix2.format_date(last_seen),
            confidence=_get_confidence_level(confidence),
            object_marking_refs=observable_markings,
            external_references=self._handle_blocklist_references(references),
            indicator_types=(
                ["malicious-activity"] if reputation == "malicious" else []
            ),
        )

        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                observable_id,
            ),
            relationship_type="based-on",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            source_ref=indicator.id,
            target_ref=observable_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([indicator, relationship])

        return indicator

    def add_attack_pattern_for_mitre(
        self, mitre_technique, observable_markings, indicator, external_references
    ) -> AttackPattern:

        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"

        attack_pattern = AttackPattern(
            id=self.helper.api.attack_pattern.generate_id(
                name=name, x_mitre_id=mitre_technique["name"]
            ),
            name=name,
            description=description,
            custom_properties={
                "x_mitre_id": mitre_technique["name"],
            },
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=observable_markings,
            external_references=external_references,
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "indicates",
                indicator.id,
                attack_pattern.id,
            ),
            relationship_type="indicates",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            source_ref=indicator.id,
            target_ref=attack_pattern.id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([attack_pattern, relationship])

        return attack_pattern

    def add_note(
        self,
        observable_id: str,
        ip: str,
        reputation: str,
        confidence: str,
        first_seen: str,
        last_seen: str,
        origin_country: str,
        origin_city: str,
        behaviors: List,
        target_countries: Dict,
        observable_markings: List,
    ) -> None:
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

            if target_countries:
                content += f"**Most targeted countries**: \n\n"
                for country_alpha_2, val in target_countries.items():
                    country_info = pycountry.countries.get(alpha_2=country_alpha_2)
                    content += "- " + country_info.name + f" ({val}%)" + "\n\n"

        note = Note(
            type="note",
            id=self.helper.api.note.generate_id(
                created=self.helper.api.stix2.format_date(), content=content
            ),
            object_refs=[observable_id],
            abstract=f"CrowdSec enrichment for {ip}",
            content=content,
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=observable_markings,
            custom_properties={
                "note_types": ["external"],
            },
        )

        self.add_to_bundle([note])

    def add_sighting(
        self,
        observable_id: str,
        first_seen: str,
        last_seen: str,
        confidence: str,
        observable_markings: List,
        sighting_ext_refs: List,
        indicator: Indicator,
    ) -> None:

        fake_indicator_id = "indicator--51b92778-cef0-4a90-b7ec-ebd620d01ac8"
        sighting = Sighting(
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            description=self.crowdsec_ent_desc,
            first_seen=(
                parse(first_seen).strftime("%Y-%m-%dT%H:%M:%SZ") if first_seen else None
            ),
            last_seen=(
                parse(last_seen).strftime("%Y-%m-%dT%H:%M:%SZ") if last_seen else None
            ),
            count=1,
            confidence=_get_confidence_level(confidence),
            object_marking_refs=observable_markings,
            external_references=sighting_ext_refs,
            sighting_of_ref=indicator.id if indicator else fake_indicator_id,
            where_sighted_refs=[self.get_or_create_crowdsec_ent()["standard_id"]],
            custom_properties={"x_opencti_sighting_of_ref": observable_id},
        )

        self.add_to_bundle([sighting])

    def add_vulnerability_from_cve(
        self, cve: str, observable_markings: List, observable_id: str
    ) -> Vulnerability:
        cve_name = cve.upper()
        vulnerability = Vulnerability(
            id=self.helper.api.vulnerability.generate_id(cve_name),
            name=cve_name,
            description=cve_name,
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            object_marking_refs=observable_markings,
        )
        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "related-to",
                vulnerability.id,
                observable_id,
            ),
            relationship_type="related-to",
            created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
            source_ref=vulnerability.id,
            target_ref=observable_id,
            confidence=self.helper.connect_confidence_level,
            allow_custom=True,
        )
        self.add_to_bundle([vulnerability, relationship])

        return vulnerability

    def _handle_blocklist_references(self, references: List) -> List[Dict]:
        blocklist_references = []
        for reference in references:
            if (
                reference.get("references")
                and isinstance(reference["references"], list)
                and reference["references"][0].startswith("http")
            ):
                first_url = reference["references"][0]
                ext_ref_dict = {
                    "source_name": reference["label"],
                    "url": first_url,
                    "description": reference["description"],
                }
                # We have to create the external reference physically as creating the object only may lead to data loss
                self.helper.api.external_reference.create(**ext_ref_dict)
                blocklist_references.append(ext_ref_dict)

        return blocklist_references

    def create_external_ref_for_mitre(self, mitre_technique) -> Dict:
        description = f"{mitre_technique['label']}: {mitre_technique['description']}"
        name = f"MITRE ATT&CK ({mitre_technique['name']} - {mitre_technique['label']})"
        ext_ref_dict = {
            "source_name": name,
            "url": f"{MITRE_URL}{mitre_technique['name']}",
            "description": description,
        }
        self.helper.api.external_reference.create(**ext_ref_dict)

        return ext_ref_dict

    def handle_labels(
        self,
        observable_id: str,
        reputation: str,
        cves: List,
        behaviors: List,
        attack_details: List,
        mitre_techniques: List,
    ) -> None:
        # Initialize labels and label colors
        labels = []
        labels_mitre_color = self.labels_mitre_color
        scenario_label_color = self.labels_scenario_color
        labels_cve_color = self.labels_cve_color
        labels_behavior_color = self.labels_behavior_color
        # Mitre techniques
        if self.labels_mitre_use:
            for mitre_technique in mitre_techniques:
                labels.append((mitre_technique["name"], labels_mitre_color))
        # CVEs
        if self.labels_cve_use:
            for cve in cves:
                labels.append((cve.upper(), labels_cve_color))
        # Behaviors
        if self.labels_behavior_use:
            for behavior in behaviors:
                labels.append((behavior["name"], labels_behavior_color))
        # Reputation
        if reputation and self.labels_reputation_use:
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

        # Create labels
        for value, color in labels:
            label = self.helper.api.label.read_or_create_unchecked(
                value=value, color=color
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=observable_id, label_id=label["id"]
            )

    def handle_target_countries(
        self,
        target_countries: Dict,
        attack_patterns: List[str],
        observable_markings: List,
    ) -> None:
        for country_alpha_2, val in target_countries.items():
            country_info = pycountry.countries.get(alpha_2=country_alpha_2)

            country = Location(
                id=self.helper.api.location.generate_id(
                    name=country_info.name, x_opencti_location_type="Country"
                ),
                name=country_info.name,
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
                created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                object_marking_refs=observable_markings,
            )

            self.add_to_bundle([country])

            # Create relationship between country and attack pattern
            for attack_pattern_id in attack_patterns:
                country_relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "targets",
                        attack_pattern_id,
                        country["id"],
                    ),
                    relationship_type="targets",
                    created_by_ref=self.get_or_create_crowdsec_ent()["standard_id"],
                    source_ref=attack_pattern_id,
                    target_ref=country["id"],
                    confidence=self.helper.connect_confidence_level,
                    allow_custom=True,
                )

                self.add_to_bundle([country_relationship])

    def send_bundle(self) -> bool:
        bundle_objects = self.bundle_objects
        if bundle_objects:
            self.helper.log_debug(
                f"[CrowdSec] sending bundle (length:{len(bundle_objects)}): {bundle_objects}"
            )
            # serialized_bundle = Bundle(objects=bundle_objects, allow_custom=True).serialize()
            serialized_bundle = self.helper.stix2_create_bundle(self.bundle_objects)
            bundles_sent = self.helper.send_stix2_bundle(serialized_bundle)
            self.helper.log_debug(
                f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
            )
            self.helper.metric.inc("record_send", len(bundle_objects))
            return True

        return False