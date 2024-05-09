# -*- coding: utf-8 -*-
"""CrowdSec builder unittest."""
import datetime
import json
import os
import unittest
from unittest.mock import MagicMock, PropertyMock

import stix2

from src.crowdsec.builder import CrowdSecBuilder


def load_file(filename: str):
    """Utility function to load a json file to a dict."""
    filepath = os.path.join(os.path.dirname(__file__), "resources", filename)
    with open(filepath, encoding="utf-8") as json_file:
        return json.load(json_file)


class CrowdSecBuilderTest(unittest.TestCase):
    @classmethod
    def setup_class(cls):
        cls.helper = MagicMock()
        cls.cti_data = load_file("malicious_ip.json")

    def test_init_builder(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        self.assertEqual(len(builder.bundle_objects), 0)
        self.assertEqual(builder.crowdsec_ent_name, "CrowdSec")
        self.assertEqual(builder.crowdsec_ent_desc, "CrowdSec CTI enrichment")
        self.assertEqual(builder.labels_scenario_use, True)
        self.assertEqual(builder.labels_scenario_only_name, False)
        self.assertEqual(builder.labels_scenario_color, "#2E2A14")
        self.assertEqual(builder.labels_cve_use, False)
        self.assertEqual(builder.labels_cve_color, "#800080")
        self.assertEqual(builder.labels_mitre_use, False)
        self.assertEqual(builder.labels_mitre_color, "#000080")
        self.assertEqual(builder.labels_behavior_use, False)
        self.assertEqual(builder.labels_behavior_color, "#808000")
        self.assertEqual(builder.labels_reputation_use, False)
        self.assertEqual(builder.labels_reputation_malicious_color, "#FF0000")
        self.assertEqual(builder.labels_reputation_suspicious_color, "#FFA500")
        self.assertEqual(builder.labels_reputation_known_color, "#808080")
        self.assertEqual(builder.labels_reputation_safe_color, "#00BFFF")
        # CTI data
        self.assertEqual(builder.reputation, "malicious")
        self.assertEqual(builder.confidence, "high")
        self.assertEqual(builder.first_seen, "2023-06-13T19:00:00+00:00")
        self.assertEqual(builder.last_seen, "2024-04-18T08:15:00+00:00")
        self.assertEqual(builder.origin_city, "New York")
        self.assertEqual(builder.origin_country, "US")
        self.assertEqual(builder.behaviors, self.cti_data.get("behaviors", []))
        self.assertEqual(builder.references, self.cti_data.get("references", []))
        self.assertEqual(builder.mitre_techniques, self.cti_data.get("mitre_techniques", []))
        self.assertEqual(builder.attack_details, self.cti_data.get("attack_details", []))
        self.assertEqual(builder.cves, self.cti_data.get("cves", []))
        self.assertEqual(builder.target_countries, self.cti_data.get("target_countries", {}))

    def test_add_to_bundle(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        observable = stix2.IPv4Address(
            value="1.2.3.4",
        )
        builder.add_to_bundle([observable])

        self.assertEqual(len(builder.bundle_objects), 1)
        self.assertEqual(builder.bundle_objects[0], observable)

        other_observable = stix2.IPv4Address(
            value="4.5.6.7",
        )
        builder.add_to_bundle([other_observable])
        self.assertEqual(len(builder.bundle_objects), 2)
        self.assertEqual(builder.bundle_objects[1], other_observable)

    def test_add_external_reference_to_target(self):
        builder = CrowdSecBuilder(
            helper=self.helper,
            config={},
            cti_data=self.cti_data,
        )
        stix_observable = load_file("stix_observable.json")

        external_reference = builder.add_external_reference_to_target(
            target=stix_observable,
            source_name="CrowdSec CTI TEST",
            url="https://crowdsec.net",
            description="CrowdSec CTI url for this IP",
        )

        self.assertEqual(external_reference["source_name"], "CrowdSec CTI TEST")
        self.assertEqual(stix_observable["extensions"], {"extension-definition--f93e2c80-4231-4f9a-af8b-95c9bd566a82": {"external_references": [external_reference]}})
