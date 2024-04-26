# -*- coding: utf-8 -*-
"""CrowdSec constants module."""

import re

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
MITRE_URL = "https://attack.mitre.org/techniques/"
CTI_URL = "https://app.crowdsec.net/cti/"
