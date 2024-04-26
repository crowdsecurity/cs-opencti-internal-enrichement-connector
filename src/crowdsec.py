# -*- coding: utf-8 -*-
"""CrowdSec internal enrichment connector main file."""

from time import sleep
from crowdsec import CrowdSecConnector


if __name__ == "__main__":
    try:
        crowdsec_connector = CrowdSecConnector()
        crowdsec_connector.start()
    except Exception as e:
        print(e)
        sleep(10)
        exit(0)
