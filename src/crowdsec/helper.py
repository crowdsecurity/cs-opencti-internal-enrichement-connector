# -*- coding: utf-8 -*-
"""CrowdSec helper module."""
import datetime
import re
from typing import Optional, Dict, Any

from .constants import LAST_ENRICHMENT_PATTERN


def clean_config(value: str) -> str:
    """Clean a string configuration value.

    Args:
        value (str): The value to clean.

    Returns:
        str: The cleaned value.
    """
    if isinstance(value, str):
        return re.sub(r"[\"']", "", value)

    return ""


def convert_timestamp_to_utc_iso(timestamp: int) -> str:
    """Convert a timestamp to UTC ISO format.

    Args:
        timestamp (str): The timestamp to convert.

    Returns:
        str: The converted timestamp.
    """
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat()


def convert_utc_iso_to_timestamp(iso: str) -> int:
    """Convert a UTC ISO format to a timestamp.

    Args:
        iso (str): The UTC ISO format to convert.

    Returns:
        int: The converted timestamp.
    """
    return int(datetime.datetime.fromisoformat(iso).timestamp())


def handle_observable_description(
    timestamp: int, stix_observable: Optional[Dict]
) -> Dict[str, Any]:
    """Handle the observable description.

    We are saving the current timestamp in description to track the last time the observable was enriched by CrowdSec.

    Args:
        timestamp (int): The current timestamp.
        stix_observable (Dict): The STIX observable to handle.

    Returns:
        Dict: The updated description with current timestamp and the time since the last enrichment.
    """
    description = ""
    time_since_last_enrichment = -1  # -1 means no previous enrichment
    if stix_observable and stix_observable["x_opencti_description"]:
        sub_pattern = r"`" + re.escape(LAST_ENRICHMENT_PATTERN) + r".*`"
        search_pattern = (
            re.escape(LAST_ENRICHMENT_PATTERN) + r"([\d-]+T[\d:]+[+-][\d:]+)"
        )
        match = re.search(search_pattern, stix_observable["x_opencti_description"])
        if match:
            time_since_last_enrichment = timestamp - convert_utc_iso_to_timestamp(
                match.group(1)
            )
        description = re.sub(
            sub_pattern + r"|\n\n" + sub_pattern,
            "",
            stix_observable["x_opencti_description"],
        )
    description += (
        f"\n\n`{LAST_ENRICHMENT_PATTERN}{convert_timestamp_to_utc_iso(timestamp)}`"
    )

    return {
        "description": description,
        "time_since_last_enrichment": time_since_last_enrichment,
    }
