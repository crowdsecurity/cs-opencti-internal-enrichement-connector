# -*- coding: utf-8 -*-
"""CrowdSec helper module."""

import re


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
