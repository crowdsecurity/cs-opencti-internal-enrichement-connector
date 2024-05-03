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
    return re.sub(r"[\"']", "", value)
