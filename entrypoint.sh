#!/bin/sh

# Correct working directory
cd /opt/opencti-crowdsec || exit

# Start the connector
python3 crowdsec.py

