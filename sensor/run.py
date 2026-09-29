#!/usr/bin/env python3
"""Run the Guardian sensor from anywhere: python3 /path/to/sensor/run.py --config guardian.json -- <server cmd>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from guardian_sensor.sensor import main  # noqa: E402

main()
