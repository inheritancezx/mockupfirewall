# DO NOT modify or add any import statements
from __future__ import annotations
import os
import sys
import struct
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Any
from support import *
# DO NOT modify or add any import statements

"""
Include your name and student number here (because everybody is submitting 'appliance.py')
"""

# Name: Fayza Bachtiar
# Student Number: 49493339
# -----------------------------------------------------------------------------

"""
IMPORTANT! You MUST cite and reference ANY external sources used!
Cite then in comments in the code, e.g. [1] used ChatGPT to get the format for 'if'

PUT YOUR REFERENCES HERE:

[1] Author, Title, etc., [online]. Available: https://blah.blah.blah
[2]




"""

# -----------------------------------------------------------------------------

# Define your classes and functions here






# ------------------- Simulator runner -------------------
# DO NOT MODIFY the run_appliance definition IN ANY WAY
# It MUST work as run_appliance("filename.spcap") as defined here

def run_appliance(cap_file: str = "traffic.spcap") -> None:
    ih = InterfaceHandler(cap_file)
    pe = PacketEngine(ih)
    while True:
        raw = ih.next_packet()
        if raw is None:
            break
        pe.process_packet(raw)

# --------------- Main ---------------
# DO NOT modify the run_appliance call
# It MUST work as run_appliance("traffic.spcap")
#
# Leaving a main() wrapper for those who like it
# You could just as easily run_appliance("traffic.spcap") directly
# instead of calling main() to do it

def main():
    run_appliance("traffic.spcap")

if __name__ == "__main__":
    main()