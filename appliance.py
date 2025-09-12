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

[1] For further understading of the oop principles in python: 
    https://www.w3schools.com/python/python_classes.asp
[2] bytes to hexadecimal typecasting: 
    https://stackoverflow.com/questions/6624453/
    whats-the-correct-way-to-convert-bytes-to-a-hex-string-in-python-3
[3] file closing and python oop destructor function:
    https://chatgpt.com/share/68c418b7-e51c-8004-aff3-15690bb2a02d
    https://www.geeksforgeeks.org/python/destructors-in-python/




"""

# -----------------------------------------------------------------------------

# Define your classes and functions here

class Interface:
    def __init__(self, name, mac, ip, mask, default_ip):
        self.name = name  
        self.mac = mac
        self.ip = ip
        self.mask = mask
        self.default_ip = default_ip

    def get_mac(self):
        return self.mac

    def set_mac(self, mac_address):
        validate_mac_string(mac_address)  
        self.mac = mac_address

    def get_ip(self):
        return self.ip

    def set_ip(self, ip_address):
        validate_ipv4(ip_address) 
        self.ip = ip_address

    def get_mask(self):
        return self.mask

    def set_mask(self, netmask):
        validate_ipv4(netmask)
        self.mask = netmask

    def get_default(self):
        return self.default_ip

    def set_default(self, ip_address):
        validate_ipv4(ip_address)
        self.default_ip = ip_address

    def send_packet(self, packet: bytes):
        hexed = packet.hex() # [2] bytes to hexadecimal typecast
        print(f"{self.name}: sent packet" + {hexed})


class InterfaceHandler:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(self.filename, "r")
    
    def next_packet(self):
        line = self.file.readline()  
        if line == "":
            return None
        else:
            return line.strip()

    def send_packet(self, interface: str, packet: bytes):
        if interface == "mgt":
            mgt.send_packet(packet)
        elif interface == "int":
            inw.send_packet(packet)
        elif interface == "dmz":
            dmz.send_packet(packet)
        elif interface == "ext":
            ext.send_packet(packet)
        else:
            print("unknown nic")
            return

    def mgt_packet(self, packet: bytes):
        hexed = packet.hex()
        print(f"Actioned management packet" + {hexed})
    
    def __del__(self): # [3] closing file and destructor function 
        self.file.close()



# nic(s)

mgt = Interface("mgt", "28:ee:52:85:f2:3a", "192.168.96.23", "255.255.240.0", None)
inw = Interface("int", "28:ee:52:e2:b7:30", "10.0.0.1", "255.255.0.0", None)
dmz = Interface("dmz", "28:ee:52:4c:4d:70", "10.1.0.1", "255.255.255.0", None)
ext = Interface("ext", "28:ee:52:9c:61:ab", "130.102.184.1", "255.255.255.0", None)


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