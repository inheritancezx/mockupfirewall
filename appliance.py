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
[4] converting bytes to int and configuring endianness:
    https://stackoverflow.com/questions/34009653/convert-bytes-to-int
    https://chatgpt.com/share/68e312b0-2ef0-8004-b993-6a69321e800f
[5] iterating syntaxes:
    https://www.geeksforgeeks.org/python/zip-in-python/
    https://www.w3schools.com/python/ref_func_enumerate.asp
[6] concate elements of byte array to string:
    https://www.geeksforgeeks.org/python/zip-in-python/
[7] IPV4 library reference:
    https://docs.python.org/3/library/ipaddress.html

"""

# -----------------------------------------------------------------------------

# Define your classes and functions here

IFACE_NUM = {
    0b00: "mgt",
    0b01: "int",
    0b10: "dmz",
    0b11: "ext"
}

PROTOCOL = { # ed disc ref
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

TCP_FLAGS = ["CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"]
# TCP_STATES = ["new", "syn_sent", "established", "closed"]
ICMP = 0
NOT_ICMP = 0

INCOMPLETE = 0
COMPLETED = 0

DMZ_HTTP = "10.1.0.54"
DMZ_SSH = "10.1.0.92"

class Interface:
    def __init__(self, name, mac, ip, mask, default_ip):
        self.name = name  
        self.mac = mac
        self.ip = ip
        self.mask = mask
        self.default_ip = default_ip
    
    def get_name(self):
        return self.name

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
        hexed = packet.hex() # [2] 
        print(f"{self.name}: sent packet {hexed}")


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
            print("unknown interface")
            return

    def mgt_packet(self, packet: bytes):
        hexed = packet.hex()
        print(f"Actioned management packet {hexed}")
    
    def __del__(self): # [3]  
        self.file.close()
    

class PatTable:
    def __init__(self):
        self.from_out: Dict[int, str] = {}
        self.to_out: Dict[Tuple[str, int], int] = {}

    def set_pat(self, in_address: str, in_port: int, out_port: int):
        self.from_out[out_port] = f"{in_address}:{in_port}"
        self.to_out[(in_address, in_port)] = out_port
        print(f"NAT: allocate {in_address}:{in_port} -> {ext.ip}:{out_port}")
    
    def get_unused_port(self):
        start = 49152
        end = 65535
        while True:
            port = random.randint(start, end)
            if port not in self.to:
                return port
    
    def get_pat_in(self,out_port: int):
        return self.from_out.get(out_port, None)

    def get_pat_out(self, in_address: str, in_port: int):
        return self.to_out.get((in_address, in_port), None)


# nic(s)
mgt = Interface("mgt", "28:ee:52:85:f2:3a", "192.168.96.23", "255.255.240.0", None)
inw = Interface("int", "28:ee:52:e2:b7:30", "10.0.0.1", "255.255.0.0", None)
dmz = Interface("dmz", "28:ee:52:4c:4d:70", "10.1.0.1", "255.255.255.0", None)
ext = Interface("ext", "28:ee:52:9c:61:ab", "130.102.184.1", "255.255.255.0", None)


class RouteTable:
    def __init__(self):
        self.routes = {}
        for iface in [mgt, inw, dmz, ext]:
            if iface.ip and iface.mask:
                net = ipaddress.IPv4Network(f"{iface.ip}/{iface.mask}", strict=False) # [7]
                self.routes[iface.name] = net

    def resolve(self, ip):
        dest_ip = ipaddress.ip_address(ip) # [7]
        best_iface = "ext"
        best_prefix = -1
        for iface, net in self.routes.items():
            if dest_ip in net and net.prefixlen > best_prefix:
                best_prefix = net.prefixlen
                best_iface = iface
        return best_iface


class Connections:
    def __init__(self):
        self.table = {}

    def add_or_update(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str,
    dst_p: int, state: str):
        # key = (nic, proto, src_ip, src_port, dst_ip, dst_p)
        # self.table[key] = state

        key = (nic, proto, src_ip, src_port, dst_ip, dst_p)
        prev_state = self.table.get(key)

        if prev_state:
            self.table[key] = state
        else:
            self.table[key] = state
    
    def state(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int):
        key = (nic, proto, src_ip, src_port, dst_ip, dst_p)
        return self.table.get(key)

    # rule 10
    def jump_box_to(self, parsed: Dict[str, Any], ip_type):
            parsed['interface'] = dmz.get_name()
            parsed['ip_dst'] = ip_type
            parsed['mac_src'] = dmz.get_mac()
            parsed['mac_dst'] = "96:a1:44:e3:6e:ae" # random mac

    def jump_box_from(self, parsed: Dict[str, Any], ip_type):
        parsed['interface'] = ext.get_name()
        parsed['ip_dst'] = ip_type
        parsed['mac_src'] = ext.get_mac()
        parsed['mac_dst'] = "96:a1:44:e3:6e:ae" # random mac
    

class Translate:
    def __init__(self, hex_line: str):
        self.hex_line = hex_line
        self.bytes_data = bytes.fromhex(hex_line)
        self.parsed = {}

    def tcp_flags(self, flag_byte: int):
        flag_bits = f"{flag_byte:08b}" # convert to 8-bit 
        return [name for bit, name in zip(flag_bits, TCP_FLAGS) if bit == '1'] # [5]

    def unpackage(self):
        b = self.bytes_data
        first_byte = b[0]

        # iface
        iface_bits = first_byte % 4   
        self.parsed['interface'] = IFACE_NUM.get(iface_bits, "unknown")

        # mac addr
        self.parsed['mac_dst'] = ':'.join(f'{x:02x}' for x in b[1:7]) # [6]
        self.parsed['mac_src'] = ':'.join(f'{x:02x}' for x in b[7:13])

        # ethertype (expect 0x0800)
        eth_type = b[13:15]
        self.parsed['ethertype'] = ''.join(f'{byte:02x}' for byte in eth_type)
        if eth_type != b'\x08\x00':
            return -1

        # protocol, src, dst
        ip_protocol = b[15]
        self.parsed['ip_protocol'] = PROTOCOL.get(ip_protocol, ip_protocol)
        self.parsed['ip_src'] = '.'.join(str(x) for x in b[16:20])
        self.parsed['ip_dst'] = '.'.join(str(x) for x in b[20:24])

        # protocol specific
        if ip_protocol == 6:  # TCP
            self.parsed['tcp_src_port'] = int.from_bytes(b[24:26], 'big') # [4]
            self.parsed['tcp_dst_port'] = int.from_bytes(b[26:28], 'big')
            self.parsed['tcp_flags'] = self.tcp_flags(b[36])
            self.parsed['payload'] = b[37:]
        elif ip_protocol == 17:  # UDP
            self.parsed['udp_src_port'] = int.from_bytes(b[24:26], 'big')
            self.parsed['udp_dst_port'] = int.from_bytes(b[26:28], 'big')
            self.parsed['payload'] = b[28:]
        elif ip_protocol == 1:  # ICMP
            self.parsed['icmp_type'] = b[24]
            self.parsed['icmp_code'] = b[25]
            self.parsed['icmp_header'] = b[26:30].hex()
            self.parsed['payload'] = b[30:]
        else:
            return -1

        return self.parsed
    

    def repackage(self):
        original = self.bytes_data[0]
        prefix_bits = original - (original % 4)

        # iface
        iface_bits = {v: k for k, v in IFACE_NUM.items()}[self.parsed['interface']]
        first_byte = prefix_bits + iface_bits

        # mac addr 
        mac_dst = bytes.fromhex(self.parsed['mac_dst'].replace(':', ''))
        mac_src = bytes.fromhex(self.parsed['mac_src'].replace(':', ''))

        # ethertype
        ethertype = bytes.fromhex(self.parsed['ethertype'])

        # protocol, src, dst 
        protocol_num = {v: k for k, v in PROTOCOL.items()}[self.parsed['ip_protocol']]
        ip_src = bytes(map(int, self.parsed['ip_src'].split('.')))
        ip_dst = bytes(map(int, self.parsed['ip_dst'].split('.')))

        # protocol specific
        payload = self.parsed.get('payload', b'')
        protocol_fields = b''
        if protocol_num == 6:  # TCP
            flags_byte = 0
            for i, flag in enumerate(TCP_FLAGS):
                if flag in self.parsed.get('tcp_flags', []):
                    flags_byte |= (1 << (7 - i))
            

            seq_num = self.bytes_data[28:32]  # TCP sequence number (4 bytes)
            ack_num = self.bytes_data[32:36]  # TCP ack number (4 bytes)
            
            protocol_fields = (
                self.parsed['tcp_src_port'].to_bytes(2, 'big') +
                self.parsed['tcp_dst_port'].to_bytes(2, 'big') +
                seq_num +  
                ack_num + 
                flags_byte.to_bytes(1, 'big')  
            )
        elif protocol_num == 17:  # UDP
            protocol_fields = (
                self.parsed['udp_src_port'].to_bytes(2, 'big') +
                self.parsed['udp_dst_port'].to_bytes(2, 'big')
            )
        elif protocol_num == 1:  # ICMP
            protocol_fields = (
                self.parsed['icmp_type'].to_bytes(1, 'big') +
                self.parsed['icmp_code'].to_bytes(1, 'big') +
                bytes.fromhex(self.parsed['icmp_header'])
            )

        # packet assembly
        packet = (
            first_byte.to_bytes(1, 'big') +
            mac_dst +
            mac_src +
            ethertype +
            protocol_num.to_bytes(1, 'big') +
            ip_src +
            ip_dst +
            protocol_fields +
            payload
        )

        return packet

class Rules:
    def __init__(self, route_table, conn_table):
        self.route_table = route_table
        self.conn_table = conn_table

    def icmp_rules(self, packet: bytes, parsed: Dict[str, Any]):
        icmp_type = parsed['icmp_type']
        icmp_code = parsed['icmp_code']
        ip_src = parsed['ip_src']
        global ICMP
        ICMP += 1

        # rule 3
        length = len(packet) / 2 # 1 bytes = 2 hex chars
        if icmp_type == 8 and length > 64:
            print(f"ALERT drop: oversize ping from {ip_src} ({length} bytes)")
            return 3
        
        # rule 4
        if ICMP > 5:
            print(f"ALERT drop: ping rate limit from {ip_src}")
            return 4
        
        # rule 5
        if ICMP < 5 and ICMP % 5 == 0:
            return 5
        
        # rule 6    
        if icmp_type != 8 and icmp_type != 0:
            print(f"ALERT drop: ICMP type {icmp_type}:{icmp_code} not allowed by policy")
            return 6
        
        return 0

    def ssh_rules(self, parsed: Dict[str, Any]):
        ip_src = parsed['ip_src']
        ip_dst = parsed['ip_dst']
        iface_in = parsed['interface']
        port = parsed['tcp_dst_port']

        # rule 8
        if iface_in == "mgt" and port == 22:
            if ip_src != "192.168.96.9":
                print("ALERT drop: new incoming TCP not allowed by policy")
                return 8
            else:
                return 0
        # rule 10
        elif iface_in == "ext" and port == 22:
            self.conn_table.jump_box_to(parsed, DMZ_SSH)
            return 0
        # rule 12
        elif iface_in == "int" and port == 22:
            if self.route_table.resolve(ip_dst) != "dmz":
                return 12
        # rule 13
        elif iface_in == "dmz" and port == 22 and ip_src == "10.1.0.92":
            if self.route_table.resolve(ip_dst) == "int":
                return 0
        # rule 14
        elif iface_in == "dmz" and port == 22 :
            if self.route_table.resolve(ip_dst) != "int":
                return 14
        
        return 0
    
    # rule 2
    def flag_rules(self, parsed: Dict[str, Any]):
        flags = parsed['tcp_flags']

        clean_flags = [f for f in flags if f not in ('URG', 'PSH')]
        parsed['tcp_flags'] = clean_flags
    
    def incomplete_rules(self, parsed: Dict[str, Any]):
        #rule 7
        iface = parsed['interface']
        proto = parsed['ip_protocol']
        ip_src = parsed['ip_src']
        ip_dst = parsed['ip_dst']
        src_port = parsed['tcp_src_port']
        dst_port = parsed['tcp_dst_port']
        flags = parsed['tcp_flags']
        global INCOMPLETE, COMPLETED
        
        # key = (ip_src, src_port, ip_dst, dst_port)

        if 'SYN' in flags and 'ACK' not in flags:
            # self.conn_table.add_or_update(iface, proto, ip_src, src_port, ip_dst, dst_port, "syn_sent")
            pass
        elif 'SYN' in flags:
            # self.conn_table.add_or_update(iface, proto, ip_src, src_port, ip_dst, dst_port, "new")
            INCOMPLETE += 1
        elif 'ACK' in flags:
            # self.conn_table.add_or_update(iface, proto, ip_src, src_port, ip_dst, dst_port, "established")
            COMPLETED += 1

        packet = INCOMPLETE - COMPLETED
        if packet > 100:
            print("ALERT drop: too many incomplete connections")
    
    def udp_rules(self, parsed: Dict[str, Any]):
        iface_in = parsed['interface']

        # rule 8
        if iface_in == "mgt":
            print("ALERT drop: new incoming UDP not allowed by policy")
            return 8
    
    def dns_rules(self, parsed: Dict[str, Any]):
        iface_in = parsed['interface']
        
        # rule 9
        if iface_in == "ext":
            return 9
        elif iface_in in ["int", "dmz"]:
            return 0
        # rule 8
        elif iface_in == "mgt":
            print("ALERT drop: new incoming UDP not allowed by policy")
            return 8
        
        return 0

    def http_rules(self, parsed: Dict[str, Any]):
        iface_in = parsed['interface']
        port = parsed['tcp_dst_port']
        
        # rule 15
        if iface_in in ["ext", "int"] and port in [80, 443]:
            if iface_in == "ext":
                self.conn_table.jump_box_to(parsed, DMZ_HTTP)
            return 0
        elif iface_in == "dmz" and port in [80, 443]:
            return 0
        
        print("ALERT drop: new incoming TCP not allowed by policy")
        return 15

    def pat_rules(self, parsed: Dict[str, Any]):
        iface_in = parsed['interface']
        
        if iface_in == "int":
            return 0
        
        return 0


class PacketEngine:  
    def __init__(self, interface_handler: InterfaceHandler):
        self.interface_handler = interface_handler
        self.route_table = RouteTable()
        self.conn_table = Connections()
        self.rules = Rules(self.route_table, self.conn_table)

    def process_packet(self, packet: bytes):
        routed_iface, tr_bytes = self.check_packet(packet)
        if not routed_iface or not tr_bytes:
            return  # dropped

        if routed_iface == "mgt":
            self.interface_handler.mgt_packet(tr_bytes)
        else:
            self.route_packet(routed_iface, tr_bytes)

    def check_packet(self, packet: bytes):
        tr = Translate(packet)
        parsed = tr.unpackage()

        if parsed == -1:
            return (None, None)
        
        # icmp 
        if parsed.get('ip_protocol') == "ICMP":
            if parsed['icmp_type'] == 8:  # Echo request
                parsed['ip_src'], parsed['ip_dst'] = parsed['ip_dst'], parsed['ip_src']
                parsed['mac_src'], parsed['mac_dst'] = parsed['mac_dst'], parsed['mac_src']
                parsed['icmp_type'] = 0
            
            if self.rules.icmp_rules(bytes.fromhex(packet), parsed) == 0:
                tr.parsed = parsed  
                tr_bytes = tr.repackage()
                routed_iface = self.route_table.resolve(parsed['ip_dst'])
                return (routed_iface, tr_bytes)
            return (None, None)

        # tcp
        elif parsed.get('ip_protocol') == "TCP":
            self.rules.flag_rules(parsed)
            self.rules.incomplete_rules(parsed)

            # ssh
            if parsed.get('tcp_dst_port') == 22:
                if self.rules.ssh_rules(parsed) == 0:
                    tr_bytes = tr.repackage()
                    routed_iface = self.route_table.resolve(parsed['ip_dst'])
                    return (routed_iface, tr_bytes)
            # http
            elif parsed.get('tcp_dst_port') in [80, 443]:
                if self.rules.http_rules(parsed) == 0:
                    tr_bytes = tr.repackage()
                    routed_iface = self.route_table.resolve(parsed['ip_dst'])
                    return (routed_iface, tr_bytes)
            # dns
            elif parsed.get('tcp_dst_port') == 53:
                if self.rules.dns_rules(parsed) == 0:
                    tr_bytes = tr.repackage()
                    routed_iface = self.route_table.resolve(parsed['ip_dst'])
                    return (routed_iface, tr_bytes)
            else:
                print("ALERT drop: new incoming TCP not allowed by policy")
                return (None, None)

        # udp
        elif parsed.get('ip_protocol') == "UDP":
            # dns
            if parsed.get('udp_dst_port') == 53:
                if self.rules.dns_rules(parsed) == 0:
                    tr_bytes = tr.repackage()
                    routed_iface = self.route_table.resolve(parsed['ip_dst'])
                    return (routed_iface, tr_bytes)
            else:
                if self.rules.udp_rules(parsed) == 0:
                    tr_bytes = tr.repackage()
                    routed_iface = self.route_table.resolve(parsed['ip_dst'])
                    return (routed_iface, tr_bytes)
            return (None, None)
        
        # other
        else:
            print("ALERT drop: new incoming TCP not allowed by policy")
            return (None, None)

    def route_packet(self, interface: str, packet: bytes):
        print(f"ROUTE to {interface}")
        self.interface_handler.send_packet(interface, packet)
        return
        


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