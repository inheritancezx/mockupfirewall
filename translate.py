import struct

class Translate:
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

    def __init__(self, hex_line: str):
        self.hex_line = hex_line
        self.bytes_data = bytes.fromhex(hex_line)
        self.parsed = {}

    def tcp_flags(self, flag_byte: int):
        flag_bits = f"{flag_byte:08b}" # convert to 8-bit 
        return [name for bit, name in zip(flag_bits, self.TCP_FLAGS) if bit == '1'] # [5]

    def parse(self):
        b = self.bytes_data
        first_byte = b[0]

        # iface
        iface_bits = first_byte % 4   
        self.parsed['interface'] = self.IFACE_NUM.get(iface_bits, "unknown")

        # mac addr
        self.parsed['mac_dst'] = ':'.join(f'{x:02x}' for x in b[1:7]) # [6]
        self.parsed['mac_src'] = ':'.join(f'{x:02x}' for x in b[7:13])

        # ethertype (expect 0x0800)
        eth_type = b[13:15]
        self.parsed['ethertype'] = ''.join(f'{byte:02x}' for byte in eth_type)
        if eth_type != b'\x08\x00':
            raise ValueError("Ethertype: not IPv4")

        # protocol, src, dst
        ip_protocol = b[15]
        self.parsed['ip_protocol'] = self.PROTOCOL.get(ip_protocol, ip_protocol)
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
            raise ValueError("Unknown protocol")

        return self.parsed

    def pretty_print(self):
        for k, v in self.parsed.items():
            # if isinstance(v, bytes):
            # v = v.hex()
            t = type(v).__name__
            print(f"{k}: {v} {t}")


# Example usage: read from file
with open("traffic.spcap", "r") as f:  # replace with your filename
    for line in f:
        line = line.strip()  # remove newline and spaces
        if not line:         # skip empty lines
            continue
        t = Translate(line)
        t.parse()
        t.pretty_print()
        print("-" * 40)

