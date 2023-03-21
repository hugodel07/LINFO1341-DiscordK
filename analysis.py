import pyshark
from pyshark.packet.packet import Packet
from typing import List

cap: pyshark.FileCapture = pyshark.FileCapture('trace_1_vid_outgoing.pcapng', display_filter="dns")

dns_domains: List[str] = []
dns_ips: List[str] = []
dns_queries_types: List[str] = []

packet: Packet
for packet in cap:
    # find all the dns packets
    if 'dns' in packet:
        # check if the dns packet is a query
        if packet.dns.flags == '0x00000100' or packet.dns.flags == '0x00000120':
            print(f"Query: {packet.dns.qry_name}")
        else:
            print(f"Response: {packet.dns.resp_name}, {'A' if packet.dns.get_field('resp_type') == '1' else 'AAAA'}, {packet.dns.get_field('a')}, {packet.dns.get_field('aaaa')}")

