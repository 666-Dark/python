#!/usr/bin/env python

import scapy.all as scapy
import argparse

def arguments():
    parser  = argparse.ArgumentParser()
    parser.add_argument('-t','--target', dest='target',help='Target IP / IP Range')
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    Main_request = broadcast / arp_request 
    answered  = scapy.srp(Main_request, timeout=1,verbose = False)[0]
    
   
    client_list=[]
    for element in answered:
        client_dict = {'ip': element[1].psrc,'mac': element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def design(result_list):
     print('IP\t\t\tMAC ADDRESS\n=============================================')
     for client in result_list:
        print(client["ip"]+ '\t\t\t' + client["mac"])

options = arguments()
scan_result = scan(options.target)
design(scan_result) 