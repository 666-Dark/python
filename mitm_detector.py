import scapy.all as scapy



def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    Main_request = broadcast / arp_request 
    answered  = scapy.srp(Main_request, timeout=1,verbose = False)[0]
    
    return answered[0][1].hwsrc

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=captured_packet)

def captured_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            
            if real_mac != response_mac:
                print("[+]Warning:You are under attack!!!!")
        except IndexError:
            pass

sniffer('eth0')