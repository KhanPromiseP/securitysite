import scapy.all as scapy
import nmap

def scan_network():
    nm = nmap.PortScanner()
    nm.scan('192.168.1.0/24', arguments='-sn --host-timeout 60s')
    
    detected_hosts = []

    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            host_details = {
                "ip_address": host,
                "hostname": nm[host].hostname(),
                "os": nm[host]['osmatch'][0]['name'] if nm[host].has_tcp(80) and nm[host]['tcp'][80]['state'] == 'open' else 'Unknown',
                "open_ports": [port for port in nm[host].all_tcp() if nm[host]['tcp'][port]['state'] == 'open'],
                "behavior_details": "Host detected during Nmap scan"
            }
            detected_hosts.append(host_details)

    scapy_hosts = scapy.arping('192.168.1.0/24', iface='Intel(R) Dual Band Wireless-AC 7265', timeout=60, verbose=True)[0]

    for sent, received in scapy_hosts:
        detected_hosts.append({
            "ip_address": received.psrc,
            "mac_address": received.hwsrc,
            "behavior_details": "Host detected during Scapy ARP scan"
        })

    return detected_hosts
