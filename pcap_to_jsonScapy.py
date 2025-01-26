from scapy.all import rdpcap
from datetime import datetime
import json
import sys

# Limite massimo per la dimensione del file JSON (1 MB)
MAX_SIZE = 1024 * 1024  # 1 MB

def mac_to_str(mac_bytes):
    """Converte un indirizzo MAC (bytes o stringa) in stringa leggibile."""
    if isinstance(mac_bytes, str):
        return mac_bytes  # Se è già una stringa, restituisci direttamente
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_str(ip_bytes):
    """Converte un indirizzo IP (bytes) in stringa leggibile."""
    return str(ip_bytes)

def format_time(timestamp):
    """Converte un timestamp UNIX in formato RFC 3339."""
    dt = datetime.fromtimestamp(float(timestamp))
    return dt.isoformat(timespec='seconds')  # RFC 3339 richiede un formato preciso fino ai secondi

def extract_pcap_data_with_scapy(pcap_file, output_json_file):
    packets = rdpcap(pcap_file)  # Legge i pacchetti dal file pcap
    extracted_data = []

    for packet in packets:
        packet_info = {
            "event": {
                "type": "network_traffic",
                "start_time": format_time(packet.time)  # Tempo di acquisizione
            },
            "network": {
                "protocol": "Unknown",
                "transport": None,
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None
            },
            "source": {
                "ip": None,
                "mac": None
            },
            "destination": {
                "ip": None,
                "mac": None
            }
        }

        # Livello Ethernet
        if packet.haslayer("Ethernet"):
            eth = packet.getlayer("Ethernet")
            packet_info["source"]["mac"] = mac_to_str(eth.src)
            packet_info["destination"]["mac"] = mac_to_str(eth.dst)

        # Livello IP (IPv4)
        if packet.haslayer("IP"):
            ip = packet.getlayer("IP")
            packet_info["network"]["protocol"] = "IPv4"
            packet_info["source"]["ip"] = ip.src
            packet_info["destination"]["ip"] = ip.dst

        # Livello IPv6
        elif packet.haslayer("IPv6"):
            ipv6 = packet.getlayer("IPv6")
            packet_info["network"]["protocol"] = "IPv6"
            packet_info["source"]["ip"] = str(ipv6.src)
            packet_info["destination"]["ip"] = str(ipv6.dst)

        # Livello TCP
        if packet.haslayer("TCP"):
            tcp = packet.getlayer("TCP")
            packet_info["network"]["transport"] = "TCP"
            packet_info["network"]["src_port"] = tcp.sport
            packet_info["network"]["dst_port"] = tcp.dport

        # Livello UDP
        if packet.haslayer("UDP"):
            udp = packet.getlayer("UDP")
            packet_info["network"]["transport"] = "UDP"
            packet_info["network"]["src_port"] = udp.sport
            packet_info["network"]["dst_port"] = udp.dport

        extracted_data.append(packet_info)

    # Converti i dati estratti in stringa JSON
    json_string = json.dumps(extracted_data, indent=4)

    # Calcola la dimensione del JSON
    size_in_bytes = len(json_string.encode('utf-8'))

    # Controlla se la dimensione supera il limite consentito
    if size_in_bytes > MAX_SIZE:
        print(f"Errore: il file JSON supera il limite di dimensione consentito ({MAX_SIZE} bytes).")
        return

    # Salva i dati estratti in formato JSON
    with open(output_json_file, 'w') as json_file:
        json_file.write(json_string)

    print(f"File JSON creato: {output_json_file} (Dimensione: {size_in_bytes} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python pcap_json.py <input_pcap_file> <output_json_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_json = sys.argv[2]

    # Chiama la funzione principale con gli argomenti forniti
    extract_pcap_data_with_scapy(pcap_file, output_json)
