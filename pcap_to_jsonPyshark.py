import pyshark
import json
import sys
from datetime import datetime, timezone

# Limite massimo per la dimensione del file JSON (1 MB)
MAX_SIZE = 1024 * 1024

def extract_pcap_data(pcap_file, output_json_file):
    """
    Prima bozza funzionante con controllo della dimensione del file JSON
    """
    cap = pyshark.FileCapture(pcap_file)
    extracted_data = []  # Lista per contenere i dati estratti dai pacchetti

    for packet in cap:
        packet_info = {
            "event": {
                "type": "network_traffic",
                "start_time": packet.sniff_time.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S%z') if hasattr(packet, 'sniff_time') else None
            },
            "network": {
                "protocol": None,
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

        # Esamina i livelli del pacchetto (es. Ethernet, IP, TCP, UDP)
        if "ETH" in packet:  # Livello Ethernet
            eth_layer = packet.eth
            packet_info["source"]["mac"] = getattr(eth_layer, "src", None)
            packet_info["destination"]["mac"] = getattr(eth_layer, "dst", None)

        if "IP" in packet:  # Livello IP
            ip_layer = packet.ip
            packet_info["network"]["protocol"] = getattr(ip_layer, "version", None)
            packet_info["source"]["ip"] = getattr(ip_layer, "src", None)
            packet_info["destination"]["ip"] = getattr(ip_layer, "dst", None)

        if "TCP" in packet:  # Livello TCP
            tcp_layer = packet.tcp
            packet_info["network"]["transport"] = "TCP"
            packet_info["network"]["src_port"] = getattr(tcp_layer, "srcport", None)
            packet_info["network"]["dst_port"] = getattr(tcp_layer, "dstport", None)

        if "UDP" in packet:  # Livello UDP
            udp_layer = packet.udp
            packet_info["network"]["transport"] = "UDP"
            packet_info["network"]["src_port"] = getattr(udp_layer, "srcport", None)
            packet_info["network"]["dst_port"] = getattr(udp_layer, "dstport", None)

        # I dati del pacchetto trasformato in dizionario vengono aggiunti alla lista
        extracted_data.append(packet_info)

    # Converti i dati estratti in stringa JSON
    json_string = json.dumps(extracted_data, indent=4, default=str)
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
        print("Usage: python pcap_to_Json.py <input_pcap_file> <output_json_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_json = sys.argv[2]

    # Chiama la funzione principale con gli argomenti forniti
    extract_pcap_data(pcap_file, output_json)
