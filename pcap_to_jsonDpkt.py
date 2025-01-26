import dpkt
import json
import socket
import sys
from datetime import datetime, timezone

# Limite massimo per la dimensione del file JSON (1 MB)
MAX_SIZE = 1024 * 1024  # 1 MB

def mac_to_str(mac_bytes):
    """Converte un indirizzo MAC (bytes) in stringa leggibile."""
    return ':'.join(f'{b:02x}' for b in mac_bytes)

def ip_to_str(ip_bytes):
    """Converte un indirizzo IP (bytes) in stringa leggibile."""
    return socket.inet_ntoa(ip_bytes)

def format_time_rfc3339(timestamp):
    """Converte un timestamp UNIX in formato RFC 3339."""
    dt = datetime.fromtimestamp(timestamp, timezone.utc)
    return dt.isoformat(timespec='seconds')  # Format RFC 3339 (preciso fino ai secondi)

def extract_pcap_with_dpkt(pcap_file, output_json_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        extracted_data = []

        for timestamp, buf in pcap:
            # Creazione di un evento con dettagli specifici
            packet_info = {
                "event": {
                    "type": "network_traffic",  # Tipo di evento
                    "start_time": format_time_rfc3339(timestamp),  # Tempo in formato RFC 3339
                    "event_id": str(timestamp),  # ID evento basato sul timestamp
                    "device": "pcap_device"  # Nome del dispositivo (ipotetico, personalizzabile)
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

            try:
                eth = dpkt.ethernet.Ethernet(buf)
                packet_info["source"]["mac"] = mac_to_str(eth.src)  # Converte MAC sorgente
                packet_info["destination"]["mac"] = mac_to_str(eth.dst)  # Converte MAC destinazione

                # Gestisci pacchetti IPv4
                if isinstance(eth.data, dpkt.ip.IP):  # Livello IP (IPv4)
                    ip = eth.data
                    packet_info["network"]["protocol"] = "IPv4"
                    packet_info["source"]["ip"] = ip_to_str(ip.src)  # Converte IP sorgente
                    packet_info["destination"]["ip"] = ip_to_str(ip.dst)  # Converte IP destinazione

                    if isinstance(ip.data, dpkt.tcp.TCP):  # Livello TCP
                        tcp = ip.data
                        packet_info["network"]["transport"] = "TCP"
                        packet_info["network"]["src_port"] = tcp.sport
                        packet_info["network"]["dst_port"] = tcp.dport

                    if isinstance(ip.data, dpkt.udp.UDP):  # Livello UDP
                        udp = ip.data
                        packet_info["network"]["transport"] = "UDP"
                        packet_info["network"]["src_port"] = udp.sport
                        packet_info["network"]["dst_port"] = udp.dport

                # Gestisci pacchetti IPv6
                elif isinstance(eth.data, dpkt.ip6.IP6):  # Livello IPv6
                    ip6 = eth.data
                    packet_info["network"]["protocol"] = "IPv6"
                    packet_info["source"]["ip"] = socket.inet_ntop(socket.AF_INET6, ip6.src)  # Converte IP sorgente IPv6
                    packet_info["destination"]["ip"] = socket.inet_ntop(socket.AF_INET6, ip6.dst)  # Converte IP destinazione IPv6

                    if isinstance(ip6.data, dpkt.tcp.TCP):  # Livello TCP
                        tcp = ip6.data
                        packet_info["network"]["transport"] = "TCP"
                        packet_info["network"]["src_port"] = tcp.sport
                        packet_info["network"]["dst_port"] = tcp.dport

                    if isinstance(ip6.data, dpkt.udp.UDP):  # Livello UDP
                        udp = ip6.data
                        packet_info["network"]["transport"] = "UDP"
                        packet_info["network"]["src_port"] = udp.sport
                        packet_info["network"]["dst_port"] = udp.dport

                extracted_data.append(packet_info)

            except Exception as e:
                print(f"Errore durante l'elaborazione del pacchetto: {e}")

    # Converti i dati estratti in stringa JSON
    json_string = json.dumps(extracted_data, indent=4)

    # Calcola la dimensione del file JSON
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
    extract_pcap_with_dpkt(pcap_file, output_json)
