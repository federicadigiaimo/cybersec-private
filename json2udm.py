import json
import sys
import os
import logging

# Configura il logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

#funzione
def json_to_udm(input_json):
    """
    Convert Tshark JSON export to Google Chronicle JSON-UDM format.

    Args:
        input_json (str): JSON string from Tshark output.

    Returns:
        list: List of dictionaries in JSON-UDM format.
    """
    try:
        packets = json.loads(input_json)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        return []
    
    udm_events = []

    for packet in packets:
        try:
            layers = packet.get("_source", {}).get("layers", {})

            # Ottiene i layer
            frame = layers.get("frame", {})
            eth = layers.get("eth", {})
            ip = layers.get("ip", {}) or layers.get("ipv6")
            arp = layers.get("arp")
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            icmp = layers.get("icmp")  # Supporto ICMP
            http = layers.get("http")  # Supporto HTTP
            

            # Determinazione tipo di evento
            if arp:
                event = {
                    "event": {
                        "type": "ARP_REQUEST",
                        "start_time": frame.get("frame.time_utc", "unknown"),
                    },
                    "network": {
                        "protocol": "ARP",
                        "src_ip": arp.get("arp.src.proto_ipv4", "unknown"),
                        "dst_ip": arp.get("arp.dst.proto_ipv4", "unknown"),
                    },
                    "source": {
                        "mac": arp.get("arp.src.hw_mac", "unknown"),
                    },
                    "destination": {
                        "mac": arp.get("arp.dst.hw_mac", "unknown"),
                    },
                }
                udm_events.append(event)
                logging.info(f"Event added: {event}")
                continue  # Continua alla prossima iterazione
            
            if eth:
                event = {
                    "event": {
                        "type": "ETHERNET_FRAME",
                        "start_time": frame.get("frame.time_utc", "unknown"),
                    },
                    "source": {
                        "mac": eth.get("eth.src", "unknown"),
                    },
                    "destination": {
                        "mac": eth.get("eth.dst", "unknown"),
                    },
                }
                udm_events.append(event)
                logging.info(f"Event added: {event}")
                continue  # Continua alla prossima iterazione
            
            # Gestione pacchetti ICMP
            if icmp:
                event = {
                    "event": {
                        "type": "ICMP_REQUEST",
                        "start_time": frame.get("frame.time_utc", "unknown"),
                    },
                    "network": {
                        "protocol": "ICMP",
                        "src_ip": ip.get("ip.src", "unknown"),
                        "dst_ip": ip.get("ip.dst", "unknown"),
                    },
                    "source": {
                        "ip": ip.get("ip.src", "unknown"),
                        "mac": eth.get("eth.src", "unknown"),
                    },
                    "destination": {
                        "ip": ip.get("ip.dst", "unknown"),
                        "mac": eth.get("eth.dst", "unknown"),
                    },
                }
                udm_events.append(event)
                logging.info(f"Event added: {event}")
                continue  # Continua alla prossima iteraziones
                
            # Gestisci pacchetti IP
            if ip:
                event_type = "NETWORK_CONNECTION"
                if http:
                    event_type = "HTTP_REQUEST"
                elif icmp:
                    event_type = "ICMP_REQUEST"
            
                event = {
                    "event": {
                        "type": event_type,
                        "start_time": frame.get("frame.time_utc", "unknown"),
                    },
                    "network": {
                        "protocol": frame.get("frame.protocols", "unknown"),
                        "src_ip": ip.get("ip.src", "unknown"),
                        "dst_ip": ip.get("ip.dst", "unknown"),
                        "src_port": tcp.get("tcp.srcport", "unknown") if tcp else (udp.get("udp.srcport", "unknown") if udp else "unknown"),
                        "dst_port": tcp.get("tcp.dstport", "unknown") if tcp else (udp.get("udp.dstport", "unknown") if udp else "unknown"),
                    },
                    "source": {
                        "ip": ip.get("ip.src", "unknown"),
                        "mac": eth.get("eth.src", "unknown"),
                    },
                    "destination": {
                        "ip": ip.get("ip.dst", "unknown"),
                        "mac": eth.get("eth.dst", "unknown"),
                    },
                }
                udm_events.append(event)
                logging.info(f"Event added: {event}")
                continue  # Continua alla prossima iterazione
            
            # Gestione pacchetti TCP e UDP
            if tcp or udp:
                event = {
                    "event": {
                        "type": "TRANSPORT_CONNECTION",
                        "start_time": frame.get("frame.time_utc", "unknown"),
                    },
                    "network": {
                        "protocol": frame.get("frame.protocols", "unknown"),
                        "src_ip": ip.get("ip.src", "unknown"),
                        "dst_ip": ip.get("ip.dst", "unknown"),
                        "src_port": tcp.get("tcp.srcport", "unknown") if tcp else (udp.get("udp.srcport", "unknown") if udp else "unknown"),
                        "dst_port": tcp.get("tcp.dstport", "unknown") if tcp else (udp.get("udp.dstport", "unknown") if udp else "unknown"),
                    },
                    "source": {
                        "ip": ip.get("ip.src", "unknown"),
                        "mac": eth.get("eth.src", "unknown"),
                    },
                    "destination": {
                        "ip": ip.get("ip.dst", "unknown"),
                        "mac": eth.get("eth.dst", "unknown"),
                    },
                }
                udm_events.append(event)
                logging.info(f"Event added: {event}")
                continue  # Continua alla prossima iterazione
            
            # Aggiungi un evento generico per i pacchetti sconosciuti
            event = {
                "event": {
                    "type": "UNKNOWN_PACKET",
                    "start_time": frame.get("frame.time_utc", "unknown"),
                },
                "raw_data": json.dumps(packet),  # Aggiungi dati grezzi per ulteriori analisi
            }
            udm_events.append(event)
            logging.info(f"Unknown event added: {event}")
        
        except KeyError as e:
            logging.warning(f"Skipping packet due to missing key: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing packet: {e}")

    return udm_events

# Main
if __name__ == "__main__":

    # Controlla numero di argomenti
    if len(sys.argv) != 3:
        print("Usage: python3 json_to_udm_parser.py <input_json_file> <output_udm_file")
        sys.exit(1)

    input_file = sys.argv[1]

    # Controlla se file di input esiste
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    # Legge il file di input
    try:
        with open(input_file, "r") as f:
            wireshark_json = f.read()
    except Exception as e:
        print(f"Error reading file '{input_file}': {e}")
        sys.exit(1)

    # Converte i data JSON
    try:
        udm_events = json_to_udm(wireshark_json)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from file '{input_file}': {e}")
        sys.exit(1)

    # Salva l'output nel file
    if udm_events:
        output_file = sys.argv[2]
        try:
            with open(output_file, "w") as f:
                json.dump(udm_events, f, indent=4)
            print(f"Conversion completed. Output saved to {output_file}.")
        except Exception as e:
            print(f"Error writing to file '{output_file}': {e}")
            sys.exit(1)
    else:
        print(f"No events to write for {input_file}")
