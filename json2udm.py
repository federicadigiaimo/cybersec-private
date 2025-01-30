import json
import sys
import os
import logging
from datetime import datetime, timezone

MAX_FILE_SIZE_MB = 1

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Convert timestamp to RFC 3339
def convert_timestamp(timestamp_str):
    try:
        dt = datetime.strptime(timestamp_str[:25], "%b %d, %Y %H:%M:%S.%f")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_timestamp = dt.isoformat()
        return iso_timestamp
    
    except Exception as e:
        logging.error(f"Error converting timestamp '{timestamp_str}': {e}")
        return None

def print_dns(items,key):
    results = []
    for k, v in items:
        if isinstance(v, dict):
            result = v.get(key)
            if result is not None:
                results.append(result)
    return results if results else None

def print_record_version(items):
    return items.get("tls.record.version")

def get_all_ciphersuites(tls):
    ciphersuites = []

    if "tls.handshake" in tls:
        ciphersuites_data = tls["tls.handshake"].get("tls.handshake.ciphersuites", {})

        # Controlla se ciphersuites_data è un dizionario
        if isinstance(ciphersuites_data, dict):
            # Prova a ottenere tutti i valori dei ciphersuites
            for key in ciphersuites_data.keys():
                print(ciphersuites_data[key])
                ciphersuites.append(ciphersuites_data[key])  # Aggiunge l'ultimo valore per ciascuna chiave

    return ciphersuites


def print_handshake(items, item):
    if "tls.handshake" in items:
        value = items["tls.handshake"].get(item)
        return value
    return None

# Function to convert JSON to UDM format
def json_to_udm(input_json):
    try:
        packets = json.loads(input_json)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON: {e}")
        return []

    udm_events = []

    for packet in packets:
        try:
            layers = packet["_source"]["layers"]

            # Extract relevant fields
            frame = layers.get("frame", {})
            eth = layers.get("eth", {})
            ip = layers.get("ip", {})
            ipv6 = layers.get("ipv6", {})
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            icmp = layers.get("icmp", {})
            dns = layers.get("dns", {})
            mdns = layers.get("mdns", {})
            http = layers.get("http", {})
            tls = layers.get("tls", {})
            arp = layers.get("arp",{})
#           data = layers.get("data",{}) da approfondire data.len e frame.len

            event = {
                "event": {
                    "type": "NETWORK_CONNECTION",
                    "vendor_name": "Wireshark",
                    "product_name": "Wireshark PacketCapture",
                    **({"event_timestamp": convert_timestamp(frame.get("frame.time_utc"))} if frame.get("frame.time_utc") else {}),
                },
                "network": {
                    **({"transport_protocol": "TCP" if tcp else "UDP"} if tcp or udp else {}),

                    **({"ip": {
                        **({"source": ip.get("ip.src")} if ip.get("ip.src") else {}),
                        **({"destination": ip.get("ip.dst")} if ip.get("ip.dst") else {}),
                        **({"ttl": ip.get("ip.ttl")} if ip.get("ip.ttl") else {}),
                    }} if ip else {}),
                    
                    **({"ipv6": {
                        **({"source": ipv6.get("ipv6.src")} if ipv6.get("ipv6.src") else {}),
                        **({"destination": ipv6.get("ipv6.dst")} if ipv6.get("ipv6.dst") else {}),
                    }} if ipv6 else {}),
                    
                    **({"eth": {
                        **({"source_mac": eth.get("eth.src")} if eth.get("eth.src") else {}),
                        **({ "destination_mac": eth.get("eth.dst")} if eth.get("eth.dst") else {}),
                    }} if eth else {}),
                    
                    **({"udp": {
                        **({"source_port": udp.get("udp.srcport")} if udp.get("udp.srcport") else {}),
                        **({"destination_port": udp.get("udp.dstport")} if udp.get("udp.dstport") else {}),
                    }} if udp else {}),
                    
                    **({"tcp": {
                         **({"source_port": tcp.get("tcp.srcport")} if tcp.get("tcp.srcport") else {}),
                        **({"destination_port": tcp.get("tcp.dstport")} if tcp.get("tcp.dstport") else {}),
                        **({"flags": tcp.get("tcp.flags")} if tcp.get("tcp.flags") else {}),
                    }} if tcp else {}),
                    
                    **({"icmp": {
                         **({"type": icmp.get("icmp.type")} if icmp.get("icmp.type") else {}),
                         **({"code": icmp.get("icmp.code")} if icmp.get("icmp.code") else {}),
                    }} if icmp else {}),
                    
                    **({"dns": {
                        **({"query": {
                            **({"name": print_dns(dns["Queries"].items(), "dns.qry.name")}
                                if "Queries" in dns and print_dns(dns["Queries"].items(), "dns.qry.name") is not None else {}),
                            **({"ttl": print_dns(dns["Answers"].items(), "dns.resp.ttl")}
                                if "Answers" in dns and print_dns(dns["Answers"].items(), "dns.resp.ttl") is not None else {}),
                            **({"flags_response": print_dns(dns["dns.flags_tree"].items(), "dns.flags.response")}
                                if "dns.flags_tree" in dns and print_dns(dns["dns.flags_tree"].items(), "dns.flags.response") is not None else {}),
                            **({"type": print_dns(dns["Queries"].items(), "dns.qry.type")}
                                if "Queries" in dns and print_dns(dns["Queries"].items(), "dns.qry.type") is not None else {}),
                        }} if any(key in dns for key in ["Queries", "Answers", "dns.flags_tree"]) else {}),
                    }} if dns else {}),

                    
                    **({"mdns": {
                        **({"query": {
                            **({"name": print_dns(mdns["Queries"].items(), "dns.qry.name")}
                                if "Queries" in mdns and print_dns(mdns["Queries"].items(), "dns.qry.name") is not None else {}),
                            **({"ttl": print_dns(mdns["Answers"].items(), "dns.resp.ttl")}
                                if "Answers" in mdns and print_dns(mdns["Answers"].items(), "dns.resp.ttl") is not None else {}),
                            **({"type": print_dns(mdns["Queries"].items(), "dns.qry.type")}
                                if "Queries" in mdns and print_dns(mdns["Queries"].items(), "dns.qry.type") is not None else {}),
                        }} if any(key in mdns for key in ["Queries", "Answers"]) else {}),
                    }} if mdns else {}),
                    
                    **({"http": {
                        **({"host": http.get("http.host")} if http.get("http.host") else {}),
                        **({"file_data": http.get("http.file_data")} if http.get("file_data") else {}),
#                        **({"method": http.get("http.request.method")} if http.get("http.request.method") else {}),
#                        **({"uri": http.get("http.request.uri")} if http.get("http.request.uri") else {}),
                    }} if http else {}),
                    
                    "tls": {
                        **({"record_version": print_record_version(tls["tls.record"])}
                            if "tls.record" in tls and print_record_version(tls["tls.record"]) is not None else {}),
    
                        **({"handshake": {
                            **({"version": print_handshake(tls["tls.record"], "tls.handshake.version")}
                                if "tls.record" in tls and print_handshake(tls["tls.record"], "tls.handshake.version") is not None else {}),
    
                            **({"ciphersuites": get_all_ciphersuites(tls["tls.record"])}
                                if tls else {}),
                        }} if "tls.handshake" in tls["tls.record"] else {}),
                    } if tls else {},
                    
                    **({"arp": {
                         **({"source_mac": arp.get("arp.src.hw_mac")} 
                            if arp.get("arp.src.hw_mac") else {}),
                         **({"source_ipv4":  arp.get("arp.src.proto_ipv4")} 
                            if arp.get("arp.src.proto_ipv4") else {}),
                         **({"destination_mac": arp.get("arp.dst.hw_mac")} 
                            if arp.get("arp.dst.hw_mac") else {}),
                         **({"destination_ipv4": arp.get("arp.dst.proto_ipv4")} 
                            if arp.get("arp.dst.proto_ipv4") else {}),
                    }} if arp else {}),
                    
                    **({"frame": {
                        **({"timestamp": convert_timestamp(frame.get("frame.time_utc"))} if frame.get("frame.time_utc") else {}),
                        **({"length": frame.get("frame.len")} if frame.get("frame.len") else {}),
                        **({"protocols": frame.get("frame.protocols")} if frame.get("frame.protocols") else {}),
                    }} if frame else {}),
                }
            }
            udm_events.append(event)
        
        except KeyError as e:
            logging.warning(f"Skipping packet due to missing key: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing packet: {e}")

    return udm_events

# Function to write events to multiple files if size exceeds 1 MB
def write_to_multiple_files(udm_events, base_output_file):
    max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
    current_file_index = 1
    current_events = []
    current_size = 0

    for event in udm_events:
        try:
            # Serialize the event and calculate its size
            event_json = json.dumps(event, indent=4)
            event_size = len(event_json.encode("utf-8"))  # Size in bytes

            # Check if adding this event exceeds the size limit
            if current_size + event_size > max_size_bytes:
                # Write the current file
                output_file = f"{base_output_file}_{current_file_index}.json"
                with open(output_file, "w") as f:
                    json.dump(current_events, f, indent=4)
                logging.info(f"Saved {len(current_events)} events to {output_file}.")
                # Start a new file
                current_file_index += 1
                current_events = []
                current_size = 0

            # Add the event to the current file's list
            current_events.append(event)
            current_size += event_size

        except IOError as e:
            logging.error(f"Error writing to file: {e}")
            continue
        except Exception as e:
            logging.error(f"Unexpected error while processing event: {e}")
            continue

    # Write the last file if there are remaining events
    if current_events:
        try:
            output_file = f"{base_output_file}_{current_file_index}.json"
            with open(output_file, "w") as f:
                json.dump(current_events, f, indent=4)
            logging.info(f"Saved {len(current_events)} events to {output_file}.")
        except IOError as e:
            logging.error(f"Error writing the final file: {e}")

# Main entry point
if __name__ == "__main__":
    # Check for the correct number of arguments
    if len(sys.argv) != 3:
        logging.error("Usage: python3 json_to_udm_parser.py <input_json_file> <name_output_udm_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Validate that the input file exists
    if not os.path.isfile(input_file):
        logging.error(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    # Read the input file
    try:
        with open(input_file, "r") as f:
            wireshark_json = f.read()
    except Exception as e:
        logging.error(f"Error reading file '{input_file}': {e}")
        sys.exit(1)

    # Convert the JSON data
    try:
        udm_events = json_to_udm(wireshark_json)
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from file '{input_file}': {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error during conversion: {e}")
        sys.exit(1)

    # Save the output to a file
    if udm_events:
        write_to_multiple_files(udm_events, output_file)
    else:
        logging.warning(f"No events to write for {input_file}")