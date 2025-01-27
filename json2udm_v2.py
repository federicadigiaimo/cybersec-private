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
        timestamp_str = timestamp_str[:-9] + timestamp_str[-3:]
        
        if "UTC" in timestamp_str:
            timestamp_str = timestamp_str.replace("UTC", " UTC")

        dt = datetime.strptime(timestamp_str, "%b %d, %Y %H:%M:%S.%f %Z")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_timestamp = dt.isoformat()
        iso_timestamp = iso_timestamp.split('.')[0] + "+00:00"
        return iso_timestamp
    except Exception as e:
        logging.error(f"Error converting timestamp '{timestamp_str}': {e}")
        return None

def print_dns_name(items):
    for query_key, query_value in items:
        mdns_output_name = query_value.get("dns.qry.name")
    return mdns_output_name

def print_dns_type(items):
    for query_key, query_value in items:
        mdns_output_type = query_value.get("dns.qry.type")
    return mdns_output_type

def print_record_version(items):
        return items.get("tls.record.version")

def print_handshake_version(items):
    if "tls.handshake" in items:
        return items["tls.handshake"].get("tls.handshake.version")
    else : return "None"

def print_tls_ciphersuite(items):
    for query_key, query_value in items:
        tls_output_cyphersuite = query_value.get("tls.handshake.ciphersuite")
    return tls_output_cyphersuite

# Function to convert JSON to UDM format
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
    protocol_map = {
        "http": "HTTP",
        "icmp": "ICMP",
        "dns": "DNS",
        "ssl": "TLS/SSL",
        "tls": "TLS/SSL",
    }

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

            # Detect application-level protocol using the protocol_map
            protocol = next((value for key, value in protocol_map.items() if key in layers), None)

            event = {
                "event": {
                    "type": "NETWORK_CONNECTION",
                    "vendor_name": "Wireshark",
                    "product_name": "Wireshark PacketCapture",
                    "event_timestamp": convert_timestamp(frame.get("frame.time_utc")) if frame.get("frame.time_utc") else None,
                },
                "network": {
                    #"application_protocol" ?
                    "transport_protocol": "TCP" if tcp else ("UDP" if udp else ("ICMP" if icmp else None)),
                    "ip": {
                        "source": ip.get("ip.src") ,
                        "destination": ip.get("ip.dst"),
                        "ttl": ip.get("ip.ttl") if ip.get("ip.ttl") else None,
                    },
                    "ipv6": {
                        "source": ipv6.get("ipv6.src") ,
                        "destination": ipv6.get("ipv6.dst"),
                        "ttl": ipv6.get("ipv6.ttl") if ipv6.get("ipv6.ttl") else None,
                    },
                    "eth": {
                        "source_mac": eth.get("eth.src"),
                        "destination_mac": eth.get("eth.dst"),
                    },
                    "udp": {
                        "source_port": udp.get("udp.srcport") if udp else None,
                        "destination_port": udp.get("udp.dstport") if udp else None,
                    },
                    "tcp": {
                        "source_port": tcp.get("tcp.srcport") if tcp else None,
                        "destination_port": tcp.get("tcp.dstport") if tcp else None,
                        "flags": tcp.get("tcp.flags") if tcp.get("tcp.flags") else None,
                    },
                    "icmp": {
                        "type": icmp.get("icmp.type") if icmp else None,
                        "code": icmp.get("icmp.code") if icmp else None,
                    },
                    "dns": {
                        "query": {
                            "name": print_dns_name(dns["Queries"].items()) if "Queries" in dns else None,
                            "type": print_dns_type(dns["Queries"].items()) if "Queries" in dns else None,
                        },
                         "response": {
                            "addresses": dns.get("dns.resp.addr") if dns else None,
                        },
                    },
                    "mdns": {
                        "query": {
                            "name": print_dns_name(mdns["Queries"].items()) if "Queries" in mdns else None,
                            "type": print_dns_type(mdns["Queries"].items()) if "Queries" in mdns else None,
                        },
                         "response": {
                            "addresses": mdns.get("dns.resp.addr") if mdns else None,
                        },
                    },
                    "http": {
                        "host": http.get("http.host") if http else None,
                        "request_uri": http.get("http.request.uri") if http else None,
                    },
                    "tls": {
                        "version":  print_record_version(tls["tls.record"]) if tls and "tls.record" in tls else None, 
                        "handshake": {
                        "version": print_handshake_version(tls["tls.record"]) if tls and "tls.record" in tls else None,
                        }
                    }
                },
                "frame": {
                    "timestamp": convert_timestamp(frame.get("frame.time_utc")) if frame.get("frame.time_utc") else None,
                    "length": frame.get("frame.len") if frame.get("frame.len") else None,
                    "protocols": frame.get("frame.protocols"),
                }
            }

            udm_events.append(event)
        
        except KeyError as e:
            logging.warning(f"Skipping packet due to missing key: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing packet: {e}")

    return udm_events

# Function to write events to multiple files if size exceeds 1 MB
def write_to_multiple_files(events, base_output_file):
    max_size_bytes = MAX_FILE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
    current_file_index = 1
    current_events = []
    current_size = 0

    for event in events:
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
