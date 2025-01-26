import json
import sys
import os
import logging
from datetime import datetime, timezone


MAX_FILE_SIZE_MB = 1

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Convert timestamp to ISO 8601
def convert_timestamp(timestamp_str):
    try:
        dt = datetime.strptime(timestamp_str[:-4], "%b %d, %Y %H:%M:%S.%f")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_timestamp = dt.isoformat() 
        return iso_timestamp
    except Exception as e:
        logging.error(f"Error converting timestamp '{timestamp_str}': {e}")
        return None

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
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})

            # Detect application-level protocol using the protocol_map
            protocol = next((value for key, value in protocol_map.items() if key in layers), None)

            event = {
                "event": {
                    "type": "NETWORK_CONNECTION",
                    "start_time": convert_timestamp(frame.get("frame.time_utc")),
                },
                "network": {
                    "protocol": protocol or frame.get("frame.protocols"),
                    "transport": "TCP" if tcp else ("UDP" if udp else None),
                    "src_ip": ip.get("ip.src"),
                    "dst_ip": ip.get("ip.dst"),
                    "src_port": tcp.get("tcp.srcport") if tcp else (udp.get("udp.srcport") if udp else None),
                    "dst_port": tcp.get("tcp.dstport") if tcp else (udp.get("udp.dstport") if udp else None),
                },
                "source": {
                    "ip": ip.get("ip.src"),
                    "mac": eth.get("eth.src"),
                },
                "destination": {
                    "ip": ip.get("ip.dst"),
                    "mac": eth.get("eth.dst"),
                },
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
