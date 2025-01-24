import json
import sys
import os
import logging

#funzione
def json_to_udm(input_json):
    """
    Convert Tshark JSON export to Google Chronicle JSON-UDM format.

    Args:
        input_json (str): JSON string from Tshark output.

    Returns:
        list: List of dictionaries in JSON-UDM format.
    """
    packets = json.loads(input_json)
    udm_events = []

    for packet in packets:
        try:
            layers = packet["_source"]["layers"]

            # Extract relevant fields
            frame = layers.get("frame", {})
            eth = layers.get("eth", {})
            ip = layers.get("ip", {}) or layers.get("ipv6")
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})
            
            # Determine event type
            event_type = "NETWORK_CONNECTION"
            if "dns" in layers:
                event_type = "DNS_REQUEST"
            elif "http" in layers:
                event_type = "HTTP_REQUEST"

            event = {
                "event": {
                    "type": event_type,
                    "start_time": frame.get("frame.time_utc","unknown"),
                },
                "network": {
                    "protocol": frame.get("frame.protocols"),
                     "transport": "TCP" if tcp else ("UDP" if udp else "unknown"),  # UDP support
                    "src_ip": ip.get("ip.src") or ip.get("ipv6.src", "unknown"),
                    "dst_ip": ip.get("ip.dst") or ip.get("ipv6.dst", "unknown"),
                    "src_port": tcp.get("tcp.srcport") if tcp else (udp.get("udp.srcport") if udp else "unknown"),
                    "dst_port": tcp.get("tcp.dstport") if tcp else (udp.get("udp.dstport") if udp else "unknown"),
                },
                "source": {
                    "ip": ip.get("ip.src") or ip.get("ipv6.src", "unknown"),
                    "mac": eth.get("eth.src","unknown"),
                },
                "destination": {
                    "ip": ip.get("ip.dst") or ip.get("ipv6.dst", "unknown"),
                    "mac": eth.get("eth.dst","unknown"),
                },
            }

            udm_events.append(event)
            
        except KeyError as e:
            logging.warning(f"Skipping packet due to missing key: {e}")
        except Exception as e:
            logging.error(f"Unexpected error processing packet: {e}")

    return udm_events

# Main entry point
if __name__ == "__main__":

    # Check for the correct number of arguments
    if len(sys.argv) != 3:
        print("Usage: python3 json_to_udm_parser.py <input_json_file> <output_udm_file")
        sys.exit(1)

    input_file = sys.argv[1]

    # Validate that the input file exists
    if not os.path.isfile(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    # Read the input file
    try:
        with open(input_file, "r") as f:
            wireshark_json = f.read()
    except Exception as e:
        print(f"Error reading file '{input_file}': {e}")
        sys.exit(1)

    # Convert the JSON data
    try:
        udm_events = json_to_udm(wireshark_json)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from file '{input_file}': {e}")
        sys.exit(1)

    # Save the output to a file
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
