import json
import sys
import os

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
            ip = layers.get("ip", {})
            tcp = layers.get("tcp", {})
            udp = layers.get("udp", {})  # Supporto UDP

            event = {
                "event": {
                    "type": "NETWORK_CONNECTION",
                    "start_time": frame.get("frame.time_utc"),
                },
                "network": {
                    "protocol": frame.get("frame.protocols"),
                     "transport": "TCP" if tcp else ("UDP" if udp else None),  # Gestione UDP
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
            print(f"Skipping packet due to missing key: {e}")

    return udm_events

# Main entry point
if __name__ == "__main__":
    # Check for the correct number of arguments
    if len(sys.argv) != 2:
        print("Usage: python3 wireshark_to_udm_parser.py <input_json_file>")
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
        output_file = os.path.splitext(input_file)[0] + ".udm.json"
        try:
            with open(output_file, "w") as f:
                json.dump(udm_events, f, indent=4)
            print(f"Conversion completed. Output saved to {output_file}.")
        except Exception as e:
            print(f"Error writing to file '{output_file}': {e}")
            sys.exit(1)
    else:
        print(f"No events to write for {input_file}")
