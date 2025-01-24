import json

def wireshark_to_udm(input_json):
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

            event = {
                "event": {
                    "type": "NETWORK_CONNECTION",
                    "start_time": frame.get("frame.time_utc"),
                },
                "network": {
                    "protocol": frame.get("frame.protocols"),
                    "transport": "TCP" if tcp else None,
                    "src_ip": ip.get("ip.src"),
                    "dst_ip": ip.get("ip.dst"),
                    "src_port": tcp.get("tcp.srcport"),
                    "dst_port": tcp.get("tcp.dstport"),
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

# Example usage
if __name__ == "__main__":
    with open("capture1.json", "r") as f:
        wireshark_json = f.read()

    udm_events = wireshark_to_udm(wireshark_json)

    with open("udm_output.json", "w") as f:
        json.dump(udm_events, f, indent=4)

    print("Conversion completed. Output saved to udm_output.json.")
