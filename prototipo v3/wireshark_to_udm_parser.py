import json
import sys
import os

def wireshark_to_udm(input_file):
    try:
        with open(input_file, 'r') as f:
            packets = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error reading or decoding JSON from {input_file}: {e}")
        return []  # Restituisci una lista vuota in caso di errore

    udm_events = []

    for packet in packets:
        try:
            layers = packet["_source"]["layers"]
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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 wireshark_to_udm_parser.py <input_json_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    udm_events = wireshark_to_udm(input_file)
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
