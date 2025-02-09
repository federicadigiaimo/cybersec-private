#!/bin/bash

# Script executed at container startup, handles both sniffing and post-processing

# Network interface (eth0 should be fine, standard for the container)
INTERFACE="-i eth0"

# Possible limits (for testing), enough to show the "write_to_multiple_files()" function
LIMITS="${LIMITS:-"-c 20000"}"

# Default rotation rules
ROTATE="${ROTATE:-"-b filesize:10240"}"

# Paths and volumes
INPUT_DIR="/app/input"      # captures are placed here
TRASH_DIR="/app/trash"      # once translated to JSON, pcaps go here
MID_DIR="/app/jsonized"     # JSONs ready for UDM parsing
OUTPUT_DIR="/app/output"    # files ready for chronicle

# Function to process a file
process_file() {
    # Get the relative path of the file and add the .json extension
    local FILE="$(basename "$1" .pcap).json"

    # Step 1: pcap -> json (move the file to trash if successful)
    if tshark -r "$1" -T json > "$MID_DIR/$FILE"; then
        mv "$1" "$TRASH_DIR/"
    else
        echo "Error converting file $1"
        return 1
    fi

    # Step 2: json -> UDM (remove input file if successful)
    if python3 /app/json2udm.py "$MID_DIR/$FILE" "$OUTPUT_DIR/$FILE"; then
        echo "Processing successful, removing file: $MID_DIR/$FILE"
        rm "$MID_DIR/$FILE"
    else
        echo "Error processing file: $MID_DIR/$FILE. Keeping the original file."
    fi

    # Step 3 (optional): sending results to Google Chronicle
#    if python3 /app/ingestion_comm.py "$OUTPUT_DIR/$FILE"; then
#        echo "Results successfully sent to Google Chronicle"
#    fi
}

# Function to recover and process pending files
recover_pending_files() {
    echo "Recovering pending files before starting new sniffing session..."
    
    # Step 1: Process all pcap files in INPUT_DIR
    for PENDING in "$INPUT_DIR"/*.pcap; do
        [ -e "$PENDING" ] && tshark -r "$PENDING" -T json > "$MID_DIR/$(basename "$PENDING" .pcap).json" && mv "$PENDING" "$TRASH_DIR/"
    done
    
    # Step 2: Process all json files in MID_DIR
    for PENDING in "$MID_DIR"/*.json; do
        if [ -e "$PENDING" ]; then
            python3 /app/json2udm.py "$PENDING" "$OUTPUT_DIR/$(basename "$PENDING")" && rm "$PENDING"
            
            # Step 3 (optional): sending results to Google Chronicle
#            python3 /app/ingestion_comm.py "$OUTPUT_DIR/$(basename "$PENDING")" && echo "Results successfully sent to Google Chronicle"
        fi
    done
}

# Check if directories exist
for DIR in "$INPUT_DIR" "$TRASH_DIR" "$MID_DIR" "$OUTPUT_DIR"; do
  if [ ! -d "$DIR" ]; then
    echo "Directory $DIR not found. Creating..."
    mkdir -p "$DIR"
  fi
done

# Check for remaining files from a previous execution that still need to be processed.
if ls "$INPUT_DIR"/*.pcap "$MID_DIR"/*.json 2> /dev/null | grep -q .; then
    recover_pending_files
fi

# Loop until an active interface is found
while true; do
    # Iterate over network interfaces
    for iface_path in /sys/class/net/*; do
        iface=$(basename "$iface_path")

        # Skip unwanted interfaces
        case "$iface" in
            lo|docker*|br-*|tun*|veth*|wg*) continue ;;
        esac

        # Check if 'operstate' is "up"
        if [[ -f "$iface_path/operstate" && $(< "$iface_path/operstate") == "up" ]]; then
            INTERFACE="-i $iface"
            echo "Active network interface found: $iface"
            break 2
        fi
    done

    echo "No active interface found. Retrying in 5 seconds..."
    sleep 5
done

# Handle error in case of premature tshark termination
trap 'echo "Terminating tshark due to script exit"; kill $TSHARK_PID' EXIT

# Start tshark in the background
echo "Starting tshark..."
tshark $INTERFACE $ROTATE $LIMITS -w $INPUT_DIR/capture.pcap &
TSHARK_PID=$!

# Log confirmation
echo "Starting tshark on interface $INTERFACE with args: $ROTATE $LIMITS"

# Monitor new files completed for writing
inotifywait -m -e close_write --format "%w%f" "$INPUT_DIR" | while read -r NEW_FILE; do
  echo "File completed: $NEW_FILE"
  # Small delay to ensure file is fully written
  sleep 1
  process_file "$NEW_FILE"
done

# Handles tshark termination (if necessary)
wait $TSHARK_PID