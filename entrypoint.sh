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

    # Step 2: json -> UDM (move the file to output if successful)
    if python3 /app/json2udm.py "$MID_DIR/$FILE" "$OUTPUT_DIR/$FILE"; then
        echo "Processing successful, removing file: $MID_DIR/$FILE"
        rm "$MID_DIR/$FILE"
    else
        echo "Error processing file: $MID_DIR/$FILE. Keeping the original file."
    fi
}

# Check if directories exist
for DIR in "$INPUT_DIR" "$TRASH_DIR" "$MID_DIR" "$OUTPUT_DIR"; do
  if [ ! -d "$DIR" ]; then
    echo "Directory $DIR not found. Creating..."
    mkdir -p "$DIR"
  fi
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