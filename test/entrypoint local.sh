#!/bin/bash

## VERSIONE SENZA DOCKER
CARTELLA="/home/fillo/Scrivania/test-parser"

INTERFACE="-i enp3s0"
LIMITS="${LIMITS:-"-c 20000"}"
ROTATE="${ROTATE:-"-b filesize:10240"}"

INPUT_DIR="$CARTELLA/app/input"      # qui vengono messe le catture
TRASH_DIR="$CARTELLA/app/trash"      # una volta tradotti in json, i pcap vanno qui
MID_DIR="$CARTELLA/app/jsonized"     # i json pronti per parsing UDM
OUTPUT_DIR="$CARTELLA/app/output"    # file pronti per chronicle

process_file() {
    local FILE="$(basename "$1" .pcap).json"
    
    if tshark -r "$1" -T json > "$MID_DIR/$FILE"; then
        mv "$1" "$TRASH_DIR/"
    else
        echo "Errore nella conversione del file $1"
        return 1
    fi
  
    #if python3 $CARTELLA/app/json2udm.py "$MID_DIR/$FILE" "$OUTPUT_DIR/$FILE"; then
        echo "Processing successful, removing file: $MID_DIR/$FILE"
    #    rm "$MID_DIR/$FILE"
    #else
    #    echo "Error processing file: $MID_DIR/$FILE. Keeping the original file."
    #fi
}
cd $CARTELLA

for DIR in "$INPUT_DIR" "$TRASH_DIR" "$MID_DIR" "$OUTPUT_DIR"; do
  if [ ! -d "$DIR" ]; then
    echo "Directory $DIR non trovata. Creazione..."
    mkdir -p "$DIR"
  fi
done

trap 'echo "Terminating tshark due to script exit"; kill $TSHARK_PID' EXIT

echo "Starting tshark..."
tshark $INTERFACE $ROTATE $LIMITS -w $INPUT_DIR/capture.pcap &
TSHARK_PID=$!

echo "Starting tshark on interface $INTERFACE with args: $ROTATE $LIMITS"

inotifywait -m -e close_write --format "%w%f" "$INPUT_DIR" | while read -r NEW_FILE; do
  echo "File completato: $NEW_FILE"
  sleep 1
  process_file "$NEW_FILE"
done

wait $TSHARK_PID
