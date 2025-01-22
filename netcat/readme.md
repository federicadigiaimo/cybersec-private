# comando per sniffare JSON con filtro su porta

sudo tshark -i enp3s0 -f "tcp port 12345" -T json > capture.json

gli screeshot mostrano le due parti di una conversazione su netcat