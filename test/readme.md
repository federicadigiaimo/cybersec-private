# primo test

## primo test

capture1.json       è un file in output da Tshark, usato per fare sniffing in una semplice conversazione tra il mio portatile e fisso tramite netcat

_reale              è il risultato dell'esecuzione

_simulato           è il risultato atteso

lo script            è la prima versione che cerca i file nella cartella in cui si trova


## secondo test

_reale+output       è stato usato lo script nella root, subito dopo la prima introduzione dell'output

## terzo test

capture1.json       tshark -i wlo1 -T json

capture2.json       tshark -i wlo1 -c 100 -T json 

capture3.json       tshark -i wlo1 -c 25 -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -T json

## quarto test

capture_arp.json

capture_dns.json

capture_http.json

capture_http2.json

capture_icmp.json

capture_mdns_udp.json

capture_tls.json

