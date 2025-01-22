# architettura per automazione del workflow
idealmente basta fare la build e tirare su il compose per avere un docker in cui:
tshark fa sniffing sulla rete, salvando i file nel volume "input", 
e periodicamente lo script python (modificato per lo use-case) li converte in json UDM-compatibile. Il tutto è gestito da uno script bashche funge da entrypoint al container.