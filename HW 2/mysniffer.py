#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime
import argparse
import logging


load_layer("http")
load_layer("tls")


class warnings(logging.Filter):
    def filter(self, record):
        
        return "Unknown" not in record.getMessage()


logger = logging.getLogger('scapy.runtime')
logger.addFilter(warnings())


def getversion(v):
    if v == 769:  
        return "v1.0"
    elif v == 770:
        return "v1.1"
    elif v == 771:
        return "v1.2"
    elif v == 772:
        return "v1.3"
    else:
        return "Unknown"





def packettrace(packet):
	if packet.haslayer(HTTPRequest):
		 httppacket(packet)
	elif packet.haslayer(TLSClientHello):
		 tlspacket(packet)


def httppacket(packet):
	
	method = packet[HTTPRequest].Method.decode()
	if method == 'GET' or method =='POST':
		source_ip = packet[IP].src
		source_port = packet[TCP].sport
		dest_ip = packet[IP].dst
		dest_port = packet[TCP].dport
		hostname = packet[HTTPRequest].Host.decode()
		url = packet[HTTPRequest].Path.decode()
		
		packet_time = Decimal(packet.time)
	


		packet_datetime = datetime.fromtimestamp(int(packet_time)) + timedelta(microseconds=int((packet_time - int(packet_time)) * 10**6))

		print(f"{packet_datetime} HTTP {source_ip}:{source_port} -> {dest_ip}:{dest_port} {hostname} {method} {url}")
	
        

def tlspacket(packet):
	version = getversion(packet[TLSClientHello].version)
	source_ip=packet[IP].src
	dest_ip=packet[IP].dst
	source_port = packet[TCP].sport
	dest_port = packet[TCP].dport
	host_name = None
	packet_time = Decimal(packet.time)
	packet_datetime = datetime.fromtimestamp(int(packet_time)) + timedelta(microseconds=int((packet_time - int(packet_time)) * 10**6))
	if hasattr(packet[TLSClientHello], 'ext'):
		for ext in packet[TLSClientHello].ext:
	       		if isinstance(ext, TLS_Ext_ServerName):
	       			server_name = ext.servernames[0].servername.decode('utf-8')
	       			if len(server_name.split('.')) > 2:
	       				host_name= '.'.join(server_name.split('.')[-2:])
	       			else:
	       				hostname=server_name
	       			break
	print(f"{packet_datetime} TLS {version} {source_ip}:{source_port} -> {dest_ip}:{dest_port} {host_name}")

	 
	
def main():
    parser = argparse.ArgumentParser(description='Sniffer')
    parser.add_argument('-i', '--interface', help='Interface', default=None)
    parser.add_argument('-r', '--tracefile', help='Tracefile', default=None)
    parser.add_argument('filter', nargs='?', help='BPF filter', default='')
    arguments = parser.parse_args()
    
    

    if(arguments.tracefile):
    	
    	print(f"Starting reading from {arguments.tracefile}")
    	sniff(offline=arguments.tracefile,filter=arguments.filter,prn=lambda x:packettrace(x),store=0)
        
    
    else:
    
     print(f"Start capturing")
     sniff(iface=arguments.interface if arguments.interface else conf.iface,
          filter=arguments.filter,
          prn=lambda x:packettrace(x),
          store=0)
    

    
    


if __name__ == "__main__":
    main()
