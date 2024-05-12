#!/usr/bin/env python3
import re
import argparse
from scapy.all import *
from scapy.layers.l2 import getmacbyip

def loadcache():
	cache = {}
	print("ARP Cache Initial State:")
	with open('/proc/net/arp', 'r') as f:
		
		for row in f.readlines()[1:]:
			col=re.split(r'\s+', row.strip())
			ip1,mac1=col[0],col[3]
			print(f"{ip1}->{mac1}")
			cache[ip1]=mac1
	return cache


def monitorchange(packet, cache):
	if packet[ARP].op == 2 or packet[ARP].op == 1:
		
		ip=packet[ARP].psrc
		mac=packet[ARP].hwsrc
		
		if ip in cache.keys():
			if mac!=cache[ip]:
			
		    		print(f"{ip} changed from {cache[ip]} to {mac}")
		    		#cache[ip]=mac
		    

def main():
    	parser=argparse.ArgumentParser(description='Arpwatcher')
    	parser.add_argument('-i', '--interface', help='Interface', default=None)
    	arguments=parser.parse_args()
    	cache=loadcache()
    	
    	
    	print("Looking For ARPSPOOF")
    	
	
    	sniff(iface=arguments.interface if arguments.interface else conf.iface, filter="arp", prn=lambda x : monitorchange(x, cache), store=0)
	    
	    
	
	
if __name__ == "__main__":
    main()	
	
	
		
	
	
