import argparse
import os
from scapy.all import *
import sys
from collections import deque
import datetime
import netifaces


packet_q= deque(maxlen=10)

def dns_detect(pkt):
	if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
		for op in packet_q:
			if op[IP].payload!=pkt[IP].payload and\
			op[DNS].id==pkt[DNS].id and op[DNS].qd.qname==pkt[DNS].qd.qname and\
			op[IP].dport==pkt[IP].dport and op[DNSRR].rdata!=pkt[DNSRR].rdata and\
			op[IP].dst==pkt[IP].dst and op[IP].sport==pkt[IP].sport:
				list_old=[]
				list_new=[]
				for i in range(op[DNS].ancount):
					if op[DNS].an[i].type==1:
						list_old.append(op[DNS].an[i].rdata)
				for i in range(pkt[DNS].ancount):
					if pkt[DNS].an[i].type==1:
						list_new.append(pkt[DNS].an[i].rdata)
				if len(list_old)!=0 and len(list_new)!=0:
					print(datetime.datetime.fromtimestamp(int(pkt.time)).strftime('%Y-%m-%d %H:%M:%S') + " DNS poisoning attempt")
					print "TXID 0x%x Request %s"%( op[DNS].id, op[DNS].qd.qname.rstrip('.'))
					print "Answer1: ", list_old
					print "Answer2: ", list_new , "\n"
		packet_q.append(pkt)


if __name__== '__main__':
	parser= argparse.ArgumentParser(add_help=False, description="DNS Spoofed Packet Detection")
	parser.add_argument("-i")
	parser.add_argument("-r")
	parser.add_argument('expression', nargs='*', action='store')
	args= parser.parse_args()
	interface=args.i
	file_name=args.r
	expression=args.expression
	final_expression=''
	try:
		if file_name and interface:
			print "Can not sniff both interface and file"
			sys.exit()

		if expression:
			print expression
			for i in expression:
				final_expression=final_expression+i+' '
	        	final_expression=final_expression[0:-1]
	        	print "BPF Filter: " +final_expresssion

		if interface:
			print "Detecting on: "+ interface
	    		sniff(iface=interface, filter=final_expression,store=0, prn=dns_detect)

        	elif file_name:
			print "Reading from tracefile: "+file_name
			#print "Sniffing from the tracefile"
			sniff(filter=final_expression, offline = file_name, store=0, prn=dns_detect)
	
		elif not interface and not file_name:			
			interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
			print "Sniffing from default interface: "+ interface
			sniff(iface=interface, filter=final_expression, store=0, prn=dns_detect)


	except AttributeError:
		print "Invalid entry/entries"
		print "dnsdetect [-i interface] [-r tracefile] expression"
