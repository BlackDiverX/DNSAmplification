#!/usr/bin/python
# dnsamplification.py
# Version: 1.0
# License: Apache License Version 2.0
# Author: Georgii Starostin
# E-mail: blackdiverx@gmail.com
# Site: https://BlackDiver.net
from scapy.all import *
import argparse

def dnsscan():
	SPort = random.randint(1025, 65534)
	p=IP(dst=Ip)/UDP(sport=SPort,dport=53)/DNS(rd=1,qd=DNSQR(qname=Query,qtype=Querytype))
	resp=sr(p,timeout=Timeout)
	f = open(Output, 'w')
	for a in resp[0]:
		if a[1].haslayer(DNS):
			AmplRatio = len(a[1])/len(p)
			if AmplRatio >= Aratio:
				f.write(a[1].src+" "+Query+" "+Querytype+" "+str(AmplRatio)+"\n")
				print a[1].src,Query,Querytype,AmplRatio
	f.close()
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-ip", help="IP for scan (Example: 192.168.1.1 or 192.168.1.0/24)")
	parser.add_argument("-query", default=".", help="DNS query (Default: .)")
	parser.add_argument("-querytype", default="A", help="DNS query type (Default: A")
	parser.add_argument("-timeout", type=int, default=10, help="Timeout to wait answers. 0-Infinity (Default: 10sec)")
	parser.add_argument("-aratio", type=int, default=0, help="Amplification ratio (Default: 0)")
	parser.add_argument("-output", help="Output file (Output format: IP DNS_query Query_type Amplification_ratio)")
	args =  parser.parse_args()
	Ip = args.ip
	Query = args.query
	Querytype = args.querytype
	Timeout = args.timeout
	Aratio = args.aratio
	Output = args.output

	if (len(sys.argv) < 2) or (Output == None) or (IP == None):
		print "Parameters missing"
		parser.print_help()
		sys.exit(0)

	try:
		print "Start scanning"
		dnsscan()
	except KeyboardInterrupt:
		print "Stoping scan and Exit"
	print "Scan ended"
