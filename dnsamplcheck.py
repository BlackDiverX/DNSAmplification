#!/usr/bin/python
# dnsamplcheck.py
# Version: 1.0
# License: Apache License Version 2.0
# Author: Georgii Starostin
# E-mail: blackdiverx@gmail.com
# Site: https://BlackDiver.net
from scapy.all import *
import argparse

def readservers(DataFile):
	with open(DataFile) as ServersFile:
		serverlist = [row.strip() for row in ServersFile]
	return serverlist

def main(slist):
	i = 0
	f = open(Output, 'w')
	for element in slist:
		SPort = random.randint(1025, 65534)
		print SPort
		param = slist[i].split()
		p=IP(dst=param[0])/UDP(sport=SPort,dport=53)/DNS(rd=1,qd=DNSQR(qname=param[1],qtype=param[2]))
#		r = sr(p,inter=0,timeout=5,verbose=0,count=100)
		resp=sr(p,timeout=Timeout,verbose=0)
		for a in resp[0]:
			if a[1].haslayer(DNS):
				AmplRatio = len(a[1])/len(p)
				if AmplRatio >= int(param[3]):
					print a[1].src,"good"
					f.write(param[0]+" "+param[1]+" "+param[2]+" "+param[3]+"\n")
		i+=1
	f.close()
	
if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-input", help="Input file with servers list (Input format: IP DNS_query Query_type Amplification_ratio)")
	parser.add_argument("-timeout", type=int, default=2, help="Timeout to wait answers. 0-Infinity (Default: 2sec)")
	parser.add_argument("-output", help="Output file (Output format: IP DNS_query Query_type Amplification_ratio)")
	args = parser.parse_args()
	Input = args.input
	Timeout = args.timeout
	Output = args.output
	if (len(sys.argv) < 2) or (Output == None) or (IP == None):
		print "Parameters missing"
		parser.print_help()
		sys.exit(0)
	try:
		print "Start checking"
		main(readservers(Input))
	except KeyboardInterrupt:
		print "Stoping check and Exit"
	print "Check ended"
