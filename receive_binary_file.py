from scapy.all import *


# function which receives a binary file from Kali VM
def handler(pkt):
	try:
		f = open("nc", "ab")
		f.write(pkt['Raw'].load)
		f.close()
		if pkt['Raw'].load == b'Finished':
			return True
	except IndexError:
		pass

sniff(stop_filter=handler, filter="icmp")
