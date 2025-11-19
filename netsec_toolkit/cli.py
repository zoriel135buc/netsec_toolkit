import argparse
from . import arp_scanner,arp_spoofer,syn_scanner

parser=argparse.ArgumentParser(description="choice your tolls from the toolkit")
parser.add_argument("-t","--tool",choices=["arp-spoof","arp-scan","syn-scan"],required=True,help="Choose which tool to run")
parser.add_argument("-i","--interface",required=False,choices=["eth0", "wlan0", "tun0"],help="please pick an interface")
parser.add_argument("-n","--network",required=False, help="please enter a subnet (e.g. 192.168.1.0/24)")
args=parser.parse_args()

def main():
    tool=args.tool
    if tool=="arp-spoof":
        arp_spoofer.run()
    elif tool=="arp-scan":       
        interface=args.interface
        network=args.network
        arp_scanner.run(interface,network)
    else:
        syn_scanner.run()

if __name__ == "__main__":
    main()
