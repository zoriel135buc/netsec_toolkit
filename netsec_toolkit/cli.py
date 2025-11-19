import argparse
from . import arp_scanner,arp_spoofer,syn_scanner

parser=argparse.ArgumentParser(description="choice your tolls from the toolkit")
parser.add_argument("-t","--tool",choices=["arp-spoof","arp-scan","syn-scan"],required=True,help="Choose which tool to run")

args=parser.parse_args()

def main():
    tool=args.tool
    if tool=="arp-spoof":
        arp_spoofer.run()
    elif tool=="arp-scan":
        arp_scanner.run()
    else:
        syn_scanner.run()

if __name__ == "__main__":
    main()
