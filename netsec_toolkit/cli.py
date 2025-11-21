import argparse
from netsec_toolkit import arp_scanner,arp_spoofer,syn_scanner,fin_scan,udp_scan
from netsec_toolkit.utils import parse_ports
def main():
    parser=argparse.ArgumentParser(description="choice your tolls from the toolkit")
    parser.add_argument("-t","--tool",choices=["arp-spoof","arp-scan","syn-scan","fin-scan","udp-scan"],required=True,help="Choose which tool to run")
    parser.add_argument("-i","--interface",required=False,help="Network interface to use (e.g. Ethernet, Wi-Fi, eth0, wlan0)")
    parser.add_argument("-n","--network",required=False, help="Subnet in CIDR format (e.g. 192.168.1.0/24)")
    parser.add_argument("-T","--target_ip",required=False,help="target ip to arp spoof")
    parser.add_argument("-S","--spoof_ip",required=False,help="spoof ip")
    parser.add_argument("-P","--ports",nargs="+",type=str,required=False,help="Ports to scan (e.g. -p 22 80 443)"
)
    args=parser.parse_args()


  
    if args.tool == "arp-spoof":
        arp_spoofer.run(target_ip=args.target_ip,spoof_ip=args.spoof_ip,interface=args.interface)

    elif args.tool == "arp-scan":
        arp_scanner.run(interface=args.interface, network=args.network)

    elif args.tool == "udp-scan":
        ports = parse_ports(args.ports)   
        udp_scan.udp_scan(
            target_ip=args.target_ip,
            ports=ports
        )

    elif args.tool == "fin-scan":
        ports = parse_ports(args.ports)
        fin_scan.fin_scn(target_ip=args.target_ip,
            ports=ports)

    elif args.tool == "syn-scan":
        ports = parse_ports(args.ports)   
        syn_scanner.syn_scan(
            target_ip=args.target_ip,
            ports=ports
        )
    else:
        print("Unknown tool selected.")


if __name__ == "__main__":
    main()
