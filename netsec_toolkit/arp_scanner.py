import ipaddress
from scapy.all import Ether, ARP, srp, get_if_list, get_if_hwaddr
from concurrent.futures import ThreadPoolExecutor, as_completed
from tabulate import tabulate



RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def auto_select_interface():
    candidates=[iface for iface in get_if_list() if "VMware" not in iface and "Bluetooth" not in iface]
    for iface in candidates:
        try:
            mac=get_if_hwaddr(iface)
            if mac and mac != "00:00:00:00:00:00":
                return iface
        except:
            continue
    return None

def scan_ip(ip, interface):
    packet=Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(ip))
    answered,_=srp(packet, iface=interface,timeout=1,verbose=0)
    for _, received in answered:
        return (received.psrc,received.hwsrc)
    return None

def run(interface=None, network=None):
    if not network:
        print(f"{RED}Missing or network (use -n){RESET}")
        return
    if not interface:
        interface=auto_select_interface()
        if not interface:
            print(f"{RED}No suitable interface found!{RESET}")
            return
        print(f"{GREEN}[+] Auto-selected interface: {interface}{RESET}")
    
    print(f"{GREEN}[+] Running ARP scan on {network} via {interface}{RESET}")

    try:
        net=ipaddress.ip_network(network,strict=False)
    except ValueError:
        print(f"{RED}Invalid network format. Use something like 192.168.1.0/24")
        return
    
    found_hosts=[]

    print("[*] Sending ARP requests in parallel...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures=[executor.submit(scan_ip,ip,interface) for ip in net.hosts()]
        for futures in as_completed(futures):
            result=futures.result()
            if result:
                found_hosts.append(result)
    print("\n=== Scan Results ===")    
    if found_hosts:
        print(tabulate(found_hosts,headers=["IP Address", "MAC Address"],tablefmt="grid"))
        with open("arp_results.txt","w") as f:
            for ip ,mac in found_hosts:
                f.write(f"{ip}\t{mac}\n")
        print(f"{GREEN} results saved tp arp_results.txt {RESET}")
    else:
        print(f"{RED}no hosts found{RESET}")
    print("====================\n")




