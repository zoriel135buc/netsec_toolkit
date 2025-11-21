from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_port(target_ip, port, timeout=1):
    packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=0)

    if response is None:
        return None
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12: 
            return port
        elif response[TCP].flags == 0x14: 
            return None
        else:
            return None
    else:
        return None

def syn_scan(target_ip, ports, max_threads=50, timeout=1):
    open_ports = []
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(scan_port, target_ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            result = future.result()
            if result:
                print(f"Port {port}: OPEN")
                open_ports.append(port)
            else:
                print(f"Port {port}: CLOSED or no response")

    print("\n=== Scan Summary ===")
    if open_ports:
        print(f"Open ports: {open_ports}")
    else:
        print("No open ports found.")
    return open_ports