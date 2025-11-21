from scapy.all import IP,UDP,sr1,ICMP
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_udp_port(target_ip,port,timeout=2):
    packet=IP(dst=target_ip)/ UDP(dport=port)
    response=sr1(packet,timeout=timeout,verbose=0)

    if response is None:
        return f"Port {port}: OPEN|FILTERED (no response)"
    elif response.haslayer(UDP):
        return f"Port {port}: OPEN (UDP response)"
    elif response.haslayer(ICMP):
        icmp_type=response[ICMP].type
        icmp_code=response[ICMP].code
        if icmp_type == 3 and icmp_code == 3:
             return f"Port {port}: CLOS ED (ICMP Port Unreachable)"
        else:
            return f"Port {port}: FILTERED (ICMP type={icmp_type}, code={icmp_code})"
    else:
        return f"Port {port}: Unknown response"

def udp_scan(target_ip, ports, max_threads=50, timeout=2):
    results = []
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(scan_udp_port, target_ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            result = future.result()
            print(f"Port {port}: {result}")
            results.append((port, result))

    print("\n=== UDP Scan Summary ===")
    for port, status in results:
        print(f"{port}: {status}")
    return results



