from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_fin_port(target_ip, port, timeout=1):
    packet = IP(dst=target_ip) / TCP(dport=port, flags="F")
    response = sr1(packet, timeout=timeout, verbose=0)

    if response is None:
        return f"Port {port}: OPEN|FILTERED (no response)"
    elif response.haslayer(TCP) and response[TCP].flags == 0x14: 
        return f"Port {port}: CLOSED"
    else:
        return f"Port {port}: Unexpected response"

def fin_scn(target_ip,ports,max_threades=50,timeout=1):
    results=[]
    with ThreadPoolExecutor(max_threades) as executor:
        futures={executor.submit(scan_fin_port,target_ip,port,timeout): port for port in ports} 
        for future in as_completed(futures):
            result=future.result()
            print(result)
            results.append(result)
    print("\n=== FIN Scan Summary ===")
    for r in results:
        print(r)
    return results

