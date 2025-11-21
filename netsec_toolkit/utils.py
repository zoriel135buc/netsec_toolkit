def parse_ports(ports_args):
    ports = []
    for arg in ports_args:
        if "-" in arg:  # טווח
            start, end = map(int, arg.split("-"))
            ports.extend(range(start, end+1))
        else:           # מספר בודד
            ports.append(int(arg))
    return ports