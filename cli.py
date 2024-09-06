import telnetlib
import sys
import time
from prometheus_client import start_http_server, Gauge
import argparse
import numpy as np

label_names = ['ip']
throughput_allowed = Gauge('throughput_allowed', 'Throughput every 15 sec',labelnames=label_names)
throughput_blocked = Gauge('throughput_blocked', 'Throughput every 15 sec',labelnames=label_names)

def send_command(command):
    try:
        # Connect to localhost on port 8080
        tn = telnetlib.Telnet('localhost', 8080)
        
        # Send the command
        tn.write(command.encode('ascii') + b"\n")
        
        # Read the response
        response = tn.read_all().decode('ascii')
        
        # Close the connection
        tn.close()
        
        return response
    except ConnectionRefusedError:
        return "Error: Connection refused. Make sure the server is running."
    except Exception as e:
        return f"Error: {str(e)}"

def monitor_delta_traffic(interval=5):
    start_http_server(8000)
    previous_allowed = {}
    previous_blocked = {}
    while True:
        current_allowed = get_allowed_traffic()
        current_blocked = get_blocked_traffic()
        delta_allowed = {}
        delta_blocked = {}
        
        for ip, count in current_allowed.items():
            delta = count - previous_allowed.get(ip, 0)
            #if delta > 0:
            delta_allowed[ip] = delta / interval
        
        for ip, count in current_blocked.items():
            delta = count - previous_blocked.get(ip, 0)
            #if delta > 0:
            delta_blocked[ip] = delta / interval
        
        if delta_allowed or delta_blocked:
            print(f"\nDelta traffic in the last {interval} seconds :")
            if delta_allowed:
                print("Allowed traffic:")
                sorted_allowed = sorted(delta_allowed.items(), key=lambda x: x[1], reverse=True)
                for ip, delta in sorted_allowed:
                    #print(f"  {ip}: {delta}")
                    throughput_allowed.labels(ip=ip).set(delta)
            if delta_blocked:
                print("Blocked traffic:")
                sorted_blocked = sorted(delta_blocked.items(), key=lambda x: x[1], reverse=True)
                for ip, delta in sorted_blocked:
                    #print(f"  {ip}: {delta}")
                    throughput_blocked.labels(ip=ip).set(delta)
        previous_allowed = current_allowed
        previous_blocked = current_blocked
        time.sleep(interval)

def get_allowed_traffic():
    response = send_command("get_allowed_traffic")
    traffic = {}
    for line in response.split('\n'):
        if ':' in line:
            ip, count = line.split(':', 1)
            ip = ip.strip()
            if ip != 'Traffic':  # Skip the 'Traffic:' line
                try:
                    count = count.strip().split()[0]  # Get the first part (number) of the count
                    traffic[ip] = np.int64(count)  # Use 64-bit integer
                except (ValueError, IndexError):
                    print(f"Warning: Could not parse line: {line}")

    return traffic

def get_blocked_traffic():
    response = send_command("get_blocked_traffic")
    traffic = {}
    for line in response.split('\n'):
        if ':' in line:
            ip, count = line.split(':', 1)
            ip = ip.strip()
            if ip != 'Traffic':  # Skip the 'Traffic:' line
                try:
                    count = count.strip().split()[0]  # Get the first part (number) of the count
                    traffic[ip] = np.int64(count)  # Use 64-bit integer
                except (ValueError, IndexError):
                    print(f"Warning: Could not parse line: {line}")
    return traffic

def monitor_delta_icmp(interval=5):
    previous_icmp = {}
    while True:
        current_icmp = get_icmp_data()
        delta_icmp = {}
        
        for ip, count in current_icmp.items():
            delta = count - previous_icmp.get(ip, 0)
            if delta > 0:
                delta_icmp[ip] = delta / interval
                if delta > 100:
                    print(f"Blacklisting {ip} due to high ICMP traffic (delta: {delta})")
                    send_command(f"blacklist {ip}")
        
        if delta_icmp:
            print(f"Delta ICMP traffic in the last {interval} seconds (only positive changes):")
            # Sort delta_icmp by value (delta) in descending order
            sorted_delta = sorted(delta_icmp.items(), key=lambda x: x[1], reverse=True)
            for ip, delta in sorted_delta:
                print(f"{ip}: {delta}")
        
        previous_icmp = current_icmp
        time.sleep(interval)

def get_icmp_data():
    response = send_command("get_icmp_data")
    icmp_data = {}
    for line in response.split('\n'):
        if ':' in line:
            ip, count = line.split(':', 1)
            ip = ip.strip()
            try:
                # Extract the number before "packets" and convert to int
                count = int(count.strip().split()[0])
                icmp_data[ip] = count
            except (ValueError, IndexError):
                print(f"Warning: Could not parse line: {line}")
    return icmp_data

def main():
    parser = argparse.ArgumentParser(description="Traffic monitoring CLI")
    parser.add_argument("command", help="Command to execute", choices=[
        "monitor_delta_traffic",
        "monitor_delta_icmp",
        "get_allowed_traffic",
        "get_blocked_traffic",
        "get_icmp_data",
        "blacklist",
        "unblacklist",
        "check_blacklist",
        "show_blacklist",
        "clear_blacklist"
    ])
    parser.add_argument("--interval", type=int, default=5, help="Monitoring interval in seconds (default: 15)")
    parser.add_argument("--ip", help="IP address for blacklisting")
    args = parser.parse_args()

    if args.command == "monitor_delta_traffic":
        monitor_delta_traffic(args.interval)
    elif args.command == "monitor_delta_icmp":
        monitor_delta_icmp(args.interval)
    elif args.command == "get_allowed_traffic":
        print(get_allowed_traffic())
    elif args.command == "get_blocked_traffic":
        print(get_blocked_traffic())
    elif args.command == "get_icmp_data":
        print(get_icmp_data())
    elif args.command == "blacklist":
        if not args.ip:
            parser.error("The blacklist command requires an --ip argument")
        response = send_command(f"blacklist {args.ip}")
        print(response)
    elif args.command == "unblacklist":
        if not args.ip:
            parser.error("The unblacklist command requires an --ip argument")
        response = send_command(f"unblacklist {args.ip}")
        print(response)
    elif args.command == "check_blacklist":
        response = send_command("check_blacklist")
        print(response)
    elif args.command == "show_blacklist":
        response = send_command("show_blacklist")
        print(response)
    elif args.command == "clear_blacklist":
        response = send_command("clear_blacklist")
        print(response)
    else:
        response = send_command(args.command)
        print(response)

if __name__ == "__main__":
    main()
