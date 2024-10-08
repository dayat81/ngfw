import telnetlib
import sys
import time
import argparse
import numpy as np

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

def monitor_delta_icmp(interval=5):
    previous_icmp = None
    while True:
        current_icmp = get_icmp_data()
        delta_icmp = {}
        
        if previous_icmp is not None:
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
        else:
            print("First run: Collecting initial ICMP data...")
        
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
        "monitor_delta_icmp",
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

    if args.command == "monitor_delta_icmp":
        monitor_delta_icmp(args.interval)
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
