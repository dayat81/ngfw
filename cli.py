import telnetlib
import sys
import time

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

def monitor_delta_traffic():
    previous_traffic = {}
    while True:
        current_traffic = get_allowed_traffic()
        delta_traffic = {}
        
        for ip, count in current_traffic.items():
            delta = count - previous_traffic.get(ip, 0)
            delta_traffic[ip] = delta
        
        print(f"Delta traffic in the last minute:")
        # Sort delta_traffic by value (delta) in descending order
        sorted_delta = sorted(delta_traffic.items(), key=lambda x: x[1], reverse=True)
        for ip, delta in sorted_delta:
            print(f"{ip}: {delta}")
        
        previous_traffic = current_traffic
        time.sleep(60)

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
                    traffic[ip] = int(count)
                except (ValueError, IndexError):
                    print(f"Warning: Could not parse line: {line}")

    return traffic

def monitor_delta_icmp():
    previous_icmp = {}
    while True:
        current_icmp = get_icmp_data()
        delta_icmp = {}
        
        for ip, count in current_icmp.items():
            delta = count - previous_icmp.get(ip, 0)
            if delta > 0:
                delta_icmp[ip] = delta
                if delta > 100:
                    print(f"Blacklisting {ip} due to high ICMP traffic (delta: {delta})")
                    send_command(f"blacklist {ip}")
        
        if delta_icmp:
            print(f"Delta ICMP traffic in the last 10 seconds (only positive changes):")
            # Sort delta_icmp by value (delta) in descending order
            sorted_delta = sorted(delta_icmp.items(), key=lambda x: x[1], reverse=True)
            for ip, delta in sorted_delta:
                print(f"{ip}: {delta}")
        
        previous_icmp = current_icmp
        time.sleep(10)

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
    if len(sys.argv) < 2:
        print("Usage: python cli.py <command>")
        print("Available commands:")
        print("- get_allowed_traffic")
        print("- get_blocked_traffic")
        print("- blacklist <ip>")
        print("- unblacklist <ip>")
        print("- check_blacklist <ip>")
        print("- show_blacklist")
        print("- clear_blacklist")  # New command
        print("- get_icmp_data")
        print("- monitor_delta_traffic")
        print("- monitor_delta_icmp")  # New command
        return

    command = sys.argv[1]
    if command == "monitor_delta_traffic":
        monitor_delta_traffic()
    elif command == "monitor_delta_icmp":
        monitor_delta_icmp()
    else:
        command = " ".join(sys.argv[1:])
        response = send_command(command)
        print(response)

if __name__ == "__main__":
    main()
