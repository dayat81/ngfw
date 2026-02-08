import requests
import sys
import time
import argparse
import json

BASE_URL = "http://localhost:8000/api"

def send_command(endpoint, method="GET", data=None):
    try:
        url = f"{BASE_URL}/{endpoint}"
        if method == "GET":
            response = requests.get(url)
        elif method == "POST":
            response = requests.post(url, json=data)
        else:
            return f"Error: Unsupported method {method}"
        
        if response.status_code == 200:
            try:
                return response.json()
            except json.JSONDecodeError:
                return response.text
        else:
            return f"Error: {response.status_code} - {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Error: Connection refused. Make sure the server is running on port 8000. Details: {str(e)}"

def monitor_delta_icmp(interval=5):
    previous_icmp = None
    while True:
        current_icmp = get_icmp_data()
        if isinstance(current_icmp, str) and current_icmp.startswith("Error"):
             print(current_icmp)
             time.sleep(interval)
             continue

        delta_icmp = {}
        
        # Convert list of dicts to dict id:packets
        current_map = {entry['ip']: entry['packets'] for entry in current_icmp}

        if previous_icmp is not None:
            for ip, count in current_map.items():
                prev_count = previous_icmp.get(ip, 0)
                delta = count - prev_count
                if delta > 0:
                    delta_icmp[ip] = delta / interval
                    if delta > 100:
                        print(f"Blacklisting {ip} due to high ICMP traffic (delta: {delta})")
                        print(send_command("blacklist", "POST", {"ip": ip}))
            
            if delta_icmp:
                print(f"Delta ICMP traffic in the last {interval} seconds (only positive changes):")
                # Sort delta_icmp by value (delta) in descending order
                sorted_delta = sorted(delta_icmp.items(), key=lambda x: x[1], reverse=True)
                for ip, delta in sorted_delta:
                    print(f"{ip}: {delta}")
        else:
            print("First run: Collecting initial ICMP data...")
        
        previous_icmp = current_map
        time.sleep(interval)

def get_icmp_data():
    return send_command("icmp_data")

def main():
    parser = argparse.ArgumentParser(description="Traffic monitoring CLI")
    parser.add_argument("command", help="Command to execute", choices=[
        "monitor_delta_icmp",
        "get_icmp_data",
        "blacklist",
        "whitelist", # Changed unblacklist to whitelist
        "check_blacklist",
        "stats"
    ])
    parser.add_argument("--interval", type=int, default=5, help="Monitoring interval in seconds (default: 5)")
    parser.add_argument("--ip", help="IP address for blacklisting/whitelisting")
    args = parser.parse_args()

    if args.command == "monitor_delta_icmp":
        monitor_delta_icmp(args.interval)
    elif args.command == "get_icmp_data":
        print(json.dumps(get_icmp_data(), indent=2))
    elif args.command == "blacklist":
        if not args.ip:
            parser.error("The blacklist command requires an --ip argument")
        response = send_command("blacklist", "POST", {"ip": args.ip})
        print(response)
    elif args.command == "whitelist":
        if not args.ip:
            parser.error("The whitelist command requires an --ip argument")
        response = send_command("whitelist", "POST", {"ip": args.ip})
        print(response)
    elif args.command == "check_blacklist":
        response = send_command("blacklist")
        print(response)
    elif args.command == "stats":
        response = send_command("stats")
        print(response)
    else:
        print(f"Unknown command: {args.command}")

if __name__ == "__main__":
    main()
