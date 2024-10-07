import re
from collections import OrderedDict
import subprocess

def get_unique_domains():
    unique_domains = OrderedDict()
    
    try:
        with open('dns_mappings.log', 'r') as log_file:
            for line in log_file:
                # Extract domain name from log entry
                match = re.search(r'\] (.+?),', line)
                if match:
                    domain = match.group(1)
                    unique_domains[domain] = None  # Using OrderedDict to maintain insertion order
    except FileNotFoundError:
        print("Error: dns_mappings.log file not found.")
    except IOError:
        print("Error: Unable to read dns_mappings.log file.")
    
    return list(unique_domains.keys())

# Example usage:
# unique_domains = get_unique_domains()
# print(unique_domains)

def get_ip_addresses_for_domain(domain):
    ip_addresses = []
    
    try:
        with open('dns_mappings.log', 'r') as log_file:
            for line in log_file:
                # Extract domain name and IP address from log entry
                match = re.search(r'\] (.+?),(.+)$', line)
                if match:
                    log_domain = match.group(1)
                    ip = match.group(2).strip()
                    if log_domain == domain:
                        ip_addresses.append(ip)
    except FileNotFoundError:
        print("Error: dns_mappings.log file not found.")
    except IOError:
        print("Error: Unable to read dns_mappings.log file.")
    
    return ip_addresses

# Example usage:
# domain = "example.com"
# ip_list = get_ip_addresses_for_domain(domain)
# print(f"IP addresses for {domain}: {ip_list}")

import sys

def get_ip_addresses_for_domain_containing(substring):
    results = {}
    
    try:
        with open('dns_mappings.log', 'r') as log_file:
            for line in log_file:
                match = re.search(r'\] (.+?),(.+)$', line)
                if match:
                    domain = match.group(1)
                    ip = match.group(2).strip()
                    if substring.lower() in domain.lower():
                        if domain not in results:
                            results[domain] = []
                        results[domain].append(ip)
    except FileNotFoundError:
        print("Error: dns_mappings.log file not found.")
    except IOError:
        print("Error: Unable to read dns_mappings.log file.")
    
    return results

def blacklist_ip_addresses_for_domain(domain):
    ip_addresses = get_ip_addresses_for_domain(domain)
    
    if not ip_addresses:
        print(f"No IP addresses found for domain: {domain}")
        return
    
    for ip in ip_addresses:
        result = subprocess.run(['python3', 'cli.py', 'blacklist', '--ip ', ip], capture_output=True, text=True)
        print(f"Blacklisting {ip}: {result.stdout.strip()}")

def blacklist_domains_containing(substring):
    results = get_ip_addresses_for_domain_containing(substring)
    
    if not results:
        print(f"No domains found containing '{substring}'")
        return
    
    for domain, ip_addresses in results.items():
        print(f"Blacklisting IPs for domain: {domain}")
        for ip in ip_addresses:
            result = subprocess.run(['python3', 'cli.py', 'blacklist', '--ip', ip], capture_output=True, text=True)
            print(f"  Blacklisting {ip}: {result.stdout.strip()}")

def whitelist_ip_addresses_for_domain(domain):
    ip_addresses = get_ip_addresses_for_domain(domain)
    
    if not ip_addresses:
        print(f"No IP addresses found for domain: {domain}")
        return
    
    for ip in ip_addresses:
        add_whitelist_rule_pair(ip)

def add_whitelist_rule_pair(ip):
    acl_rule_path = 'acl_rule'
    rule_pair = [
        f"@0.0.0.0/0\t{ip}/32\t0 : 65535\t0 : 65535 0/0\n",
        f"@{ip}/32\t0.0.0.0/0\t0 : 65535\t0 : 65535 0/0\n"
    ]
    
    try:
        with open(acl_rule_path, 'r+') as acl_file:
            existing_rules = acl_file.readlines()
            new_rules = []
            for rule in rule_pair:
                if rule not in existing_rules:
                    new_rules.append(rule)
            
            if new_rules:
                acl_file.seek(0, 2)  # Move to the end of the file
                acl_file.writelines(new_rules)
                print(f"Whitelisted {ip}: New rule{'s' if len(new_rules) > 1 else ''} added successfully")
            else:
                print(f"Skipped {ip}: Rules already exist")
    except IOError:
        print(f"Error: Unable to read or write to {acl_rule_path} file.")

def whitelist_specific_ip(ip):
    add_whitelist_rule_pair(ip)
    print(f"Whitelisted IP: {ip}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python domain.py <command> [argument]")
        print("Available commands:")
        print("- get_unique_domains")
        print("- get_ip_addresses_for_domain <domain>")
        print("- get_ip_addresses_for_domain_containing <substring>")
        print("- blacklist_domain <domain>")
        print("- blacklist_domains_containing <substring>")
        print("- whitelist_domain <domain>")
        print("- whitelist_ip <ip_address>")
        return

    command = sys.argv[1]

    if command == "get_unique_domains":
        unique_domains = get_unique_domains()
        print("Unique domains:")
        for domain in unique_domains:
            print(domain)
    elif command == "get_ip_addresses_for_domain":
        if len(sys.argv) < 3:
            print("Error: Please provide a domain name.")
            return
        domain = sys.argv[2]
        ip_addresses = get_ip_addresses_for_domain(domain)
        print(f"IP addresses for {domain}:")
        for ip in ip_addresses:
            print(ip)
    elif command == "get_ip_addresses_for_domain_containing":
        if len(sys.argv) < 3:
            print("Error: Please provide a substring to search for in domain names.")
            return
        substring = sys.argv[2]
        results = get_ip_addresses_for_domain_containing(substring)
        if results:
            print(f"IP addresses for domains containing '{substring}':")
            for domain, ips in results.items():
                print(f"{domain}:")
                for ip in ips:
                    print(f"  - {ip}")
        else:
            print(f"No domains found containing '{substring}'")
    elif command == "blacklist_domain":
        if len(sys.argv) < 3:
            print("Error: Please provide a domain name to blacklist.")
            return
        domain = sys.argv[2]
        blacklist_ip_addresses_for_domain(domain)
    elif command == "blacklist_domains_containing":
        if len(sys.argv) < 3:
            print("Error: Please provide a substring to search for in domain names.")
            return
        substring = sys.argv[2]
        blacklist_domains_containing(substring)
    elif command == "whitelist_domain":
        if len(sys.argv) < 3:
            print("Error: Please provide a domain name to whitelist.")
            return
        domain = sys.argv[2]
        whitelist_ip_addresses_for_domain(domain)
    elif command == "whitelist_ip":
        if len(sys.argv) < 3:
            print("Error: Please provide an IP address to whitelist.")
            return
        ip = sys.argv[2]
        whitelist_specific_ip(ip)
    else:
        print(f"Error: Unknown command '{command}'")

if __name__ == "__main__":
    main()


