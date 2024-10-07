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
    ip_addresses = set()  # Using a set to store unique IP addresses
    
    try:
        with open('dns_mappings.log', 'r') as log_file:
            for line in log_file:
                # Extract domain name and IP address from log entry
                match = re.search(r'\] (.+?),(.+)$', line)
                if match:
                    log_domain = match.group(1)
                    ip = match.group(2).strip()
                    if log_domain == domain:
                        ip_addresses.add(ip)  # Add to set instead of list
    except FileNotFoundError:
        print("Error: dns_mappings.log file not found.")
    except IOError:
        print("Error: Unable to read dns_mappings.log file.")
    
    return list(ip_addresses)  # Convert set back to list before returning

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
                            results[domain] = set()  # Use a set instead of a list
                        results[domain].add(ip)  # Add IP to the set
    except FileNotFoundError:
        print("Error: dns_mappings.log file not found.")
    except IOError:
        print("Error: Unable to read dns_mappings.log file.")
    
    # Convert sets back to lists before returning
    return {domain: list(ips) for domain, ips in results.items()}

def block_ip_addresses_for_domain(domain):
    ip_addresses = get_ip_addresses_for_domain(domain)
    
    if not ip_addresses:
        print(f"No IP addresses found for domain: {domain}")
        return
    
    for ip in ip_addresses:
        add_block_rule_pair(ip)

def add_block_rule_pair(ip):
    acl_rule_path = 'acl_blacklist'
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
                print(f"Blocked {ip}: New rule{'s' if len(new_rules) > 1 else ''} added successfully")
            else:
                print(f"Skipped {ip}: Rules already exist")
    except IOError:
        print(f"Error: Unable to read or write to {acl_rule_path} file.")

def block_specific_ip(ip):
    add_block_rule_pair(ip)
    print(f"Blocked IP: {ip}")

def unblock_ip_addresses_for_domain(domain):
    ip_addresses = get_ip_addresses_for_domain(domain)
    
    if not ip_addresses:
        print(f"No IP addresses found for domain: {domain}")
        return
    
    for ip in ip_addresses:
        add_unblock_rule_pair(ip)

def add_unblock_rule_pair(ip):
    acl_rule_path = 'acl_whitelist'
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
                print(f"Unblocked {ip}: New rule{'s' if len(new_rules) > 1 else ''} added successfully")
            else:
                print(f"Skipped {ip}: Rules already exist")
    except IOError:
        print(f"Error: Unable to read or write to {acl_rule_path} file.")

def unblock_specific_ip(ip):
    add_unblock_rule_pair(ip)
    print(f"Unblocked IP: {ip}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python domain.py <command> [argument]")
        print("Available commands:")
        print("- get_unique_domains")
        print("- get_ip_addresses_for_domain <domain>")
        print("- get_ip_addresses_for_domain_containing <substring>")
        print("- block_domain <domain>")
        print("- block_ip <ip_address>")
        print("- unblock_domain <domain>")
        print("- unblock_ip <ip_address>")
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
    elif command == "block_domain":
        if len(sys.argv) < 3:
            print("Error: Please provide a domain name to block.")
            return
        domain = sys.argv[2]
        block_ip_addresses_for_domain(domain)
    elif command == "block_ip":
        if len(sys.argv) < 3:
            print("Error: Please provide an IP address to block.")
            return
        ip = sys.argv[2]
        block_specific_ip(ip)
    elif command == "unblock_domain":
        if len(sys.argv) < 3:
            print("Error: Please provide a domain name to unblock.")
            return
        domain = sys.argv[2]
        unblock_ip_addresses_for_domain(domain)
    elif command == "unblock_ip":
        if len(sys.argv) < 3:
            print("Error: Please provide an IP address to unblock.")
            return
        ip = sys.argv[2]
        unblock_specific_ip(ip)
    else:
        print(f"Error: Unknown command '{command}'")

if __name__ == "__main__":
    main()


