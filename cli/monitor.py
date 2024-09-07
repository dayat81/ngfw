import argparse
import subprocess
import time

from prometheus_client import start_http_server, Gauge
label_names = ['ip']
throughput_allowed = Gauge('throughput_allowed', 'Throughput',labelnames=label_names)
throughput_blocked = Gauge('throughput_blocked', 'Throughput',labelnames=label_names)


def run_counter_cli(traffic_type):
    result = subprocess.run(['./build/counter', traffic_type], capture_output=True, text=True)
    output = result.stdout.strip().split('\n')
    data = {}
    for line in output:
        if line:  # Skip empty lines
            key, value = line.split(', Value: ')
            key = key.split(': ')[1]  # Remove 'Key: ' prefix
            data[key] = int(value)
    return data

def calculate_delta(previous, current):
    delta = {}
    for ip, count in current.items():
        if ip in previous:
            delta[ip] = max(0, count - previous[ip])
        else:
            delta[ip] = count
    return delta

def monitor_traffic(interval):
    start_http_server(8000)
    previous_allowed = None
    previous_blocked = None
    while True:
        current_allowed = run_counter_cli('allowed')
        current_blocked = run_counter_cli('blocked')
        
        if previous_allowed is not None and previous_blocked is not None:
            delta_allowed = calculate_delta(previous_allowed, current_allowed)
            delta_blocked = calculate_delta(previous_blocked, current_blocked)
            
            print("Delta values for allowed traffic:")
            for ip, count in delta_allowed.items():
                #print(f"{ip}: {count}")
                throughput_allowed.labels(ip=ip).set(count/interval)
            
            #print("\nDelta values for blocked traffic:")
            for ip, count in delta_blocked.items():
                #print(f"{ip}: {count}")
                throughput_blocked.labels(ip=ip).set(count/interval)
        else:
            print("Initial data collected. Delta will be available on the next run.")
        
        previous_allowed = current_allowed
        previous_blocked = current_blocked
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor network traffic")
    parser.add_argument("--interval", type=int, default=5, help="Interval between checks in seconds")
    args = parser.parse_args()
    
    monitor_traffic(args.interval)
