import subprocess
import time

def run_counter_cli(traffic_type):
    result = subprocess.run(['./counter_cli', traffic_type], capture_output=True, text=True)
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
            delta[ip] = count - previous[ip]
        else:
            delta[ip] = count
    return delta

def monitor_traffic():
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
                print(f"{ip}: {count}")
            
            print("\nDelta values for blocked traffic:")
            for ip, count in delta_blocked.items():
                print(f"{ip}: {count}")
        else:
            print("Initial data collected. Delta will be available on the next run.")
        
        previous_allowed = current_allowed
        previous_blocked = current_blocked
        time.sleep(5)

if __name__ == "__main__":
    monitor_traffic()
