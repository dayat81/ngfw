import telnetlib
import sys

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
        return

    command = " ".join(sys.argv[1:])
    response = send_command(command)
    print(response)

if __name__ == "__main__":
    main()
