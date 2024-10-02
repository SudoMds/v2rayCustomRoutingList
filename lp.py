import asyncio
import websockets
import ssl
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Function to check WebSocket connection with a timeout and retry
async def check_websocket(ip, url, timeout=5):
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with websockets.connect(
            f"wss://{ip}:443", extra_headers={'Host': url}, ssl=ssl_context, timeout=timeout
        ):
            print(f"{Fore.GREEN}[DEBUG] Working WebSocket at {ip}{Style.RESET_ALL}")
            return ip
    except (asyncio.TimeoutError, websockets.exceptions.InvalidHandshake, websockets.exceptions.InvalidStatusCode) as e:
        print(f"{Fore.RED}[DEBUG] WebSocket error at {ip}: {e}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[DEBUG] General error at {ip}: {e}{Style.RESET_ALL}")
        return None

# Run asynchronous task
def run_check(ip, url):
    return asyncio.run(check_websocket(ip, url))

# Function to create a list of IP addresses from a range
def generate_ip_range(start_ip, end_ip):
    try:
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
    except ipaddress.AddressValueError as e:
        print(f"{Fore.RED}[ERROR] Invalid IP address range: {e}{Style.RESET_ALL}")
        return []

# Main function for multithreaded scanning
def scan_ip_range(start_ip, end_ip, url, max_workers=50):
    ip_list = generate_ip_range(start_ip, end_ip)
    if not ip_list:
        return []  # Exit if IP range is invalid

    working_websockets = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(run_check, ip, url): ip for ip in ip_list}
        for future in future_to_ip:
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result:
                    working_websockets.append(result)
            except Exception as exc:
                print(f'{Fore.RED}[DEBUG] IP {ip} caused an exception: {exc}{Style.RESET_ALL}')

    return working_websockets

if __name__ == "__main__":
    print(f"{Fore.CYAN}Enter the start and end IP addresses for scanning, as well as the URL to check the WebSocket.{Style.RESET_ALL}")
    start_ip = input("Enter the start IP address: ")
    end_ip = input("Enter the end IP address: ")
    url = input("Enter the domain you specified in Fastly (without https://): ")

    if not start_ip or not end_ip or not url:
        print(f"{Fore.RED}[ERROR] Please provide valid inputs for IP range and URL.{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Starting to scan the IP address range from {start_ip} to {end_ip} for working WebSocket connections...{Style.RESET_ALL}")
        working_websockets = scan_ip_range(start_ip, end_ip, url)

        if working_websockets:
            with open('working_websockets.txt', 'w') as file:
                for ip in working_websockets:
                    file.write(f"{ip}\n")
            print(f"{Fore.CYAN}Working WebSocket connections saved to 'working_websockets.txt'{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No working WebSocket connections found.{Style.RESET_ALL}")
