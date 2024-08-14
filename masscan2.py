import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Hàm để quét cổng của một IP
def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            return True
    return False

# Hàm để quét dải IP từ file và cổng 3389
def scan_ip_range_from_file(file_path, port, max_workers):
    with open(file_path, 'r') as file:
        ip_range = [line.strip() for line in file]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(scan_port, ip, port): ip for ip in ip_range}
        start_time = time.time()
        scanned_ips = 0
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            if future.result():
                save_good_ip(ip, port)
            scanned_ips += 1
            elapsed_time = time.time() - start_time
            estimated_total_time = (elapsed_time / scanned_ips) * len(ip_range)
            estimated_remaining_time = estimated_total_time - elapsed_time
            print(f"Scanned {scanned_ips} IPs. Estimated remaining time: {estimated_remaining_time:.2f} seconds.")

# Hàm lưu IP vào file good_ips.txt
def save_good_ip(ip, port):
    with open(f"good_ips.txt", "a") as good_file:
        good_file.write(ip + f":{port}" + "\n")
    print(f"Open port {port} found on IP {ip}. Added to good_ips_{port}.txt")

# Chuyển đổi dải IP CIDR thành danh sách các IP và lưu vào file
def generate_ip_list_from_cidr(cidr, file_path):
    network = ipaddress.ip_network(cidr)
    with open(file_path, 'w') as file:
        for ip in network.hosts():
            file.write(str(ip) + '\n')

# Hàm để quét nhiều dải IP từ một tệp
def scan_multiple_ip_ranges(file_path, port, max_workers):
    with open(file_path, 'r') as file:
        ip_ranges = [line.strip() for line in file]

    for cidr in ip_ranges:
        ip_list_file = "temp_ip_list.txt"
        generate_ip_list_from_cidr(cidr, ip_list_file)
        scan_ip_range_from_file(ip_list_file, port, max_workers)

# Ví dụ sử dụng
if __name__ == "__main__":
    ip_ranges_file = "ip_ranges.txt"  # Tệp chứa danh sách các dải IP CIDR
    port = 3389
    max_workers = 1000  # Số lượng luồng tối đa

    # Quét cổng 3389 cho từng dải IP trong tệp
    scan_multiple_ip_ranges(ip_ranges_file, port, max_workers)
    