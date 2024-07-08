from scapy.all import sniff
import threading
import time
import subprocess
from collections import defaultdict
import requests

connection_log = defaultdict(list)
blocked_ips = set()
lock = threading.Lock()
CONNECTION_THRESHOLD = 100
TIME_WINDOW = 30
SHORT_WINDOW_THRESHOLD = 20
SHORT_WINDOW = 5
LOG_WINDOW = 5
SERVER_IP = ""
SERVER_NAME = ""
last_log_time = defaultdict(lambda: 0)
ALERT_SLACK = False

def alert_slack(message=""):
    if not ALERT_SLACK:
      return

    webhook = "<slack webhook url>"
    payload = {
        "text": f"<!channel> {message}",
    }
    req = requests.post(webhook, json=payload)

def monitor_connections():
    sniff(filter="tcp port 8091", prn=log_connection)

def log_connection(packet):
    ip = packet[1].src
    current_time = time.time()
    if ip == SERVER_IP or ip in blocked_ips:
        return
    with lock:
        if current_time - last_log_time[ip] > LOG_WINDOW:
            print(f"Connection from {ip} at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")
            last_log_time[ip] = current_time
        connection_log[ip].append(current_time)
        clean_old_connections(ip)
        if check_spam(ip):
            print(f"DETECTED SPAMMING from {ip}")
            deny_ip(ip)
            connection_log[ip] = []

            try:
                alert_slack(f"{SERVER_IP} [{SERVER_NAME}] - DETECTED SPAMMING from {ip}")
            except Exception as e:
                print(f"Error alert to slack: {e}")

        elif len(connection_log[ip]) >= CONNECTION_THRESHOLD:
            print(f"DETECTED DDOS from {ip}")
            deny_ip(ip)
            connection_log[ip] = []

            try:
                alert_slack(f"{SERVER_IP} [{SERVER_NAME}] - DETECTED DDOS from {ip}")
            except Exception as e:
                print(f"Error alert to slack: {e}")

def clean_old_connections(ip):
    current_time = time.time()
    connection_log[ip] = [t for t in connection_log[ip] if current_time - t <= TIME_WINDOW]

def check_spam(ip):
    current_time = time.time()
    short_window_connections = [t for t in connection_log[ip] if current_time - t <= SHORT_WINDOW]
    return len(short_window_connections) >= SHORT_WINDOW_THRESHOLD

def deny_ip(ip):
    ufw_command = f"sudo ufw insert 1 deny from {ip}"
    iptables_command = f"sudo iptables -I INPUT -s {ip} -j DROP"
    try:
        result = subprocess.run(ufw_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"IP {ip} has been denied access by UFW. Output: {result.stdout.decode()}")
        blocked_ips.add(ip)  # Add IP to blocked list
    except subprocess.CalledProcessError as e:
        print(f"Error denying IP {ip} with UFW: {e.stderr.decode()}")

    try:
        result = subprocess.run(iptables_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"IP {ip} has been denied access by iptables. Output: {result.stdout.decode()}")
        blocked_ips.add(ip)  # Add IP to blocked list
    except subprocess.CalledProcessError as e:
        print(f"Error denying IP {ip} with iptables: {e.stderr.decode()}")

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitor_connections)
    monitor_thread.start()
    monitor_thread.join()
