#!/usr/bin/env python3
import os
import platform
import subprocess
import psutil
import json
import http.server
import socketserver
import webbrowser

def get_system_info():
    return {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.architecture()[0],
        "Hostname": platform.node()
    }

def check_installed_software():
    try:
        if platform.system() == "Windows":
            cmd = "wmic product get name,version"
        else:
            cmd = "dpkg -l"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        return result.stdout.strip().split("\n")
    except Exception as e:
        return [f"Error retrieving installed software: {str(e)}"]

def check_running_processes():
    try:
        processes = [
            f"PID: {p.info['pid']}, Name: {p.info['name']}, User: {p.info['username']}"
            for p in psutil.process_iter(['pid', 'name', 'username'])
        ]
        return processes
    except Exception as e:
        return [f"Error retrieving processes: {str(e)}"]

def check_firewall_status():
    try:
        if platform.system() == "Windows":
            cmd = "netsh advfirewall show allprofiles state"
        else:
            cmd = "sudo ufw status | grep Status"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error checking firewall status: {str(e)}"

def get_disk_usage():
    usage = psutil.disk_usage('/')
    return {
        "total": usage.total // (1024**3),
        "used": usage.used // (1024**3),
        "free": usage.free // (1024**3),
        "percent": usage.percent
    }

def get_memory_usage():
    memory = psutil.virtual_memory()
    return {
        "total": memory.total // (1024**3),
        "used": memory.used // (1024**3),
        "available": memory.available // (1024**3),
        "percent": memory.percent
    }

def get_cpu_usage():
    return psutil.cpu_percent(interval=1)

def get_open_ports():
    ports = []
    try:
        result = subprocess.run(["ss", "-tuln"], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        for line in lines:
            if "LISTEN" in line:
                parts = line.split()
                if len(parts) >= 5:
                    addr = parts[4]
                    if ":" in addr:
                        port = addr.split(":")[-1]
                        service = get_service_name(port)
                        ports.append(f"{port} ({service})")
    except Exception:
        ports.append("Error getting open ports.")
    return ports

def get_service_name(port):
    try:
        cmd = f"sudo netstat -tuln | grep :{port} | awk '{{print $1}}'"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

def save_report_to_json(system_info, installed_software, running_processes, firewall_status, disk_usage, memory_usage, cpu_usage, open_ports):
    report_data = {
        "System Information": system_info,
        "Installed Software": installed_software,
        "Running Processes": running_processes,
        "Firewall Status": firewall_status,
        "Disk Usage": disk_usage,
        "Memory Usage": memory_usage,
        "CPU Usage": cpu_usage,
        "Open Ports": open_ports
    }

    os.makedirs("reports", exist_ok=True)
    with open("reports/audit_report.json", "w") as file:
        json.dump(report_data, file, indent=4)
    
    print("Audit report saved to reports/audit_report.json")

def start_web_server(port=5000):
    os.chdir("reports")

    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        webbrowser.open(f"http://localhost:{port}")
        print(f"Serving report at: http://localhost:{port}")
        httpd.serve_forever()

def run_audit_script():
    print("\n*** Starting System Audit ***\n")

    system_info = get_system_info()
    installed_software = check_installed_software()
    running_processes = check_running_processes()
    firewall_status = check_firewall_status()
    disk_usage = get_disk_usage()
    memory_usage = get_memory_usage()
    cpu_usage = get_cpu_usage()
    open_ports = get_open_ports()

    print("\n--- SYSTEM INFO ---")
    for key, value in system_info.items():
        print(f"{key}: {value}")

    print("\n--- FIREWALL STATUS ---")
    print(firewall_status)

    print("\n--- DISK USAGE ---")
    print(f"Total Space: {disk_usage['total']} GB")
    print(f"Used Space: {disk_usage['used']} GB")
    print(f"Free Space: {disk_usage['free']} GB")
    print(f"Usage Percent: {disk_usage['percent']}%")

    print("\n--- MEMORY USAGE ---")
    print(f"Total Memory: {memory_usage['total']} GB")
    print(f"Used Memory: {memory_usage['used']} GB")
    print(f"Available Memory: {memory_usage['available']} GB")
    print(f"Usage Percent: {memory_usage['percent']}%")

    print("\n--- CPU USAGE ---")
    print(f"CPU Usage: {cpu_usage}%")

    print("\n--- OPEN PORTS ---")
    for port in open_ports:
        print(f"Open Port: {port}")

    save_report_to_json(system_info, installed_software, running_processes, firewall_status, disk_usage, memory_usage, cpu_usage, open_ports)

    start_web_server()

if __name__ == "__main__":
    run_audit_script()
