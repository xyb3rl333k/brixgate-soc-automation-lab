#!/usr/bin/env python3
"""
ICMP Traffic Capture and Analysis Script
=========================================
Captures ICMP traffic on Kali Linux using tshark, analyzes for potential threats,
and sends alerts to Aria AI agent via API.

Requirements:
    - tshark (Wireshark command-line tool)
    - Python 3.7+
    - Root privileges (sudo)

Usage:
    sudo python3 icmp_capture.py
"""

import subprocess
import csv
import json
import time
import os
import sys
import threading
from datetime import datetime, timedelta
from collections import defaultdict
import requests

# =============================================================================
# CONFIGURATION
# =============================================================================

# Network Interface
INTERFACE = "eth0"

# Capture Settings
CAPTURE_DURATION = 60          # seconds
ANALYSIS_WINDOW = 60 * 60      # 60 minutes in seconds
ALERT_THRESHOLD = 30           # packets threshold for alert

# File Paths
PCAP_FILE = "/tmp/icmp_capture.pcap"
CSV_FILE = "/tmp/icmp_capture.csv"

# Aria AI API Configuration
# Replace with your actual API URL and key
ARIA_API_URL = "https://api.airia.ai/v2/PipelineExecution/cd6e159c-b3bb-4e7d-b80c-0892aac7716c"
ARIA_API_KEY = "ak-MTI2MjcyNzI4NXwxNzc2NzgxNTY3Nzg1fHRpLVJXdDBaV05vTFU5d1pXNGdVbVZuYVhOMGNtRjBhVzl1TFVGcGNtbGhJRVp5WldVPXwxfDE2NzA1ODI4MzAg"

# =============================================================================
# GLOBAL VARIABLES
# =============================================================================

packet_count = 0
start_time = None
stop_capture = False


def check_tshark_installed():
    """Check if tshark is installed and available."""
    try:
        result = subprocess.run(
            ["tshark", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print("[+] tshark is installed")
            return True
        else:
            print("[-] tshark is not properly installed")
            return False
    except FileNotFoundError:
        print("[-] tshark not found. Install with: sudo apt-get install tshark")
        return False
    except Exception as e:
        print(f"[-] Error checking tshark: {e}")
        return False


def check_root_privileges():
    """Check if running with root privileges."""
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo)")
        return False
    print("[+] Running with root privileges")
    return True


def capture_icmp_traffic():
    """
    Capture ICMP packets from eth0 interface using tshark.
    Saves to .pcap file with source and destination IPs.
    """
    global packet_count, start_time, stop_capture
    
    print(f"\n[*] Starting ICMP capture on interface {INTERFACE}")
    print(f"[*] Capture duration: {CAPTURE_DURATION} seconds")
    print(f"[*] Output file: {PCAP_FILE}")
    print("-" * 60)
    
    # Remove existing pcap file if it exists
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)
    
    start_time = time.time()
    
    # tshark command to capture ICMP packets
    # -i: interface
    # -f: BPF filter for ICMP only
    # -w: output file
    # -F: output format (pcap)
    tshark_cmd = [
        "tshark",
        "-i", INTERFACE,
        "-f", "icmp",
        "-w", PCAP_FILE,
        "-F", "pcap"
    ]
    
    try:
        # Start tshark capture process
        process = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Monitor capture in real-time
        while not stop_capture:
            elapsed = int(time.time() - start_time)
            remaining = CAPTURE_DURATION - elapsed
            
            # Try to get packet count from tshark (if available)
            # Note: This is a simplified approach - real implementation
            # might use dumpcap or other methods for accurate counts
            
            if remaining >= 0:
                # Display timer and packet count
                print(f"\r[+] Timer: {elapsed}s / {CAPTURE_DURATION}s | Packets captured: {packet_count}", 
                      end="", flush=True)
            
            if elapsed >= CAPTURE_DURATION:
                stop_capture = True
                break
            
            time.sleep(1)
        
        # Stop the capture process
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        
        elapsed = int(time.time() - start_time)
        print(f"\n\n[+] Capture completed! Duration: {elapsed}s")
        print(f"[+] Total packets captured: {packet_count}")
        
        return True
        
    except Exception as e:
        print(f"\n[-] Error during capture: {e}")
        return False


def convert_pcap_to_csv():
    """
    Convert the .pcap capture data to a CSV file.
    Extracts source IP, destination IP, and other relevant fields.
    """
    print(f"\n[*] Converting {PCAP_FILE} to {CSV_FILE}")
    
    # tshark command to read pcap and output CSV
    tshark_cmd = [
        "tshark",
        "-r", PCAP_FILE,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "icmp.type",
        "-e", "icmp.code",
        "-e", "frame.len",
        "-E", "header=y",
        "-E", "separator=,"
    ]
    
    try:
        result = subprocess.run(
            tshark_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"[-] Error converting pcap: {result.stderr}")
            return False
        
        # Write CSV file
        with open(CSV_FILE, 'w') as f:
            f.write(result.stdout)
        
        print(f"[+] CSV file created: {CSV_FILE}")
        return True
        
    except Exception as e:
        print(f"[-] Error during conversion: {e}")
        return False


def analyze_traffic():
    """
    Analyze the captured traffic.
    Count packets per source host within the analysis window.
    Generate JSON alert if threshold is exceeded.
    """
    print(f"\n[*] Analyzing traffic from {CSV_FILE}")
    print(f"[*] Analysis window: {ANALYSIS_WINDOW // 60} minutes")
    print(f"[*] Alert threshold: >= {ALERT_THRESHOLD} packets")
    
    # Dictionary to count packets per source IP
    source_packet_counts = defaultdict(int)
    packet_rows = []
    capture_start_time = None
    
    try:
        with open(CSV_FILE, 'r') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    timestamp = float(row.get('frame.time_epoch', 0))
                    src_ip = row.get('ip.src', '')
                    dst_ip = row.get('ip.dst', '')
                    icmp_type = row.get('icmp.type', '')
                    icmp_code = row.get('icmp.code', '')
                    frame_len = row.get('frame.len', '')
                    
                    if not src_ip or src_ip == '':
                        continue
                    
                    # Set capture start time
                    if capture_start_time is None or timestamp < capture_start_time:
                        capture_start_time = timestamp
                    
                    # Save packet row for JSON payload
                    packet_rows.append({
                        "frame.time_epoch": timestamp,
                        "ip.src": src_ip,
                        "ip.dst": dst_ip,
                        "icmp.type": icmp_type,
                        "icmp.code": icmp_code,
                        "frame.len": frame_len
                    })
                    
                    # Count packets per source IP
                    source_packet_counts[src_ip] += 1
                    
                except (ValueError, KeyError) as e:
                    # Skip malformed rows
                    continue
        
        # Display analysis results
        print("\n" + "=" * 60)
        print("PACKET COUNT BY SOURCE HOST")
        print("=" * 60)
        
        alerts = []
        current_time = time.time()
        
        for src_ip, count in sorted(source_packet_counts.items(), 
                                     key=lambda x: x[1], reverse=True):
            status = ""
            if count >= ALERT_THRESHOLD:
                status = " [!ALERT!]"
                alerts.append({
                    "source_ip": src_ip,
                    "packet_count": count,
                    "timestamp": datetime.now().isoformat(),
                    "severity": "HIGH" if count >= ALERT_THRESHOLD * 2 else "MEDIUM"
                })
            
            print(f"  {src_ip:20s} -> {count:5d} packets{status}")
        
        print("=" * 60)
        
        # Generate JSON alert if threshold exceeded
        if alerts:
            alert_data = {
                "alert_type": "ICMP_TRAFFIC_THRESHOLD",
                "capture_duration": CAPTURE_DURATION,
                "analysis_window_minutes": ANALYSIS_WINDOW // 60,
                "threshold": ALERT_THRESHOLD,
                "triggered_alerts": alerts,
                "total_unique_sources": len(source_packet_counts),
                "total_packets": sum(source_packet_counts.values()),
                "generated_at": datetime.now().isoformat(),
                "packets": packet_rows
            }
            
            # Save alert to JSON file
            alert_file = "/tmp/icmp_alert.json"
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f, indent=2)
            
            print(f"\n[+] Alert data saved to: {alert_file}")
            return alert_data
        else:
            print("\n[+] No alerts generated (threshold not exceeded)")
            return None
        
    except Exception as e:
        print(f"[-] Error during analysis: {e}")
        return None


def send_alert_to_aria_api(alert_data):
    """
    Send the alert data to Aria AI agent via API.
    Print the agent's response.
    """
    if not alert_data:
        print("\n[*] No alert data to send to Aria AI")
        return None
    
    print(f"\n[*] Sending alert to Aria AI agent...")
    print(f"[*] API URL: {ARIA_API_URL}")
    
    # Prepare headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ARIA_API_KEY}"
    }
    
    # Prepare text payload and required UserInput field for Aria AI
    summary_text = (
        "ICMP traffic alert: source hosts exceeded threshold. "
        f"Total unique sources: {alert_data['total_unique_sources']}, "
        f"total packets: {alert_data['total_packets']}, "
        f"threshold: {alert_data['threshold']} packets. "
        "Please analyze and respond with mitigation suggestions."
    )
    request_body = {
        "alert": alert_data,
        "action": "analyze_icmp_threat"
    }
    payload = {
        "request": json.dumps(request_body),
        "UserInput": summary_text
    }
    
    try:
        # Send POST request to Aria AI API
        response = requests.post(
            ARIA_API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        
        # Check response status
        if response.status_code == 200:
            print("[+] Successfully sent alert to Aria AI")
            print("\n" + "=" * 60)
            print("ARIA AI AGENT RESPONSE")
            print("=" * 60)
            
            try:
                agent_response = response.json()
                print(json.dumps(agent_response, indent=2))
            except json.JSONDecodeError:
                print(response.text)
            
            print("=" * 60)
            return agent_response
        else:
            print(f"[-] API request failed with status code: {response.status_code}")
            print(f"[-] Response: {response.text}")
            return None
            
    except requests.exceptions.Timeout:
        print("[-] API request timed out")
        return None
    except requests.exceptions.ConnectionError:
        print("[-] Failed to connect to Aria AI API")
        print("[-] Please check your API URL and network connection")
        return None
    except Exception as e:
        print(f"[-] Error sending alert to API: {e}")
        return None


def update_packet_count():
    """
    Background thread to update packet count periodically.
    Uses tshark to count packets in the pcap file.
    """
    global packet_count
    
    while not stop_capture:
        time.sleep(2)  # Update every 2 seconds
        try:
            # Use tshark to count packets in pcap
            count_cmd = [
                "tshark",
                "-r", PCAP_FILE,
                "-Y", "icmp",
                "-T", "fields",
                "-e", "frame.number"
            ]
            result = subprocess.run(
                count_cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                packet_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        except:
            pass


def main():
    """Main function to orchestrate the ICMP capture and analysis."""
    print("=" * 60)
    print("ICMP TRAFFIC CAPTURE AND ANALYSIS TOOL")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Step 1: Check prerequisites
    print("\n[*] Checking prerequisites...")
    
    if not check_root_privileges():
        sys.exit(1)
    
    if not check_tshark_installed():
        sys.exit(1)
    
    # Step 2: Start packet count update thread
    print("\n[*] Starting packet count monitor...")
    count_thread = threading.Thread(target=update_packet_count, daemon=True)
    count_thread.start()
    
    # Step 3: Capture ICMP traffic
    if not capture_icmp_traffic():
        print("[-] Capture failed")
        sys.exit(1)
    
    # Step 4: Convert pcap to CSV
    if not os.path.exists(PCAP_FILE):
        print("[-] PCAP file not found")
        sys.exit(1)
    
    if not convert_pcap_to_csv():
        print("[-] Conversion failed")
        sys.exit(1)
    
    # Step 5: Analyze traffic
    alert_data = analyze_traffic()
    
    # Step 6: Send alert to Aria AI
    if alert_data:
        response = send_alert_to_aria_api(alert_data)
        if response:
            print("\n[+] Alert successfully processed by Aria AI")
        else:
            print("\n[-] Failed to send alert to Aria AI")
    else:
        print("\n[*] No alerts to send")
    
    print("\n" + "=" * 60)
    print("CAPTURE AND ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


if __name__ == "__main__":
    main()