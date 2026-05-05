#!/usr/bin/env python3
"""
Simple Honeypot for Ubuntu
Monitors specified ports and logs connection attempts
"""

import socket
import threading
import logging
import datetime
import argparse
import os
import sys
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class Honeypot:
    def __init__(self, ports, bind_ip='0.0.0.0'):
        self.bind_ip = bind_ip
        self.ports = ports
        self.servers = []
        self.running = True
        
        # Create directory for detailed logs
        self.log_dir = '/var/log/honeypot'
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
    
    def start_listener(self, port):
        """Start a listener on the specified port"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.bind_ip, port))
            server.listen(5)
            
            logging.info(f"[*] Listening on {self.bind_ip}:{port}")
            
            self.servers.append(server)
            
            while self.running:
                try:
                    client, addr = server.accept()
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client, addr, port)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting connection: {e}")
                    break
                    
        except Exception as e:
            logging.error(f"Could not start listener on port {port}: {e}")
    
    def handle_client(self, client_socket, address, port):
        """Handle client connection and log details"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        client_ip = address[0]
        client_port = address[1]
        
        logging.info(f"[+] Connection from {client_ip}:{client_port} to port {port}")
        
        # Create detailed log file for this connection
        log_file = f"{self.log_dir}/{timestamp}_{client_ip}_{port}.log"
        
        with open(log_file, 'w') as f:
            f.write(f"Connection from {client_ip}:{client_port} to port {port}\n")
            f.write(f"Timestamp: {datetime.datetime.now().isoformat()}\n\n")
            
            # Send a banner to entice the attacker
            banner = self.get_service_banner(port)
            if banner:
                client_socket.send(banner.encode('utf-8'))
                f.write(f"Sent banner: {banner}\n\n")
            
            # Receive and log data (up to 4KB)
            try:
                data = b""
                while True:
                    chunk = client_socket.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 4096:
                        break
                
                if data:
                    f.write("Received data:\n")
                    try:
                        decoded = data.decode('utf-8', errors='replace')
                        f.write(decoded + "\n")
                    except:
                        f.write(f"Binary data: {data.hex()}\n")
            except Exception as e:
                f.write(f"Error receiving data: {e}\n")
        
        client_socket.close()
    
    def get_service_banner(self, port):
        """Return a fake service banner based on the port"""
        banners = {
            21: "220 Ubuntu FTP server 20.04 ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            23: "\r\nUbuntu 20.04 LTS\r\nlogin: ",
            25: "220 ubuntu.localdomain ESMTP Postfix\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            110: "+OK POP3 server ready\r\n",
            143: "* OK IMAP4rev1 Server ready\r\n",
            443: "",  # HTTPS doesn't typically send a banner
            3306: "5.7.32-0ubuntu0.20.04.1\x00",  # MySQL
            5432: "PostgreSQL 12.5 (Ubuntu 12.5-0ubuntu0.20.04.1)\r\n",  # PostgreSQL
            8080: "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n\r\n",
        }
        return banners.get(port, f"Ubuntu Service on port {port}\r\n")
    
    def start(self):
        """Start honeypot on all specified ports"""
        for port in self.ports:
            listener_thread = threading.Thread(target=self.start_listener, args=(port,))
            listener_thread.daemon = True
            listener_thread.start()
        
        # Keep the main thread running
        try:
            while self.running:
                signal.pause()
        except (KeyboardInterrupt, SystemExit):
            self.shutdown()
    
    def shutdown(self, *args):
        """Shutdown the honeypot gracefully"""
        logging.info("Shutting down honeypot...")
        self.running = False
        
        # Close all server sockets
        for server in self.servers:
            try:
                server.close()
            except:
                pass
        
        logging.info("Honeypot stopped")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Honeypot for Ubuntu")
    parser.add_argument(
        "--ports", 
        type=int, 
        nargs="+", 
        default=[21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 8080],
        help="Ports to monitor (default: common service ports)"
    )
    parser.add_argument(
        "--ip", 
        type=str, 
        default="0.0.0.0",
        help="IP address to bind to (default: 0.0.0.0)"
    )
    
    args = parser.parse_args()
    
    # Check if running as root (required to bind to privileged ports)
    if os.geteuid() != 0 and any(port < 1024 for port in args.ports):
        print("Error: Root privileges required to bind to ports below 1024.")
        print("Please run with sudo or as root.")
        sys.exit(1)
    
    print(f"Starting honeypot on {args.ip}, monitoring ports: {args.ports}")
    honeypot = Honeypot(args.ports, args.ip)
    honeypot.start()