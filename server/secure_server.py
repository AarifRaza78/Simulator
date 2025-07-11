#!/usr/bin/env python3
"""
Secure Server with Brute Force Detection
---------------------------------------
This server simulates a login service with brute force attack detection,
logging, and IP blocking capabilities.
"""

import socket
import threading
import json
import time
import logging
from datetime import datetime
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_log.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SecureServer")

# Server configuration
HOST = '127.0.0.1'
PORT = 9999
BACKLOG = 5
TIMEOUT = 60  # seconds

# Security settings
MAX_ATTEMPTS = 5  # Maximum failed attempts before temporary block
BLOCK_TIME = 300  # Block time in seconds (5 minutes)
DETECTION_WINDOW = 30  # Time window to count login attempts (in seconds)
ATTEMPT_THRESHOLD = 10  # Number of attempts within window that triggers alert

# In-memory database (username: password)
USER_DATABASE = {
    "admin": "secure_password_123",
    "user1": "user1pass",
    "user2": "strongpass456",
    "alice": "alicepass789",
    "bob": "bobsecret!@#"
}

# Track failed login attempts {ip_address: [timestamp1, timestamp2, ...]}
failed_attempts = {}

# Track blocked IPs {ip_address: unblock_time}
blocked_ips = {}

# Lock for thread safety
lock = threading.Lock()

def check_credentials(username, password):
    """Verify if the username and password match the database."""
    if username in USER_DATABASE:
        return USER_DATABASE[username] == password
    return False

def is_ip_blocked(ip_address):
    """Check if an IP address is currently blocked."""
    with lock:
        if ip_address in blocked_ips:
            if time.time() < blocked_ips[ip_address]:
                remaining = int(blocked_ips[ip_address] - time.time())
                return True, remaining
            else:
                # Unblock the IP as the block time has expired
                del blocked_ips[ip_address]
    return False, 0

def record_failed_attempt(ip_address):
    """Record a failed login attempt and block IP if threshold reached."""
    current_time = time.time()
    
    with lock:
        # Initialize if this is the first attempt from this IP
        if ip_address not in failed_attempts:
            failed_attempts[ip_address] = []
            
        # Add the timestamp of this attempt
        failed_attempts[ip_address].append(current_time)
        
        # Remove attempts outside the detection window
        failed_attempts[ip_address] = [t for t in failed_attempts[ip_address] 
                                    if current_time - t <= DETECTION_WINDOW]
        
        # Check if number of recent attempts exceeds threshold
        if len(failed_attempts[ip_address]) >= MAX_ATTEMPTS:
            blocked_ips[ip_address] = current_time + BLOCK_TIME
            logger.warning(f"IP {ip_address} BLOCKED for {BLOCK_TIME} seconds due to multiple failed attempts")
            return True
            
        # Check for potential brute force pattern
        if len(failed_attempts[ip_address]) >= ATTEMPT_THRESHOLD:
            logger.warning(f"ALERT: Potential brute force attack detected from {ip_address}")
            
    return False

def handle_client(client_socket, client_address):
    """Handle client connection and login attempts."""
    client_ip = client_address[0]
    logger.info(f"Connection from {client_ip}:{client_address[1]}")
    
    try:
        # Check if IP is blocked
        blocked, remaining = is_ip_blocked(client_ip)
        if blocked:
            response = {
                "status": "error",
                "message": f"Your IP is temporarily blocked. Try again in {remaining} seconds."
            }
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            logger.info(f"Rejected connection from blocked IP {client_ip}")
            return
        
        # Set a timeout for the client connection
        client_socket.settimeout(TIMEOUT)
        
        # Receive data from client
        data = client_socket.recv(1024).decode('utf-8')
        if not data:
            return
            
        # Parse the login request
        try:
            request = json.loads(data)
            username = request.get('username', '')
            password = request.get('password', '')
            
            # Validate credentials
            if check_credentials(username, password):
                response = {
                    "status": "success",
                    "message": f"Welcome, {username}! Login successful."
                }
                logger.info(f"Successful login for user '{username}' from {client_ip}")
            else:
                # Record the failed attempt
                blocked = record_failed_attempt(client_ip)
                
                if blocked:
                    response = {
                        "status": "error",
                        "message": f"Too many failed attempts. Your IP is blocked for {BLOCK_TIME} seconds."
                    }
                else:
                    response = {
                        "status": "error",
                        "message": "Invalid username or password."
                    }
                logger.warning(f"Failed login attempt for user '{username}' from {client_ip}")
                
            # Send response to client
            client_socket.sendall(json.dumps(response).encode('utf-8'))
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON received from {client_ip}")
            response = {"status": "error", "message": "Invalid request format."}
            client_socket.sendall(json.dumps(response).encode('utf-8'))
            
    except socket.timeout:
        logger.warning(f"Connection from {client_ip} timed out")
    except Exception as e:
        logger.error(f"Error handling client {client_ip}: {str(e)}")
    finally:
        client_socket.close()

def start_server():
    """Start the server and listen for connections."""
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(BACKLOG)
        
        logger.info(f"Server started on {HOST}:{PORT}")
        logger.info("Security settings:")
        logger.info(f"- Max failed attempts: {MAX_ATTEMPTS}")
        logger.info(f"- Block time: {BLOCK_TIME} seconds")
        logger.info(f"- Detection window: {DETECTION_WINDOW} seconds")
        logger.info(f"- Attempt threshold: {ATTEMPT_THRESHOLD}")
        
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
            
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
    finally:
        if 'server' in locals():
            server.close()

def print_stats():
    """Periodically print statistics about failed attempts and blocked IPs."""
    while True:
        try:
            time.sleep(60)  # Update stats every minute
            current_time = time.time()
            
            with lock:
                # Clean up expired blocks
                expired_blocks = [ip for ip, t in blocked_ips.items() if current_time > t]
                for ip in expired_blocks:
                    del blocked_ips[ip]
                
                # Print current stats
                logger.info(f"--- Stats Update ---")
                logger.info(f"Failed attempt tracking: {len(failed_attempts)} IPs")
                logger.info(f"Currently blocked IPs: {len(blocked_ips)}")
                for ip, unblock_time in blocked_ips.items():
                    remaining = int(unblock_time - current_time)
                    logger.info(f"  - {ip}: blocked for {remaining} more seconds")
                logger.info(f"-------------------")
                
        except Exception as e:
            logger.error(f"Error in stats thread: {str(e)}")

if __name__ == "__main__":
    # Start stats monitoring in a separate thread
    stats_thread = threading.Thread(target=print_stats)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Start the server
    start_server()
