#!/usr/bin/env python3
"""
Legitimate Client
----------------
A client that connects to the secure server for normal login operations.
"""

import socket
import json
import sys
import time

# Server information
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

def login(username, password):
    """Attempt to login to the server with the given credentials."""
    try:
        # Create a socket connection
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        
        # Print the server's response
        print(f"\nServer Response:")
        print(f"Status: {response_data.get('status', 'unknown')}")
        print(f"Message: {response_data.get('message', 'No message')}")
        
        return response_data.get('status') == "success"
        
    except ConnectionRefusedError:
        print(f"Error: Could not connect to server at {SERVER_HOST}:{SERVER_PORT}")
        print("Make sure the server is running.")
        return False
    except json.JSONDecodeError:
        print("Error: Received invalid response from server")
        return False
    except Exception as e:
        print(f"Error: {str(e)}")
        return False
    finally:
        if 'client_socket' in locals():
            client_socket.close()

def interactive_mode():
    """Run the client in interactive mode."""
    print("\n=== Secure Login Client ===")
    print(f"Connecting to server at {SERVER_HOST}:{SERVER_PORT}")
    
    while True:
        print("\nOptions:")
        print("1. Login")
        print("2. Exit")
        
        choice = input("\nSelect an option (1-2): ").strip()
        
        if choice == "1":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            login(username, password)
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    if len(sys.argv) == 3:
        # Command-line login
        username = sys.argv[1]
        password = sys.argv[2]
        login(username, password)
    else:
        # Interactive mode
        interactive_mode()
