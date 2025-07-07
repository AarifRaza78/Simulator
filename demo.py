#!/usr/bin/env python3
"""
Demo Script for Brute Force Attack Simulator
------------------------------------------
Runs a complete demonstration of the simulator in multiple terminals.
"""

import os
import subprocess
import time
import sys
import signal
import atexit

# Global list of processes to terminate on exit
processes = []

def cleanup():
    """Kill all spawned processes on exit."""
    for p in processes:
        try:
            p.terminate()
            p.wait(timeout=1)
        except:
            try:
                p.kill()
            except:
                pass

def run_in_terminal(command, title="Terminal"):
    """Run a command in a new terminal window."""
    # Determine which terminal program to use
    terminal = None
    
    # Try different terminals
    if os.system('which gnome-terminal > /dev/null') == 0:
        terminal = ['gnome-terminal', '--', 'bash', '-c']
    elif os.system('which xterm > /dev/null') == 0:
        terminal = ['xterm', '-title', title, '-e']
    elif os.system('which konsole > /dev/null') == 0:
        terminal = ['konsole', '--separate', '--workdir', os.getcwd(), '-e']
    else:
        print("Couldn't find a suitable terminal emulator.")
        print(f"Please run this command manually: {command}")
        return None
    
    # Launch the process
    process = subprocess.Popen(terminal + [command])
    processes.append(process)
    return process

def main():
    """Run the demo."""
    # Register cleanup function
    atexit.register(cleanup)
    
    # Clear the screen
    os.system('clear')
    
    print("="*60)
    print("  BRUTE FORCE ATTACK SIMULATOR - INTERACTIVE DEMO")
    print("="*60)
    print("\nThis script will start the server and different clients in separate terminal windows.")
    print("Press Ctrl+C at any time to stop the demo.")
    
    # Get the base directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    try:
        # Start the server
        print("\n[1/4] Starting the secure server...")
        server_dir = os.path.join(base_dir, "server")
        server_cmd = f"cd {server_dir} && python3 ./secure_server.py; exec bash"
        server_process = run_in_terminal(server_cmd, "Secure Server")
        time.sleep(2)  # Wait for server to start
        
        # Start the legitimate client
        print("[2/4] Starting the legitimate client...")
        client_dir = os.path.join(base_dir, "client")
        client_cmd = f"cd {client_dir} && python3 ./legitimate_client.py; exec bash"
        client_process = run_in_terminal(client_cmd, "Legitimate Client")
        time.sleep(1)
        
        # Start the brute force attacker
        print("[3/4] Starting the brute force attacker...")
        utils_dir = os.path.join(base_dir, "utils")
        attacker_cmd = f"cd {client_dir} && python3 ./brute_force_attacker.py -u admin -d {utils_dir}/password_dictionary.txt -w 0.2; exec bash"
        attacker_process = run_in_terminal(attacker_cmd, "Brute Force Attacker")
        time.sleep(1)
        
        # Start another brute force attacker with multiple threads
        print("[4/4] Starting another attacker with multiple threads...")
        mt_attacker_cmd = f"cd {client_dir} && python3 ./brute_force_attacker.py -u user1 -d {utils_dir}/password_dictionary.txt -t 4 -w 0.1; exec bash"
        mt_attacker_process = run_in_terminal(mt_attacker_cmd, "Multi-Threaded Attacker")
        
        print("\nAll components started! Watch the terminals to see the simulation in action.")
        print("\nAfter the simulation, you can analyze the logs with:")
        print(f"cd {utils_dir} && python3 ./log_analyzer.py {server_dir}/server_log.log")
        print("\nPress Ctrl+C to stop all processes and exit the demo.")
        
        # Wait indefinitely until Ctrl+C
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDemo stopped by user. Cleaning up...")
        cleanup()
        print("All processes terminated. Demo ended.")

if __name__ == "__main__":
    main()
