#!/usr/bin/env python3
"""
Setup Script for Brute Force Attack Simulator
--------------------------------------------
Checks dependencies and helps set up the environment.
"""

import sys
import os
import subprocess
import shutil

def check_python_version():
    """Check if Python version is 3.6+."""
    required_version = (3, 6)
    current_version = sys.version_info
    
    if current_version.major < required_version[0] or \
       (current_version.major == required_version[0] and 
        current_version.minor < required_version[1]):
        print(f"Error: Python {required_version[0]}.{required_version[1]}+ is required")
        print(f"Current Python version: {current_version.major}.{current_version.minor}")
        return False
    
    print(f"✓ Python version {current_version.major}.{current_version.minor}.{current_version.micro} detected")
    return True

def check_dependencies():
    """Check if required Python packages are installed."""
    try:
        import matplotlib
        print("✓ matplotlib is installed")
        has_matplotlib = True
    except ImportError:
        print("× matplotlib is not installed (required for visualization)")
        has_matplotlib = False
    
    return has_matplotlib

def install_dependencies():
    """Install required dependencies."""
    print("\nInstalling dependencies...")
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "matplotlib"])
        print("✓ matplotlib installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("× Failed to install matplotlib")
        return False

def check_file_permissions():
    """Check if script files have execute permissions."""
    files_to_check = [
        "server/secure_server.py",
        "client/legitimate_client.py",
        "client/brute_force_attacker.py",
        "utils/log_analyzer.py"
    ]
    
    all_executable = True
    
    for file in files_to_check:
        if not os.path.exists(file):
            print(f"× File not found: {file}")
            all_executable = False
            continue
            
        if not os.access(file, os.X_OK):
            print(f"× File not executable: {file}")
            all_executable = False
        else:
            print(f"✓ File is executable: {file}")
    
    return all_executable

def set_file_permissions():
    """Set execute permissions on script files."""
    files_to_chmod = [
        "server/secure_server.py",
        "client/legitimate_client.py",
        "client/brute_force_attacker.py",
        "utils/log_analyzer.py"
    ]
    
    print("\nSetting execute permissions...")
    
    for file in files_to_chmod:
        try:
            if os.path.exists(file):
                os.chmod(file, 0o755)  # rwxr-xr-x
                print(f"✓ Set execute permission on {file}")
            else:
                print(f"× File not found: {file}")
        except Exception as e:
            print(f"× Error setting permissions for {file}: {str(e)}")
            
    return True

def print_usage_instructions():
    """Print instructions on how to use the simulator."""
    print("\n" + "="*50)
    print("BRUTE FORCE ATTACK SIMULATOR - USAGE INSTRUCTIONS")
    print("="*50)
    
    print("\n1. Start the server:")
    print("   cd server")
    print("   ./secure_server.py")
    
    print("\n2. Use the legitimate client:")
    print("   cd client")
    print("   ./legitimate_client.py")
    print("   # or with credentials:")
    print("   ./legitimate_client.py username password")
    
    print("\n3. Run a brute force attack:")
    print("   cd client")
    print("   ./brute_force_attacker.py -u admin -d ../utils/password_dictionary.txt")
    print("   # For faster attack with 4 threads:")
    print("   ./brute_force_attacker.py -u admin -d ../utils/password_dictionary.txt -t 4")
    
    print("\n4. Analyze the attack logs:")
    print("   cd utils")
    print("   ./log_analyzer.py ../server/server_log.log")
    
    print("\n" + "="*50)
    print("NOTE: This tool is for educational purposes only.")
    print("="*50 + "\n")

def main():
    """Main setup function."""
    print("="*50)
    print("BRUTE FORCE ATTACK SIMULATOR - SETUP")
    print("="*50 + "\n")
    
    # Check Python version
    if not check_python_version():
        print("\nPlease upgrade your Python version and try again.")
        sys.exit(1)
    
    # Check dependencies
    has_matplotlib = check_dependencies()
    if not has_matplotlib:
        install = input("\nWould you like to install matplotlib now? (y/n): ").strip().lower()
        if install == 'y':
            has_matplotlib = install_dependencies()
        else:
            print("Note: Visualization will not be available without matplotlib.")
    
    # Check file permissions
    all_executable = check_file_permissions()
    if not all_executable:
        set_perm = input("\nWould you like to set execute permissions on the scripts? (y/n): ").strip().lower()
        if set_perm == 'y':
            set_file_permissions()
        else:
            print("Note: You'll need to set permissions manually to run the scripts.")
    
    # Print usage instructions
    print_usage_instructions()

if __name__ == "__main__":
    main()
