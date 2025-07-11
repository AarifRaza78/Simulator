#!/usr/bin/env python3
"""
Attack Analytics Tool
-------------------
Analyzes server logs to identify attack patterns and visualize brute force attempts.
"""

import re
import sys
import os
import datetime
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict, Counter
import argparse

def parse_log_file(log_file):
    """Parse the server log file and extract relevant information."""
    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found.")
        return None
        
    # Patterns to extract information from log lines
    login_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*Failed login attempt for user \'(.*?)\' from (\d+\.\d+\.\d+\.\d+)')
    block_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*IP (\d+\.\d+\.\d+\.\d+) BLOCKED for (\d+) seconds')
    alert_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}).*ALERT: Potential brute force attack detected from (\d+\.\d+\.\d+\.\d+)')
    
    # Data structures to store extracted information
    failed_attempts = []
    blocked_ips = []
    alerts = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Extract failed login attempts
                login_match = login_pattern.search(line)
                if login_match:
                    timestamp = login_match.group(1)
                    username = login_match.group(2)
                    ip = login_match.group(3)
                    failed_attempts.append((timestamp, username, ip))
                    continue
                
                # Extract IP blocks
                block_match = block_pattern.search(line)
                if block_match:
                    timestamp = block_match.group(1)
                    ip = block_match.group(2)
                    duration = block_match.group(3)
                    blocked_ips.append((timestamp, ip, duration))
                    continue
                    
                # Extract brute force alerts
                alert_match = alert_pattern.search(line)
                if alert_match:
                    timestamp = alert_match.group(1)
                    ip = alert_match.group(2)
                    alerts.append((timestamp, ip))
                    
        return {
            'failed_attempts': failed_attempts,
            'blocked_ips': blocked_ips,
            'alerts': alerts
        }
        
    except Exception as e:
        print(f"Error parsing log file: {str(e)}")
        return None

def convert_timestamp(timestamp_str):
    """Convert timestamp string to datetime object."""
    return datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')

def analyze_data(log_data):
    """Analyze the extracted log data and calculate statistics."""
    if not log_data:
        return None
        
    # Count failed attempts by IP
    ip_attempts = defaultdict(int)
    for _, username, ip in log_data['failed_attempts']:
        ip_attempts[ip] += 1
    
    # Count failed attempts by username
    username_attempts = defaultdict(int)
    for _, username, _ in log_data['failed_attempts']:
        username_attempts[username] += 1
    
    # Count blocks by IP
    ip_blocks = defaultdict(int)
    for _, ip, _ in log_data['blocked_ips']:
        ip_blocks[ip] += 1
    
    # Calculate time distribution of failed attempts
    time_distribution = defaultdict(int)
    for timestamp, _, _ in log_data['failed_attempts']:
        dt = convert_timestamp(timestamp)
        hour_minute = dt.strftime('%H:%M')
        time_distribution[hour_minute] += 1
    
    return {
        'ip_attempts': dict(ip_attempts),
        'username_attempts': dict(username_attempts),
        'ip_blocks': dict(ip_blocks),
        'time_distribution': dict(time_distribution),
        'total_failed_attempts': len(log_data['failed_attempts']),
        'total_blocks': len(log_data['blocked_ips']),
        'total_alerts': len(log_data['alerts'])
    }

def visualize_data(analysis_data):
    """Create visualizations of the analyzed data."""
    if not analysis_data:
        return
    
    plt.figure(figsize=(16, 10))
    
    # Plot 1: Top 10 IPs with failed attempts
    plt.subplot(2, 2, 1)
    ip_counts = Counter(analysis_data['ip_attempts'])
    top_ips = dict(ip_counts.most_common(10))
    plt.bar(top_ips.keys(), top_ips.values(), color='skyblue')
    plt.title('Top 10 IPs with Failed Login Attempts')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Failed Attempts')
    plt.xticks(rotation=45)
    
    # Plot 2: Top 10 usernames targeted
    plt.subplot(2, 2, 2)
    username_counts = Counter(analysis_data['username_attempts'])
    top_usernames = dict(username_counts.most_common(10))
    plt.bar(top_usernames.keys(), top_usernames.values(), color='orange')
    plt.title('Top 10 Targeted Usernames')
    plt.xlabel('Username')
    plt.ylabel('Number of Failed Attempts')
    plt.xticks(rotation=45)
    
    # Plot 3: Time distribution of failed attempts
    plt.subplot(2, 2, 3)
    # Sort time distribution by time
    sorted_times = sorted(analysis_data['time_distribution'].items(), 
                         key=lambda x: datetime.datetime.strptime(x[0], '%H:%M'))
    times = [x[0] for x in sorted_times]
    counts = [x[1] for x in sorted_times]
    
    plt.plot(times, counts, 'r-', marker='o')
    plt.title('Time Distribution of Failed Attempts')
    plt.xlabel('Time (HH:MM)')
    plt.ylabel('Number of Failed Attempts')
    plt.xticks(rotation=45)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Plot 4: Pie chart of blocked IPs vs. non-blocked IPs
    plt.subplot(2, 2, 4)
    total_ips = len(analysis_data['ip_attempts'])
    blocked_ips = len(analysis_data['ip_blocks'])
    non_blocked = total_ips - blocked_ips
    
    plt.pie([blocked_ips, non_blocked], 
            labels=['Blocked IPs', 'Non-Blocked IPs'], 
            autopct='%1.1f%%', 
            colors=['crimson', 'lightgreen'],
            explode=(0.1, 0),
            shadow=True)
    plt.title('Proportion of IPs Blocked')
    
    # Summary statistics as text
    plt.figtext(0.5, 0.02, 
               f"Total Failed Attempts: {analysis_data['total_failed_attempts']} | "
               f"Total Blocks: {analysis_data['total_blocks']} | "
               f"Total Alerts: {analysis_data['total_alerts']}",
               ha='center', fontsize=12, bbox={'facecolor': 'lightgrey', 'alpha': 0.5})
    
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.15)
    
    # Save the figure and show it
    plt.savefig('attack_analysis.png')
    print(f"Analysis visualization saved as 'attack_analysis.png'")
    plt.show()

def print_report(analysis_data):
    """Print a textual report of the analyzed data."""
    if not analysis_data:
        return
        
    print("\n===== Brute Force Attack Analysis Report =====\n")
    
    print(f"Total Failed Login Attempts: {analysis_data['total_failed_attempts']}")
    print(f"Total IP Blocks: {analysis_data['total_blocks']}")
    print(f"Total Brute Force Alerts: {analysis_data['total_alerts']}")
    
    print("\nTop 5 IPs with Failed Attempts:")
    ip_counts = Counter(analysis_data['ip_attempts'])
    for ip, count in ip_counts.most_common(5):
        print(f"  {ip}: {count} attempts")
    
    print("\nTop 5 Targeted Usernames:")
    username_counts = Counter(analysis_data['username_attempts'])
    for username, count in username_counts.most_common(5):
        print(f"  {username}: {count} attempts")
    
    print("\nBlocked IPs and Number of Blocks:")
    for ip, count in analysis_data['ip_blocks'].items():
        print(f"  {ip}: blocked {count} times")
    
    print("\n==========================================\n")

def main():
    """Main function to parse arguments and run the analysis."""
    parser = argparse.ArgumentParser(description="Analyze brute force attack logs")
    parser.add_argument("log_file", help="Path to the server log file")
    parser.add_argument("--no-viz", action="store_true", 
                        help="Disable visualization (text report only)")
    parser.add_argument("--output", "-o", help="Save the report to a text file")
    
    args = parser.parse_args()
    
    # Parse and analyze log data
    log_data = parse_log_file(args.log_file)
    if not log_data:
        return
        
    analysis_data = analyze_data(log_data)
    if not analysis_data:
        return
    
    # Print report to console or file
    if args.output:
        original_stdout = sys.stdout
        try:
            with open(args.output, 'w') as f:
                sys.stdout = f
                print_report(analysis_data)
            sys.stdout = original_stdout
            print(f"Report saved to {args.output}")
        except Exception as e:
            sys.stdout = original_stdout
            print(f"Error saving report: {str(e)}")
    else:
        print_report(analysis_data)
    
    # Generate visualization if not disabled
    if not args.no_viz:
        try:
            visualize_data(analysis_data)
        except Exception as e:
            print(f"Error creating visualization: {str(e)}")
            print("Make sure matplotlib is installed: pip install matplotlib")

if __name__ == "__main__":
    main()
