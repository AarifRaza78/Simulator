# Brute Force Attack Simulator with Detection

This project simulates password brute-force attacks against a secure server and implements various detection and protection mechanisms.

## Features

- **Secure Server**: Socket-based server that handles login attempts
- **Brute Force Detection**: Monitors failed login attempts and implements IP blocking
- **Attack Simulation**: Configurable brute force attack client with multi-threading
- **Analysis Tools**: Scripts to analyze and visualize attack patterns
- **Legitimate Client**: Normal login client for comparison

## Project Structure

```
brute_force_simulator/
├── server/
│   └── secure_server.py  # Server with brute force protection
├── client/
│   ├── legitimate_client.py  # Normal login client
│   └── brute_force_attacker.py  # Attack simulation
└── utils/
    ├── password_dictionary.txt  # Common passwords list
    └── log_analyzer.py  # Analytics tool
```

## Getting Started

### Prerequisites

- Python 3.6+
- matplotlib (for analytics visualization): `pip install matplotlib`

### Running the Server

```bash
cd brute_force_simulator/server
python secure_server.py
```

The server will start listening on 127.0.0.1:9999 by default.

### Using the Legitimate Client

```bash
cd brute_force_simulator/client
python legitimate_client.py
```

Or use command-line arguments:

```bash
python legitimate_client.py username password
```

### Running a Brute Force Attack

```bash
cd brute_force_simulator/client
python brute_force_attacker.py -u admin -d ../utils/password_dictionary.txt
```

#### Attack Options

- `-u, --username`: Target username (default: admin)
- `-d, --dictionary`: Password dictionary file
- `-t, --threads`: Number of threads (default: 1)
- `-w, --wait`: Delay between attempts in seconds (default: 0.1)
- `-r, --random`: Randomize password list order

### Analyzing Logs

After running the server and performing some attacks, you can analyze the logs:

```bash
cd brute_force_simulator/utils
python log_analyzer.py ../server/server_log.log
```

This will generate both a text report and visual analysis of the attack patterns.

## Security Features

- IP-based blocking after multiple failed attempts
- Time-windowed attempt counting
- Throttling of login attempts
- Detailed logging of suspicious activities

## Customizing the Simulation

You can modify the following parameters in the server and client files:

### Server (`secure_server.py`)
- `MAX_ATTEMPTS`: Number of failed attempts before blocking
- `BLOCK_TIME`: Duration of IP blocks in seconds
- `DETECTION_WINDOW`: Time window to count attempts
- `ATTEMPT_THRESHOLD`: Attempts threshold for alerts

### Attacker (`brute_force_attacker.py`)
- Command-line parameters to control attack speed and threading

## Educational Purpose

This project is designed for educational purposes only to understand:
1. How brute force attacks work
2. How to detect and prevent them
3. Analysis of attack patterns

**Do not use this tool against systems without explicit permission.**

## License

This project is licensed under the MIT License - see the LICENSE file for details.
