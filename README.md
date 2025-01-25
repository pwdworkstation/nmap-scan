![nmap-script_pwdworkstation_vectorized](https://github.com/pwdworkstation/nmap-scan/assets/138977500/128048d9-6c85-4edc-8da6-423dbb5e2081)

## Overview
[![Python Version](https://img.shields.io/badge/python-3.9.2-blue.svg)](https://www.python.org/downloads/release/python-390/) [![Developed in Parrot Security](https://img.shields.io/badge/Developed%20in-Parrot%20Security-23B5E8.svg)](https://www.parrotsec.org/) ![Nmap Version](https://img.shields.io/badge/Nmap-7.93-orange.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) ![Last Update: October 2023](https://img.shields.io/badge/Last_Update-October_2023-purple.svg)



This script is designed to facilitate port scanning using the Nmap command-line tool. It provides an interactive interface for users to input target IP addresses or domains and additional Nmap options. The script offers color-coded output for easy interpretation of results and provides the option to save the scan report in various formats.
It's simply provides a set of basic instructions to initiate a scan, with credit due to Nmap for its comprehensive scanning capabilities and functionalities.

## Simplified Nmap Exploration for Beginners

The Nmap Scan Script serves as an accessible resource tailored for users seeking a straightforward introduction to the functionalities of Nmap. Designed with a user-friendly approach in mind, this script provides a simplified pathway for individuals navigating the complexities of network security. By offering a practical and hands-on guide, the script aims to empower beginners in comprehending the fundamental mechanics of Nmap without the need for intricate technical expertise.

By presenting a concise and comprehensive overview of Nmap's core functionalities, this script enables users to embark on their journey in network security exploration with confidence and clarity. It serves as an invaluable companion for individuals eager to grasp the foundational concepts of Nmap in a convenient and accessible manner.

#### Requirements

- Python 3.x
- Nmap

### Installing Python 3.x

You can install Python 3.x using the package manager that comes with your Linux distribution.

```python
sudo apt update sudo apt install python3
```

### Installing Nmap

You can install Nmap using the package manager that comes with your Linux distribution.

```python
sudo apt update
sudo apt install nmap
```

## Modules Used

- **signal:** Allows manipulation of software signals and management of interruptions.
- **os:** Provides functions for interacting with the operating system, such as file and directory manipulation.
- **re:** Offers operations for working with regular expressions, enabling sophisticated parsing and manipulation of text strings.
- **time:** Provides functions related to time manipulation, such as accessing the system clock and measuring time intervals.
- **subprocess:** Allows the generation of new processes, as well as communication with them.
- **sys:** Offers access to system-specific variables and functions, as well as the ability to interact with the Python interpreter itself.
- **threading:** Allows the concurrent execution of multiple threads (subprocesses) within a program, facilitating parallel programming.
- **socket:** Provides a socket API that enables communication over the network using specific protocols.
- **validators:** Offers functions for validating and verifying the validity of certain data types, such as email addresses, URLs, etc.
- **readline:** Provides command-line editing capabilities, enabling more sophisticated handling of user inputs in the terminal.

## Usage

Run the script in the terminal with the following command:

```python
python3 nmap-scan.py
```

#### Additional Option

The script supports the following additional option:

#Display suggested Nmap commands.
```python
python3 nmap-scan.py help 
```

## Screenshots
Here's an example of an IP with the command -A -sS saved in the -oN, -oX, -oA, -oG formats.
![nmap-pwdworkstation-IP_01](https://github.com/pwdworkstation/nmap-scan/assets/138977500/c293ee49-8bd1-450f-9d4e-d063ba8e3a47)
## 
![nmap-pwdworkstation-IP_02](https://github.com/pwdworkstation/nmap-scan/assets/138977500/a3700295-f66b-468d-8d72-77c5387c9609)
## 
![nmap-pwdworkstation-IP_03](https://github.com/pwdworkstation/nmap-scan/assets/138977500/5ca9e391-5c1b-4eb4-81f0-7d9966a2c6f0)
##
Here's an example of an IP range, using the command -A -sS, saved in the -oG format.
![nmap-pwdworkstation-IP-range_01](https://github.com/pwdworkstation/nmap-scan/assets/138977500/6fc169fb-e4ae-467b-8567-4a8e19863c40)
## 
![nmap-pwdworkstation-IP-range_02](https://github.com/pwdworkstation/nmap-scan/assets/138977500/592907b1-436b-46b1-91a3-6266e0723fa7)
## 
![nmap-pwdworkstation-IP-range_03](https://github.com/pwdworkstation/nmap-scan/assets/138977500/7b18479b-90fa-4ee2-9880-06e3089a345d)
## 
![nmap-pwdworkstation-8](https://github.com/pwdworkstation/nmap-scan/assets/138977500/e89e718b-5896-4c35-8379-526771dff73d)
## 
![nmap-pwdworkstation-9](https://github.com/pwdworkstation/nmap-scan/assets/138977500/08af06cc-7797-4d13-ad56-f37b5df639d1)

## Example

### Example 1: Custom Scan with Additional Options

```python
nmap -sV -p 1-1000 192.168.0.1-1000
```

This command scans the specified IP range with service version detection enabled and port range set from 1 to 1000.

### Example 2: Range Scanning with CIDR Notation

A common way to scan a range of IP addresses is by using CIDR (Classless Inter-Domain Routing) notation. For instance, to scan a range of IP addresses belonging to the local network 192.168.10.0, you can use CIDR notation as follows:

```python
nmap 192.168.10.0/24
```

This command will scan all IP addresses in the range of the local network 192.168.10.0, with the suffix "/24" indicating that the first 24 bits of the IP address should be considered as the network part, corresponding to the first three numeric sequences "192.168.10". This notation makes it convenient to scan a broader range of IP addresses with a single concise instruction.

CIDR notation simplifies the specification of IP address ranges by indicating the number of bits of the IP address that will be considered as part of the network. For example, "/24" implies that the first 24 bits of the address refer to the network, while the remaining 8 bits (32 bits in total in a standard IP address) can take any value in the range from 0 to 255.

### Example 3: Web Application Vulnerability Analysis

Nmap can be used for web application vulnerability analysis, aiding in the identification of potential security vulnerabilities within specific web pages. For instance, the following command targets a particular website:

```python
nmap --script http-vuln-cve2014-2126 <website URL>
```

In this command, the `--script http-vuln-cve2014-2126` option triggers Nmap to scan for a specific known vulnerability associated with the CVE (Common Vulnerabilities and Exposures) identifier "CVE-2014-2126" on the specified website. This helps in detecting and evaluating any existing vulnerabilities, thereby fortifying the overall security of the web application.

### Example 4: Firewall and IDS Evasion Analysis

Nmap is capable of performing Firewall and IDS (Intrusion Detection System) Evasion Analysis, assisting in the evaluation of network security measures. The following command demonstrates how Nmap can be used to test evasion techniques:

```python
nmap -f -D RND:10 <target IP>
```

In this command, the options `-f` and `-D RND:10` allow Nmap to utilize fragmentation and a decoy scanning technique to evade firewall and IDS detection. This aids in assessing the robustness of the network's security infrastructure, enabling the identification of potential weaknesses and vulnerabilities that might be exploited by malicious actors.

### Example 5: Vulnerability Analysis

Nmap can also be employed for Vulnerability Analysis, aiding in the identification of potential weaknesses within a network or system. The following command showcases a basic vulnerability scan:

```python
nmap --script vuln <target IP>
```

By utilizing the `--script vuln` option, Nmap executes a series of scripts designed to identify known vulnerabilities within the target network or system. This process enables the detection of potential entry points that may be exploited by attackers, allowing administrators to take preemptive measures to bolster the overall security posture.

## Usage and Command-line Options

- The script prompts users to input target IP addresses or domains for scanning.
- Users can add extra Nmap options to the command for more customized scans.
- The script includes a comprehensive list of Nmap commands and options for reference.

## Troubleshooting

- If you encounter issues or errors while running the script, ensure that the Nmap and Python environments are properly configured.
- Verify that the required Python modules are installed using the provided installation command.

## Contributing

We welcome contributions to this project. Please provide feedback, report bugs, or suggest improvements by submitting issues or pull requests on GitHub.

## License

This script is distributed under the [MIT License](https://opensource.org/licenses/MIT).

## Acknowledgments

We express our gratitude to the developers of the Nmap tool and the Python community for their invaluable contributions.

## About this script

About this script

This is a simple script I made to quickly experiment with Nmap. It’s not a complex tool, just a basic way to play around with it and see what it can do. If you're looking for something quick and easy to use, this might be helpful.

Feel free to try it out, and if you have any feedback or ideas to improve it, I’d be happy to hear from you.
