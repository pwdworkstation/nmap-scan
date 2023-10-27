![nmap-script_pwdworkstation_vectorized](https://github.com/pwdworkstation/nmap-scan/assets/138977500/0d94b0bd-d9db-46fe-baa9-a1f73dcbfdbc)

## Overview
![phython](https://github.com/pwdworkstation/nmap-scan/assets/138977500/92554906-c762-486b-9304-fefd0794dfec) ![parrot-os](https://github.com/pwdworkstation/nmap-scan/assets/138977500/f697d833-0f05-4b0b-8c82-5af94e36d276)



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
![nmap-pwdworkstation-IP_01](https://github.com/pwdworkstation/nmap-scan/assets/138977500/cb3b0f03-f550-4157-b0de-6edbf7a72831)
## 
![nmap-pwdworkstation-IP_02](https://github.com/pwdworkstation/nmap-scan/assets/138977500/0724b07c-2801-440c-9dbf-a4bbe363b83d)
## 
![nmap-pwdworkstation-IP_03](https://github.com/pwdworkstation/nmap-scan/assets/138977500/caaa0ca3-e32f-40b2-b583-045577f82b9f)
##
Here's an example of an IP range, using the command -A -sS, saved in the -oG format.
![nmap-pwdworkstation-IP-range_01](https://github.com/pwdworkstation/nmap-scan/assets/138977500/a7b67645-1ded-43db-a781-367314c97d85)
## 
![nmap-pwdworkstation-IP-range_02](https://github.com/pwdworkstation/nmap-scan/assets/138977500/ff2f110d-cd41-41ad-a20b-6bcba30a1008)
## 
![nmap-pwdworkstation-IP-range_03](https://github.com/pwdworkstation/nmap-scan/assets/138977500/378b7c18-eb77-4d27-865e-ec09dc8f7a7a)
## 
![nmap-pwdworkstation-8](https://github.com/pwdworkstation/nmap-scan/assets/138977500/ce722bba-2c6a-45d0-8e5f-4795bbcdc3f8)
## 
![nmap-pwdworkstation-9](https://github.com/pwdworkstation/nmap-scan/assets/138977500/44e230e6-6c3f-43fd-8b2b-7bdaf6b545d4)

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

This simple script was created by me, an enthusiast of technology and cybersecurity. While I have a keen interest in the world of programming, this project is an exercise to enhance my skills in Python and to explore the field of pentesting in a basic capacity.

As a beginner in the realm of programming and cybersecurity, my aim with this script is not to establish myself as an expert in the field but rather to provide a simple tool that may be helpful for those also embarking on their journey in this exciting domain. I welcome any feedback, advice, or contribution that the community may offer to improve this simple project and my skills at large.

If you wish to connect or share any ideas related to this project, feel free to reach out to me through my GitHub profile.
