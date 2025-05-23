—----------------------------------------------------

Password Strength Checker

A simple yet robust Python tool for checking the strength of passwords. This script analyzes passwords for length, character variety, entropy, and common weaknesses, providing instant feedback and actionable suggestions.

Features
Checks against common weak passwords

Evaluates password length and character diversity

Estimates password entropy (strength) using information theory

Gives detailed, user-friendly feedback

Scoring system for easy assessment

Quick and interactive CLI usage

How It Works
User enters a password via the command line.

The script checks:

Is the password common/weak?

Does it meet length requirements (8+ chars, 12+ chars recommended)?

Does it include lowercase, uppercase, digits, and special characters?

What’s the estimated entropy?

Outputs a score (0–7) and clear feedback, highlighting strengths and weaknesses.

Usage
Run the Script
bash
Copy
Edit
python password_checker.py
You’ll be prompted to enter a password. The program will then display:

Suggestions for improvement

A final score out of 7

An overall strength rating

Example Output
vbnet
Copy
Edit
=== Password Strength Checker ===
Enter a password to check: MyP@ssw0rd2024!

Feedback:
Good length.
Good entropy.
Strong password!

Score: 7/7
How the Score Works
Length: Short (<8), Decent (8–11), Good (12+)

Character Variety: Checks for lowercase, uppercase, digits, special characters

Entropy: Estimates the unpredictability of the password

Common Passwords: Instantly rejects widely used weak passwords

The highest possible score is 7. Feedback will guide you on how to improve weaker passwords.

Code Highlights
Uses regular expressions for pattern matching

Employs a mini-dictionary of common passwords

Calculates entropy based on character set and length

Modular design for easy customization and extension

Requirements
Python 3.x

No external libraries required

Why Use This Tool?
Great for personal use, educational projects, or as a base for web/app integration.

Helps users build stronger, safer passwords and learn good security habits.

--------------------------------------------------------

Mini-Project 31_ Python for Cybersecurity
Simple Python Port Scanner

This project is a simple and easy-to-use **port scanner** written in Python. It allows users to scan the open TCP ports of a target host on their local network or a host for which they have permission to scan. This tool demonstrates basic concepts of socket programming and network security.

## Project Overview

- **Demonstrates**: Socket programming and port scanning in Python.
- **Scans**: Well-known TCP ports (ports 1-1023).
- **Features**: User input validation, error handling for common issues, and displays scan timing information.
- **Purpose**: For educational use only—do not use on networks without authorization.

## Features

- Prompts user for a remote hostname or IP address.
- Validates user input for empty values.
- Resolves hostnames to IP addresses.
- Scans ports 1 through 1023 with a half-second timeout per port.
- Gracefully handles errors including:
    - Invalid hostnames
    - Remote server connection issues
    - User-initiated cancellation (Ctrl+C)
- Prints the open ports found and scan duration.

## Requirements

- Python 3.x

## Setup

1. **Clone the repository or download the `portscanner.py` script:**
    ```bash
    git clone https://github.com/yourusername/port-scanner.git
    cd port-scanner
    ```

2. **(Optional) Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use venv\Scripts\activate
    ```

3. **No external dependencies required!**

## Usage

1. **Run the script:**
    ```bash
    python portscanner.py
    ```

2. **Enter the hostname or IP address of the target host** when prompted.
    - Example: `localhost` or `192.168.1.1` or `www.example.com`

3. **View the results**:
    - Open ports will be listed as they are found.
    - If no ports are open or the host is unreachable, appropriate error messages will be displayed.
    - Scan duration is displayed upon completion.

## Example Output

Please wait, scanning remote host 192.168.1.10
Scanning started at: 2024-05-23 18:00:00.123456
Port 22: Open
Scanning completed in: 0:00:01.500123

## References

- [Python socket documentation](https://docs.python.org/3/library/socket.html)
- [Real Python - Python Socket Programming](https://realpython.com/python-sockets/)

—-----------------------------------

Mini Project 32: Perl: Analyze Apache Log File
Apache Log IP Counter
This project analyzes an Apache access log file to count how many requests came from the localhost IP (127.0.0.1) and how many came from other IP addresses. The script demonstrates basic Perl file handling and text processing techniques, specifically using the index and substr functions as required by the project prompt.

Project Prompt
Refer to the apache_access.log file. Every row is a request on a web server. Some are pages, some are images, some are JavaScript files. That's not important right now though.
We are going to focus on the first field of every line, which is the IP address of the requester.
As you know, every device uses the IP address 127.0.0.1 to refer to itself. So, visitors arriving from that IP address are coming from the same machine.
Your task is to write a script that will count how many requests came from 127.0.0.1 and how many from elsewhere.

Basic steps:

Open the file for reading or die

Chomp remove trailing newlines

Use index function

Use substr function

Solution Overview
The script reads the Apache access log line by line.

For each line, it extracts the IP address (the first field).

It counts how many times the IP address is 127.0.0.1 (localhost) and how many times it is any other address.

Uses Perl's index and substr functions for text processing, as required by the prompt.

Usage
Place your Apache access log file in the project directory and name it apache_access.log.

Run the script with Perl (Perl 5.32 or higher recommended):

bash
Copy
Edit
perl ip_counter.pl
Output Example:

csharp
Copy
Edit
Requests from 127.0.0.1: 7
Requests from elsewhere: 15
Code
<details> <summary>Click to view script</summary>
perl
Copy
Edit
use 5.32.0;
use warnings;

my $log_file = "apache_access.log";
open(my $fh, "<", $log_file) or die "File $log_file could not be found: $!";

my $local_count = 0;
my $other_count = 0;

while (my $line = <$fh>) {
    chomp $line;

    my $space_pos = index($line, ' ');
    next if $space_pos == -1;  # Skip if malformed

    my $ip_address = substr($line, 0, $space_pos);

    if ($ip_address eq '127.0.0.1') {
        $local_count++;
    } else {
        $other_count++;
    }
}

close($fh);

say "Requests from 127.0.0.1: $local_count";
say "Requests from elsewhere: $other_count";
</details>
Notes
The script assumes each line in apache_access.log begins with an IP address followed by a space.

It uses strict error checking to avoid issues with missing files or malformed log lines.

—----------------------------

Mini-Project 33: PowerShell for Cybersecurity

This repository contains my solutions to a set of Active Directory (AD) administration and security-related tasks using PowerShell. These exercises are commonly performed by sysadmins and security admins to manage and audit AD environments.

Usage
To run these commands, you will need:

Windows PowerShell with the ActiveDirectory module installed (RSAT tools).

Appropriate permissions in Active Directory.

Some commands may need to be run with administrator privileges.

—----------------------------------------

Perl Port Scanner

A multi-threaded port scanner written in Perl that quickly scans TCP ports on a target host. Supports flexible port range selection and customizable thread counts for efficient network reconnaissance.

Features
Multi-threaded: Fast scans using a user-defined number of threads

Flexible port selection: Scan a range (e.g. 1-1024), a list (e.g. 22,80,443), or both

Customizable: Choose target host, ports, and thread count from the command line

Simple output: Clearly lists all open ports found on the target

Easy to use: One script, simple dependencies, works cross-platform

Usage
sh
Copy
Edit
perl port_scanner.pl --host <host> [--ports <ports>] [--threads <threads>]
Options
Option	Short	Description	Default
--host	-h	Target host to scan (required)	
--ports	-p	Ports to scan (e.g. 22,80,443 or 1-1024)	1-1024
--threads	-t	Number of concurrent threads	100
--help		Show usage information	

Examples
Scan all ports from 1 to 1024 on scanme.nmap.org (default thread count):

sh
Copy
Edit
perl port_scanner.pl --host scanme.nmap.org
Scan ports 22, 80, and 443 on 192.168.1.1 with 50 threads:

sh
Copy
Edit
perl port_scanner.pl --host 192.168.1.1 --ports 22,80,443 --threads 50
Scan a custom port range on a local network device:

sh
Copy
Edit
perl port_scanner.pl -h 10.0.0.5 -p 1000-1100
Requirements
Perl 5 (tested on 5.32+)

Core Perl modules:

IO::Socket::INET

threads

Thread::Queue

Getopt::Long

Pod::Usage

Install any missing modules via CPAN:

sh
Copy
Edit
cpan IO::Socket::INET threads Thread::Queue Getopt::Long Pod::Usage
How it Works
Port Parsing: Supports ranges (e.g., 1-100), lists (e.g., 80,443), or both

Thread Pool: Launches a pool of threads to scan ports in parallel for speed

Result Display: Prints out open ports, or notifies if none are found

Sample Output
vbnet
Copy
Edit
Scanning scanme.nmap.org on ports: 1-1024
Using 100 threads...

Scan complete. Open ports on scanme.nmap.org:
  Port 22 is OPEN
  Port 80 is OPEN

