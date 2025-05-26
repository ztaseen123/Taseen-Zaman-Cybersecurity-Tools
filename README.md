Cybersecurity Tools Collection
A comprehensive collection of cybersecurity and network administration tools written in Python, Perl, and PowerShell. These tools are designed for educational purposes, penetration testing, system administration, and security auditing.
🛡️ Tools Overview
1. Password Strength Checker (Python)
A robust Python tool for evaluating password security using entropy calculations and pattern analysis.
2. Python Port Scanner
A fast, multi-threaded TCP port scanner with progress tracking and comprehensive reporting.
3. Perl Port Scanner
An advanced multi-threaded port scanner with flexible port selection and customizable threading.
4. Apache Log Analyzer (Perl)
Efficient log file analyzer for tracking specific IP addresses in Apache access logs.
5. PowerShell AD Commands
A collection of Active Directory administration and security audit commands.

🐍 Password Strength Checker
A simple yet robust Python tool for checking the strength of passwords. This script analyzes passwords for length, character variety, entropy, and common weaknesses, providing instant feedback and actionable suggestions.
Features

✅ Checks against common weak passwords
✅ Evaluates password length and character diversity
✅ Estimates password entropy (strength) using information theory
✅ Gives detailed, user-friendly feedback
✅ Scoring system for easy assessment
✅ Quick and interactive CLI usage

Usage
bashpython3 password_checker.py
Example Output
=== Password Strength Checker ===
Enter a password to check: MyP@ssw0rd2024!

Feedback:
✅ Good length.
✅ Good entropy.
🎉 Strong password!

Score: 7/7
Requirements

Python 3.x
No external libraries required


🐍 Python Port Scanner
A simple and efficient port scanner written in Python with progress tracking and comprehensive error handling.
Features

🎯 Scans TCP ports 1-1023
📊 Real-time progress indication
🛡️ Comprehensive error handling
⏱️ Detailed timing and statistics
🔄 Graceful interrupt handling (Ctrl+C)

Usage
bashpython3 port_scanner.py
Example Output
============================================================
           Python Port Scanner
============================================================
Enter a remote host to scan: scanme.nmap.org
------------------------------------------------------------
Scanning target: scanme.nmap.org (45.33.32.156)
Port range: 1-1023
Scan started at: 2024-05-26 14:30:00
------------------------------------------------------------
Scanned 100/1023 ports...
Port 22: OPEN
Port 80: OPEN
------------------------------------------------------------
SCAN RESULTS
------------------------------------------------------------
Host: scanme.nmap.org (45.33.32.156)
Ports scanned: 1023
Open ports found: 2
Open ports: 22, 80
Total scan time: 0:00:15.432
Requirements

Python 3.x
No external dependencies


🐪 Perl Port Scanner
A high-performance, multi-threaded port scanner with advanced features and flexible configuration options.
Features

⚡ Multi-threaded scanning for maximum speed
🎛️ Flexible port selection (ranges, lists, combinations)
🔧 Customizable thread count
📝 Built-in help documentation
🛡️ Input validation and error handling
📊 Comprehensive result reporting

Usage
bashperl port_scanner.pl --host <target> [options]
Options
OptionShortDescriptionDefault--host-hTarget host to scan (required)---ports-pPorts to scan (e.g. 22,80,443 or 1-1024)1-1024--threads-tNumber of concurrent threads100--help-Show usage information-
Examples
bash# Scan default ports (1-1024) with 100 threads
perl port_scanner.pl --host scanme.nmap.org

# Scan specific ports with custom thread count  
perl port_scanner.pl --host 192.168.1.1 --ports 22,80,443 --threads 50

# Scan port ranges and individual ports
perl port_scanner.pl -h example.com -p "20-25,80,443,8000-8080"
Requirements

Perl 5.32+
Core modules: IO::Socket::INET, threads, Thread::Queue, Getopt::Long, Pod::Usage


🐪 Apache Log Analyzer
Efficient Perl script for analyzing Apache access logs and tracking specific IP addresses with comprehensive statistics.
Features

🎯 Tracks multiple target IP addresses simultaneously
📊 Progress indication for large log files
📈 Comprehensive statistics and summaries
🛡️ Robust error handling and input validation
⚡ Optimized hash-based lookup for performance
📝 Professional formatted output

Usage
bashperl apache_log_analyzer.pl
Note: Ensure your log file is named apache_access.log or modify the $log_file variable in the script.
Configuration
Edit the script to customize target IP addresses:
perlmy @target_ips = ('127.0.0.1', '127.0.0.11', '217.0.22.3', '139.12.0.2');
Example Output
Analyzing Apache log file: apache_access.log
Target IP addresses: 127.0.0.1, 127.0.0.11, 217.0.22.3, 139.12.0.2
--------------------------------------------------

Analysis Results:
==================================================
Total lines read: 15234
Lines processed: 15230

127.0.0.1       appeared 7 times
127.0.0.11      not found in log  
139.12.0.2      appeared 2 times
217.0.22.3      appeared 6 times

Summary:
Total matches found: 15
Target IPs found: 127.0.0.1, 139.12.0.2, 217.0.22.3
Requirements

Perl 5.32+
No external dependencies


💻 PowerShell Active Directory Commands
A comprehensive collection of PowerShell commands for Active Directory administration and security auditing.
Commands Included
Group Management
powershell# 1. Find all AD groups
Get-ADGroup -Filter *

# 2. Check if specific group exists
Get-ADGroup -Identity 'HR'

# 3. List local group members
Get-LocalGroupMember -Identity "Administrators"

# 4. List nested group members
Get-ADGroupMember -Identity 'HR' -Recursive

# 5. Bulk group member lookup
$groupNames = 'HR','Accounting','IT'
foreach ($group in $groupNames) {
    Get-ADGroupMember -Identity $group
}
Authentication & Credentials
powershell# 6. Query with alternate credentials
Get-ADGroup -Identity 'HR' -Credential (Get-Credential)
Advanced Queries
powershell# 7. Get group members with email addresses
Get-ADGroupMember "HR" | Where-Object {$_.objectClass -eq "user"} | ForEach-Object {
    $user = Get-ADUser $_.SamAccountName -Properties EmailAddress
    [PSCustomObject]@{
        Name = $user.Name
        Email = $user.EmailAddress
    }
}

# 8. Filter by group type
Get-ADGroup -Filter {GroupCategory -eq "Security"}

# 9. OU-specific queries (corrected syntax)
Get-ADGroup -Filter '*' -SearchBase 'OU=NYC,OU=Locations,DC=company,DC=pri'

# 10. Export results to CSV
Get-ADGroup -Filter '*' -SearchBase 'OU=NYC,OU=Locations,DC=company,DC=pri' -SearchScope Subtree | Export-Csv -Path 'nyc.csv' -NoTypeInformation
Requirements

Windows PowerShell 5.1+ or PowerShell 7+
Active Directory PowerShell module (RSAT tools)
Appropriate AD permissions
Administrator privileges (for some commands)

Installation
powershell# Install RSAT tools (Windows 10/11)
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# Or install specific AD tools
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"

🚀 Quick Start
Clone the Repository
bashgit clone (https://github.com/ztaseen123/Taseen-Zaman-Cybersecurity-Tools)
cd cybersecurity-tools
File Structure
cybersecurity-tools/
├── README.md
├── password_checker.py
├── port_scanner.py
├── port_scanner.pl
├── apache_log_analyzer.pl
├── powershell_ad_commands.ps1
└── apache_access.log (sample log file)

⚠️ Legal Disclaimer
IMPORTANT: These tools are for educational and authorized testing purposes only.

✅ DO use on your own networks and systems
✅ DO use for authorized penetration testing
✅ DO use for educational learning
❌ DO NOT use on networks without explicit permission
❌ DO NOT use for malicious purposes
❌ DO NOT use to attack systems you don't own

Always ensure you have proper authorization before scanning or testing any network or system.

🤝 Contributing
Contributions are welcome! Please feel free to submit pull requests or open issues for:

Bug fixes
Feature enhancements
Documentation improvements
Additional security tools


📄 License
This project is provided as-is for educational and authorized security testing purposes. Please use responsibly and in accordance with applicable laws and regulations.

🔗 Additional Resources

NIST Cybersecurity Framework
OWASP Testing Guide
Python Socket Programming
Perl Network Programming
PowerShell Active Directory Module


Made with ❤️ for cybersecurity education and ethical hacking
