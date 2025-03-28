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









