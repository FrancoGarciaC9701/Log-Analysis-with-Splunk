## Log-Analysis-with-Splunk
We ingested data from the "attack_data" repository found on GitHub and used Splunk to analyze the 10 most common types of attacks.

## Technologies used
- Splunk Enterprise
- Source of the logs: https://github.com/splunk/attack_data/tree/master
- Languages: SPL (Splunk Processing Language)

## SPL queries used
images and brief explanation of the queries used

# Brute Force
![Fuerza bruta](https://github.com/FrancoGarciaC9701/Log-Analysis-with-Splunk/blob/8efc82f424620bd681fdef0d95f2c9145cb49a6b/assets/brute-force1.png)
This shows us the query
![Fuerza bruta]
![Fuerza bruta]
We have several login attempts that give "Success" and then something fails from IP 73.15.72.101. The person at this IP is trying to access with several emails within the "rodsoto.onmicrosoft.com" domain. This is considered a typical brute force attack or credential spoofing procedure. Therefore, the measures to take are:
- Temporarily block the IP and activate MFA
- Create an alert in Splunk to detect similar patterns
- Review the logs for other attack patterns

  
  


    
