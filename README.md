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


Analizando los eventos nos damos cuenta de dos cosas:
1. Tiene solicitudes GET y POST, es decir, que estuvo mandando solicitudes POST a través de una URL sospechosa hasta que consiguió entrar y de ahí ya mandar solicitudes GET
2. Que la URL sospechosa venía cargada con diferentes payloads y la categoría "threatname" mostraba la amenaza detectada


    
