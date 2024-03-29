# Alpha-NIDS
A lightweight Network Intrusion Detection Tool.

# Introduction
Alpha-NIDS monitors network in real-time for malicious activity or policy violations.
It monitors , analyzes and alerts the network admin based on suspicious activities within network traffic on different network layers.

# Traffic Monitoring
Can monitor packets that match certain criteria, such as being of type IP, ARP, ICMP, UDP, or specific TCP ports (such as 53, 443, 8443, 80, 8080).

Packet counts per IP are maintained to detect potential high-traffic anomalies.

# Packet Analysis
1. ARP table:
Checks for new devices and potential ARP spoofing.
Alerts and logs if a new device is detected or if an existing IP starts using a different MAC address.
Alerts if a device is not in the whitelist.

2. HTTP packets:
Checks for malicious strings in the host or URI and counts the number of GET requests to send alert in order to prevent DDOS.

3. ICMP packets:
Detects and logs a high number of ICMP packets and sends alert.

4. DNS queries:
Detects and logs DNS queries and potential DNS flood.

# Whitelisting/Blacklisting Mechanism
Devices (MAC addresses) can be whitelisted to avoid false positives.

Blacklists IPs sending abnormal amount of traffic to the network and to its connected devices.

Blacklists MAC addresses previously involved in malicious activities.

# Alerting Mechanism
If packet count from a particular IP crosses the threshold, a potential DDoS attack or an intrusion is logged, and an email alert is triggered which utilizes SMTP to send alerts.

Email configurations are fetched from the 'config.ini' file or the environment variables.

Can send out alert emails when suspicious activities are detected such as mac address not whitelisted, or in the case of an attack on the network.

# Alerting and Error Logging
Alpha-NIDS has an excellent logging mechanism and the logs are stored in the nids_log.log file.

If unable to read configuration throws error : “Missing Configuration for XXXXX” and logs it and does the same job in case of any other type of error.

It shows Non-whitelisted devices in real time.

# Mac Address Spoofing Scenario
Just imagine a case in which an attacker spoofs his mac to a whitelisted device to get into the network so that he doesn’t raise alerts in the network. 

Getting attacked by a whitelisted device can be devastating.

In case of suspicious activity from a whitelisted device, Alpha-NIDS automatically drops the whitelisted device temporarily from the config.ini file and logs it so that the network admin can have a look on it.

The alerts it logs: “Device with MAC xx:xx:xx:xx:xx has been removed from whitelist and blocked”

In case it fails to remove the device it logs error: “Failed to block device: xx:xx:xx:xx:xx" and sends alerts.

# Visualization
The system provides a real-time visualization of packet counts per IP using a bar graph.

It shows Alerts in real time.

# Conclusion
Alpha-NIDS will serve as a lightweight network intrusion detection tool designed to monitor network traffic, identify suspicious activities, and alert administrators either through logs or email notifications. The real-time visualization provides a quick overview of the network's state, making it easier for administrators to gauge potential threats. The whitelisting mechanism ensures that known devices can operate without triggering false positives.

# Usage
1. Run command- git clone https://github.com/smridhgupta/alpha-nids.git
2. Fill in the configuration in the config file.
3. Run command- pip3 install -r requirements.txt
4. Run command-  python3 anids.py

# NOTE
The script has been tested on Linux.

# Configuration & Setup
Setup the configuration in ‘config.ini’ file.
Set the threshold.
Set emails alerts to “True” or “False”.
Set the MAC addresses of the whitelisted devices.
Set the SMTP server config.

# Disclamer
The developer retains the copyright to the script uploaded on this repository. This script is provided for educational and informational purposes only. 

The developer makes no representations or warranties regarding the accuracy or completeness of the script. Users downloading or utilizing the script do so at their own risk and discretion. The developer shall not be liable for any direct, indirect, incidental, special, or consequential damages arising out of the use or inability to use the script.

By downloading or using the script, you agree to abide by the terms and conditions mentioned here. If you have any questions or need further information, please contact the developer Smridh Gupta, Email- smridhgupta@proton.me.

# Donate
. BTC: bc1qykzfyjdkyck5v4sd46j4y8ra6mgltvu6zqu69s

# Warning
This project is only for educational purposes. I am not responsible for any misuse!

# Contact
smridhgupta@proton.me
Developed by @smridhgupta










