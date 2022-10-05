# IBM-Cybersecurity-Fundamentals
Course
This badge earner demonstrates a foundational understanding of cybersecurity concepts, objectives, and practices. 

This includes 

- cyber threat groups
- types of attacks
- social engineering
- case studies
- overall security strategies
- cryptography, 
- common approaches that organizations take to prevent, detect, and respond to cyber attacks. 

This also includes an awareness of the job market. 

Badge earners can use this knowledge to pursue further education for a variety of roles in cybersecurity.


-- Cyber threat groups

Outsider threats

External cyber threats include:

    Organized criminals or criminal groups
    Professional hackers, like state-sponsored actors
    Amateur hackers, like hacktivists

Insider threats

Insider threats are users who have authorized and legitimate access to a company's assets and abuse them either deliberately or accidentally. 
They include:

    Employees careless of security policies and procedures
    Disgruntled current or former employees
    Business partners, clients, contractors or suppliers with system access



-- Types of attacks

- Backdoor Trojan

A backdoor Trojan creates a backdoor vulnerability in the victim's system, allowing the attacker to gain remote, and almost total, control. Frequently used to link up a group of victims' computers into a botnet or zombie network, attackers can use the Trojan for other cybercrimes.

- Cross-site scripting (XSS) attack

XSS attacks insert malicious code into a legitimate website or application script to get a user's information, often using third-party web resources. Attackers frequently use JavaScript for XSS attacks, but Microsoft VCScript, ActiveX and Adobe Flash can be used, too.

- Denial-of-service (DoS)

DoS and Distributed denial-of-service (DDoS) attacks flood a system's resources, overwhelming them and preventing responses to service requests, which reduces the system's ability to perform. Often, this attack is a setup for another attack.

- DNS tunneling

Cybercriminals use DNS tunneling, a transactional protocol, to exchange application data, like extract data silently or establish a communication channel with an unknown server, such as a command and control (C&C) exchange.

- Malware

Malware is malicious software that can render infected systems inoperable. Most malware variants destroy data by deleting or wiping files critical to the operating system's ability to run.

- Phishing

Phishing scams attempt to steal users' credentials or sensitive data like credit card numbers. In this case, scammers send users emails or text messages designed to look as though they're coming from a legitimate source, using fake hyperlinks.

- Ransomware

Ransomware is sophisticated malware that takes advantage of system weaknesses, using strong encryption to hold data or system functionality hostage. Cybercriminals use ransomware to demand payment in exchange for releasing the system. A recent development with ransomware is the add-on of extortion tactics.


- SQL injection

Structured Query Language (SQL) injection attacks embed malicious code in vulnerable applications, yielding backend database query results and performing commands or similar actions that the user didn't request.

- Zero-day exploit

Zero-day exploit attacks take advantage of unknown hardware and software weaknesses. These vulnerabilities can exist for days, months or years before developers learn about the flaws.



    DoS, DDoS and malware attacks can cause system or server crashes.
    DNS tunneling and SQL injection attacks can alter, delete, insert or steal data into a system.
    Phishing and zero-day exploit attacks allow attackers entry into a system to cause damage or steal valuable information.
    Ransomware attacks can disable a system until the company pays the attacker a ransom.

An effective cybersecurity system prevents, detects and reports cyberattacks using key cybersecurity technologies and best practices, including:

    Identity and access management (IAM)
    A comprehensive data security platform
    Security information and event management (SIEM)
    Offensive and defensive security services and threat intelligence

Targets:

Business financial data
Clients lists
Customer financial data
Customer databases, including personally identifiable information (PII)
Email addresses and login credentials
Intellectual property, like trade secrets or product designs
IT infrastructure access
IT services, to accept financial payments
Sensitive personal data
US government departments and government agencies

Four steps for threat prevention

- Secure the perimeter
next-generation firewalls (NGFWs) integrate Advanced Malware Protection (AMP), Next-Generation Intrusion Prevention System (NGIPS), Application Visibility and Control (AVC), and URL filtering to provide a multilayered approach.

- Protect users wherever they work
virtual private networks (VPNs) and user verification and device trust can immediately improve mobile device security.

- Smart network segmentation
A DMZ Network is a perimeter network that protects and adds an extra layer of security to an organization's internal local-area network from untrusted traffic. A common DMZ is a subnetwork that sits between the public internet and private networks. 
The end goal of a DMZ is to allow an organization to access untrusted networks, such as the internet, while ensuring its private network or LAN remains secure.
It is ideally located between two firewalls, if an attacker is able to penetrate the external firewall and compromise a system in the DMZ, they then also have to get past an internal firewall before gaining access to sensitive corporate data.

- Find and control problems fast
Recommended an incident response plan and test current network solutions with penetration testing.
Types of threat prevention and detection solutions

NextGen FW
NextGen IPS
Advanced Malware Protection
Application Visibility and Control (AVC) technology
Deep packet inspection (DPI)
Threat intelligence
User verification and device trust (Network access control and Two-factor authentication)



-- Social Engineering

Social engineering is not a cyber attack. Instead, social engineering is all about the psychology of persuasion: It targets the mind like your old school grifter or con man. The aim is to gain the trust of targets, so they lower their guard, and then encourage them into taking unsafe actions such as divulging personal information or clicking on web links or opening attachments that may be malicious.

Types:

- Phishing

- Watering hole attacks

- Business email compromise attacks

- Physical social engineering

- USB baiting


-- Security strategies

IT security is a set of cybersecurity strategies that prevents unauthorized access to organizational assets such as computers, networks, and data. It maintains the integrity and confidentiality of sensitive information, blocking the access of sophisticated hackers.


Types of IT security

- Network security
- Internet security
- Endpoint security
- Cloud security
- Application security


Working from anywhere, combined with enterprises' move to SaaS and the cloud, has effectively rendered the perimeter security model obsolete and traditional security defenses ineffective
An open approach is required to address the fragmentation and complexity challenges facing security teams today as they adopt a zero trust strategy. 

Security zero trust help address the following business initiatives:

    Preserve customer privacy
    Secure the hybrid and remote workforce
    Reduce the risk of insider threat
    Protect the hybrid cloud

-- Cryptography


https://www.ibm.com/docs/en/i/7.4?topic=cryptography-concepts

https://www.ibm.com/docs/en/ibm-mq/7.5?topic=concepts-cryptography


-- Prevent, detect, and respond to cyber attacks. 

Security operations centers (SOCs) and security teams can detect and respond to cyber threats before they become active and affect the organization. Even so, you should still have an incident response plan in place for when an incident occurs. This allows your team to isolate, respond to, and bounce back from cybersecurity incidents.        

To arrange a timely and appropriate response, SOC teams must understand the particular cyber threat. Using frameworks such as MITRE ATT&CK can assist security teams with their understanding of adversaries and how they work, making threat response and detection faster. 

SOC analysts can also gain a significant advantage from using advanced tools including behavioral analytics (UEBA) and threat hunting capabilities, which can help with proactive threat detection.  

Security organizations use sophisticated tools to detect and prevent threats. In the traditional security operations center (SOC), the main system used to collect threat data and detect threats was the security information and event management (SIEM) system. Increasingly, organizations are transitioning to AI solutions, which can improve detection of evasive threats, automate investigation, and enable direct response to threats.

On the prevention side, a range of advanced threat protection technologies that leverage artificial intelligence (AI) are helping detect threats, even if they do not match a known malware or attack signature. These include NGAV, user behavior rules, and ransomware protection.

Threat Prevention Solutions 

Here are some useful tools for detecting and preventing security threats.

    Next-Generation Antivirus (NGAV)
    User Behavior Analytics (UBA)
    Deception Technology
    Ransomware Protection
    Vulnerability Scanning

Traditionally, threat detection was based on technologies like security information and event management (SIEM), network traffic analysis (NTA), and endpoint detection and response (EDR). 

SIEM systems collect security-data from across the enterprise and generate reports and security alerts, but they are limited in their ability to perform in-depth analysis of these events, and combine them into a meaningful attack story. Traditional SIEMs are also not able to directly respond to threats. 

NTA, EDR and similar solutions are highly effective at detecting threats in specific silos within the IT environment, and enable teams to rapidly respond to them. 

AI solutions are a new security paradigm that combines the strengths of traditional solutions. Like SIEM, it collects data from multiple security silos. Like NTA and EDR, it enables in-depth investigation and direct response to threats discovered in the environment. They collects in-depth data from networks, endpoints, cloud systems, email systems, and other resources. 

They uses artificial intelligence (AI) and threat intelligence to identify threats and construct a full attack story, which security teams can easily visualize, and quickly act upon. It integrates with IT systems and security tools, enabling security teams to identify an incident, investigate it, and rapidly respond from the same interface.

End-to-End Prevention & Detection 

    Endpoint protection – multi-layered defense including NGAV, protecting against malware, ransomware, exploits and fileless attacks
    Network protection – protecting against scanning attacks, MITM, lateral movement and data exfiltration 
    User protection – preset behavior rules coupled with dynamic behavior profiling to detect malicious anomalies  
    Deception – wide array of network, user, file decoys to lure advanced attackers into revealing their hidden presence 


SOAR Layer: Response Automation 

    Investigation – automated root cause and impact analysis 
    Findings – actionable conclusions on the attack’s origin and its affected entities
    Remediation – elimination of malicious presence, activity and infrastructure across user, network and endpoint attacks 
    Visualization – intuitive flow layout of the attack and the automated response flow 

MDR Layer: Expert Monitoring and Oversight

    Alert monitoring – First line of defense against incoming alerts, prioritizing and notifying customer on critical events
    Attack investigation – Detailed analysis reports on the attacks that targeted the customer 
    Proactive threat hunting – Search for malicious artifacts and IoC within the customer’s environment 
    Incident response guidance – Remote assistance in isolation and removal of malicious infrastructure, presence and activity  


