![alt tag](https://user-images.githubusercontent.com/24201238/29351849-9c3087b4-82b8-11e7-8fed-350e3b8b4945.png)

# Panopticon Project

## Patchwork

## Aliases
* [Dropping Elephant](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)
* [Chinastrats](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)
* [Capricorn Organisation](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)
* [APT-C-09](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)
* [Viceroy Tiger](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml#)

## Overview
A high level summary of the threat actor

## Attack Pattern
A type of Tactics, Techniques, and Procedures (TTP) that describes ways threat actors attempt to compromise targets.

## Campaign 
A grouping of adversarial behaviors that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.

## Course of Action 
An action taken to either prevent an attack or respond to an attack.

## Identity
Individuals, organizations, or groups, as well as classes of individuals, organizations, or groups.

## Indicator
Contains a pattern that can be used to detect suspicious or malicious cyber activity.

## Intrusion Set
A grouped set of adversarial behaviors and resources with common properties believed to be orchestrated by a single threat actor.

## Malware
A type of TTP, also known as malicious code and malicious software, used to compromise the confidentiality, integrity, or availability of a victim’s data or system.

## Observed Data
Conveys information observed on a system or network (e.g., an IP address).

## Report 
Collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including contextual details.

## Threat Actor 
Individuals, groups, or organizations believed to be operating with malicious intent.

## Tool
Legitimate software that can be used by threat actors to perform attacks.

## Vulnerability
A mistake in software that can be directly used by a hacker to gain access to a system or network.

## Raw Intelligence
http://www.securityweek.com/patchwork-cyberspies-adopt-new-exploit-techniques
December 12, 2017 
Also known as Dropping Elephant or Chinastrats and believed to be operating out of the Indian subcontinent, the group is said to have been active since 2014. Initially focused on government-associated organizations that have connections to Southeast Asia and the South China Sea, the actor has expanded its target list to include entities in a broad range of industries. 
The observed campaigns focused on multiple sectors in China and South Asia, but also hit organizations in the U.K., Turkey, and Israel. Using spear-phishing emails, the cyberespionage group targeted high-profile personalities, business-to-consumer (B2C) online retailers, telecommunications and media companies, aerospace researchers, and financial institutions. The United Nations Development Programme was targeted as well.
The spear-phishing emails contained website redirects, direct links, or malicious attachments. Some emails contained direct links to malicious documents hosted on the attacker-owned servers. The group spoofed a news site and used it to divert visitors to socially engineered, malware-ridden documents and was also observed misusing email and newsletter distribution services.

A fake Youku Tudou website (a social video platform popular in China) was used for drive-by downloads. The victim was tricked into downloading and executing a fake Adobe Flash Player update that was, in fact, a variant of the xRAT Trojan.

Patchwork was also observed phishing for credentials to take over a target’s emails and other online accounts. One attack copied a webpage from a legitimate web development company and displayed the fake page to victims alone.

Using Rich Text Format (RTF) documents, the group exploited vulnerabilities such as CVE-2012-1856 – a remote code execution (RCE) in the Windows common control MSCOMCTL, or CVE-2015-1641 – a memory corruption in Microsoft Office. They also exploited the CVE-2014-4114 Sandworm RCE vulnerability in Windows’ Object Linking and Embedding (OLE) via PowerPoint (PPSX) files.

More recent vulnerabilities the actor has been abusing include CVE-2017-0199 – an RCE in Microsoft Office’s Windows OLE, patched in April 2017, and CVE-2017-8570 – an RCE in Microsoft Office patched in July 2017. They were exploited via PowerPoint (PPT) and PPSX files.

The malicious PPSX files exploiting CVE-2017-8570 downloaded a Windows Script Component (SCT) file from a Patchwork-owned server to eventually deliver the xRAT malware. 

The threat actor was observed dropping malware such as the NDiskMonitor custom backdoor (believed to be Patchwork’s own, it can list files and logical drives and download and execute files from specified URLs); and Socksbot, which can start Socket Secure (SOCKS) proxy, take screenshots, and run executables and PowerShell scripts.

Malware such as the xRAT remote access tool (its source code is available online) and the Badnews backdoor (potent information-stealing and file-executing malware) were also associated with the group’s activities, as well as a series of file stealers (Taskhost Stealer and Wintel Stealer targeting .doc, .docx, .xls, .xlsx, .ppt, .pptx, .pdf, and RTF files, along with .eml and .msg email messages; as well as versions of file stealers written in AutoIt). 

The group has been using publicly available PHP scripts for retrieving files from the server without disclosing their real paths, likely to prevent security researchers from finding open directories. Trend Micro also observed the group temporarily removing a file so it could not be retrieved or replacing it with a legitimate one. Sometimes they would display “a fake 302 redirection page to trick researchers into thinking the files are gone.”

https://www.securityweek.com/patchwork-cyberspies-update-badnews-backdoor
March 13, 2018 
Patchwork campaigns Palo Alto Networks has observed over the past few months have been targeting entities in the Indian subcontinent and revealed the use of legitimate but malicious documents to deliver an updated BADNEWS payload. 

The malware, which has been updated since the last public report in December 2017, provides attackers with full control over the victim machine and is known to abuse legitimate third-party websites for command and control (C&C). The new version shows changes in the manner the C&C server information is fetched, as well as modifications to its communication routine. 
The campaigns featured malicious documents with embedded EPS files targeting two vulnerabilities in Microsoft Office, namely CVE-2015-2545 and CVE-2017-0261.
When executed, shellcode embedded within the malicious EPS drops three files: VMwareCplLauncher.exe (a legitimate, signed VMware executable to deliver the payload), vmtools.dll (a modified DLL to ensure persistence and load the malware), and MSBuild.exe (which is the BADNEWS backdoor itself). 

VMwareCplLauncher.exe is executed first, to load the vmtools.dll DLL, which in turn creates a scheduled task to attempt to run the malicious, spoofed MSBuild.exe every subsequent minute.

Once up and running on the infected machine, the backdoor communicates with the C&C over HTTP and allows attackers to download and execute files, upload documents of interest, and take screenshots of the desktop.

The recently observed variation of the backdoor sets a new mutex to ensure only one instance of the backdoor is running, and also uses different filenames from the previous versions. The manner in which the C&C information stored via dead drop resolvers is obfuscated has been changed as well, the security researchers say. 
Although it performs many of the functions associated with previous versions, the new variant no longer searches USB drives for files that might be of interest. When preparing C&C communication, the malware aggregates victim information and appends it to two strings. 
The C&C communication has been updated as well, now offering support for commands such as kill (the backdoor); upload a file containing the list of interesting files and spawn a new instance of Badnews; upload a specified file; upload a file containing the list of collected keystrokes; copy a file to a .tmp and send it to the C&C; take a screenshot and send it to the C&C; and download a file and execute it. 

https://www.securityweek.com/patchwork-cyberspies-target-us-think-tanks
June 08, 2018
Patchwork has shown an increase in activity recently, and also started using unique tracking links in their phishing emails, to identify which recipients opened their messages
The security firm observed three spear-phishing campaigns launched by the group, “leveraging domains and themes mimicking those of well-known think tank organizations in the United States.” The actors used articles and themes from the Council on Foreign Relations (CFR), the Center for Strategic and International Studies (CSIS), and the Mercator Institute for China Studies (MERICS) as lures, along with malicious Rich Text Format (RTF) documents. 

The attacks shared the use of email recipient tracking, a linked RTF document, and the final payload, but various elements in each campaign were different

The group apparently used publicly available exploit code from Github to deploy the freely available QuasarRAT.

Written in C#, the remote access tool (RAT) provides AES encryption of network communication, file management, the ability to download, upload, and execute files, keylogging, remote desktop access, remote webcam viewing, reverse proxy, and browser and FTP client password recovery, among other capabilities. 

The malware achieves persistence by creating a scheduled task that points to the QuasarRAT binary (saved on disk as microsoft_network.exe). The scheduled task, named Microsoft_Security_Task, runs at 12:00 AM each day, then repeats every 5 minutes for 60 days. 

When executed, the malware first attempts to determine the geographical location of the infected host, then starts beaconing over an encrypted connection to the command and control domain. 

## Links

https://blog.trendmicro.com/trendlabs-security-intelligence/the-urpage-connection-to-bahamut-confucius-and-patchwork/, 

https://blog.trendmicro.com/trendlabs-security-intelligence/deciphering-confucius-cyberespionage-operations/

http://normanshark.com/wp-content/uploads/2013/08/NS-Unveiling-an-Indian-Cyberattack-Infrastructure_FINAL_Web.pdf	

https://www.cymmetria.com/patchwork-targeted-attack/	

https://blogs.forcepoint.com/security-labs/monsoon-analysis-apt-campaign	

https://securelist.com/the-dropping-elephant-actor/75328/	

http://blog.trendmicro.com/trendlabs-security-intelligence/untangling-the-patchwork-cyberespionage-group/	

http://www.sohu.com/a/211497788_764248	

https://ti.360.net/blog/articles/analysis-of-apt-c-09-target-china/	

https://www.securityweek.com/india-linked-threat-actor-targets-military-political-entities-worldwide

https://www.securityweek.com/dropping-elephant-new-and-growing-cyber-espionage-group

https://www.securityweek.com/monsoon-cyber-espionage-campaign-linked-patchwork-apt

https://www.securityweek.com/patchwork-threat-actor-expands-target-list

https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf

https://researchcenter.paloaltonetworks.com/2018/03/unit42-patchwork-continues-deliver-badnews-indian-subcontinent/

https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/

https://github.com/c4bbage/xRAT

https://github.com/quasar/QuasarRAT

https://blog.trendmicro.com/trendlabs-security-intelligence/confucius-update-new-tools-and-techniques-further-connections-with-patchwork/

https://cybleinc.com/2021/01/20/a-deep-dive-into-patchwork-apt-group/

https://blog.malwarebytes.com/threat-intelligence/2022/01/patchwork-apt-caught-in-its-own-web/

https://www.securityweek.com/researchers-draw-connections-between-apts

https://www.zdnet.com/article/new-novel-android-spyware-linked-to-pro-india-confucius-threat-group/

https://news.softpedia.com/news/pakistani-military-targeted-by-confucius-with-pegasus-spyware-lures-533823.shtml
