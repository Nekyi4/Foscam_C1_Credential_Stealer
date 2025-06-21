# Foscam_C1_Credential_Stealer
A proof of concept project that explores the vulnerabilities of the FOSCAM C1 camera.

Quick video presentation - https://youtu.be/xT1AmdON0yg

Introduction
The aim of this project is to find vulnerabilities that would allow a potential attacker to gain unauthorized access to the camera feed of an IP camera. The specific model used in this project is the Foscam C1 IP camera. The access will be gained by exploiting the vulnerability of the credentials being sent in plain text during the communication between the Foscam plugin, software that is required to access Foscam cameras, and user’s browser. The tool will extract these credentials during this communication, and with them we will be able to gain access to the camera.

Tool Capabilities
The tool is fully automatic and has two main modes:
• Offline analysis - will attempt to extract the credentials from a pcapg file.
• Live sniffing - will attempt to sniff and extract the credentials during a live authentication attempt on the current machine.

Note
This is only a project that explores the vulnerabilities of the FOSCAM camera and was developed to help me refine my skills in cybersecurity. Please do not use it with malicious intentions or any other way that would break the law.
