# brixgate-soc-automation-lab
Enterprise SOC automation lab featuring ICMP traffic capture, AI-driven threat analysis, and automated response workflows

Brixgate SOC Automation Lab

A hands-on SOC automation lab focused on building a lightweight detection and triage workflow for suspicious network activity.

This project demonstrates how to capture ICMP traffic from a Linux host, identify abnormal packet spikes, and forward the findings to an AI-assisted SOC workflow for triage and escalation. The lab combines network telemetry, a structured SOC playbook, and automated response logic to simulate real-world analyst operations.

Key Highlights:

ICMP traffic capture and monitoring using tshark on Kali Linux
PCAP-to-CSV conversion and packet anomaly detection
Threshold-based alerting for unusually high ICMP volume
SOC triage workflow using a structured playbook
Risk scoring based on packet volume, timing, and service exposure
MITRE ATT&CK mapping for the detected activity
Analyst action planning for monitoring, enrichment, escalation, and containment
Airia AI agent integration for automated SOC analysis and response recommendations
Project Components:

TrafficCapture.py — captures ICMP traffic and exports relevant metadata
SOC playbook — defines validation, classification, scoring, escalation rules, and response steps
AI-driven workflow — sends alert data to an AI agent for triage support
Flowchart — illustrates the end-to-end lab architecture and process
This lab is designed to showcase a practical SOC pipeline: Network capture → alert generation → enrichment → classification → risk scoring → MITRE mapping → analyst response.

Built to explore AI-assisted security operations, automated triage, and defensive workflow design in a lab environment.

#CyberSecurity #SOC #ThreatDetection #BlueTeam #MITREATTACK #Automation #Python #Splunk #AI #KaliLinux
