# Elastic Security SIEM & Detection Home Lab

## 📌 Overview
Dự án triển khai hệ thống SIEM tập trung sử dụng **Elastic Stack (ELK)** kết hợp **Sysmon** trên Windows Endpoint để thu thập, phân tích log realtime và xây dựng quy trình Threat Hunting bằng ngôn ngữ truy vấn **KQL**.

## 🏗️ Architecture
* **SIEM Server:** Elastic Security (Elasticsearch + Kibana) chạy trên Docker Ubuntu.
* **Endpoint Monitoring:** Windows Client trang bị Sysmon (SwiftOnSecurity Config) + Elastic Agent.
* **Attack Platform:** Kali Linux (Mô phỏng Brute-force & Command Execution).

## 🔍 Tested Use Cases & KQL Queries
1. **Detecting RDP/SMB Brute Force:**
   `event.code: 4625 | stats count by winlog.event_data.TargetUserName`
2. **Detecting Suspicious PowerShell Download:**
   `process.name: "powershell.exe" and process.args: ("*Invoke-WebRequest*" or "*DownloadString*")`
3. **Persistence via Registry Modification:**
   `winlog.channel: "Microsoft-Windows-Sysmon/Operational" and event.code: 13 and registry.path: "*\\CurrentVersion\\Run*"`

## 📊 Dashboards & Artifacts
![Kibana Dashboard](./Kibana-Dashboard.png)
