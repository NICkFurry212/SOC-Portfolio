# Incident Response Playbook: Phishing Attack

## 1. Scope & Objective
Quy trình xử lý sự cố khi người dùng nhận email lừa đảo (Phishing), click vào link độc hại hoặc mở file đính kèm chứa Malware/Macro.

## 2. Detection & Analysis
### Indicators of Compromise (IoC)
* **Email Artifacts:** Mismatch Sender Domain, SPF/DKIM/DMARC Fail, Tiêu đề giật gân, Link ẩn danh (Bit.ly, TinyURL).
* **Endpoint Artifacts:** File đính kèm dạng `.xlsm`, `.iso`, `.exe`, `.js` chạy ngầm.
* **Network Artifacts:** Kế nối outbound bất thường tới các IP/Domain C2 lạ.

### Investigation Steps
1. Khai thác thông tin Email Header (Sender IP, Return-Path, Authentication-Results).
2. Kiểm tra Hash của file đính kèm trên VirusTotal / Hybrid Analysis.
3. Truy vấn SIEM tìm các User khác nhận cùng Email này:
   * **Elastic KQL:** `email.subject: "*Important Invoice*"` hoặc `email.sender: "attacker@domain.com"`
4. Kiểm tra xem nạn nhân đã thực thi file chưa (Sysmon Event ID 1 - Process Creation):
   * `process.parent.name: "WINWORD.EXE" or process.parent.name: "EXCEL.EXE"`

## 3. Containment & Eradication
### Containment (Cô lập)
* **Email Gateway:** Purge/Delete email độc hại khỏi toàn bộ Hòm thư công ty.
* **Network:** Block Sender Domain / Sender IP / URL trên Email Gateway & Firewall.
* **Host Level:** Nếu nạn nhân đã mở file độc $\rightarrow$ Isolate Host khỏi mạng LAN lập tức.

### Eradication & Recovery
* Revoke Active Sessions & Reset Password tài khoản nạn nhân (nếu là Phishing Credential Theft).
* Chạy Antivirus / EDR Full Scan trên máy nạn nhân.
* Khai báo bổ sung IOC vào Cơ sở dữ liệu Threat Intel của công ty.

## 4. Post-Incident & Lessons Learned
* Tổ chức đào tạo Security Awareness cho nhân sự vừa dính Phishing.
* Tối ưu hóa DMARC/SPF policy lên `Reject`.
