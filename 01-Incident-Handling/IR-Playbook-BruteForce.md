# Incident Response Playbook: RDP / Active Directory Brute-Force

## 1. Scope & Objective
Phát hiện và xử lý các đợt tấn công dò quét mật khẩu (Brute Force / Password Spraying) hướng vào máy chủ RDP hoặc Active Directory Domain Controller.

## 2. Detection & Analysis
### Detection Rules / Queries
* **Windows Event ID:**
  * `4625`: Failed Logon.
  * `4624`: Successful Logon (Cần chú ý nếu có 4624 ngay sau hàng loạt 4625).
  * `4740`: User Account Locked Out.

### Investigation Queries
* **Elastic KQL (Tìm IP đang Brute Force):**
  `event.code: 4625 | stats count by winlog.event_data.IpAddress`
* **Tiêu chí đánh giá Alert:**
  * **False Positive:** 1-3 lần logon sai từ IP nội bộ (User gõ nhầm pass).
  * **True Positive:** >50 lần logon sai trong 5 phút từ một IP lạ hoặc ngoài Internet.

## 3. Containment & Eradication
1. **Block Source IP:** Thêm IP tấn công vào Blacklist của Firewall / Edge Router.
2. **Account Protection:**
   * Tạm thời Disable tài khoản bị nhắm tới nếu có dấu hiệu bị Compromised.
   * Yêu cầu đổi mật khẩu mới có độ phức tạp cao hơn.
3. **Host Isolation:** Nếu phát hiện Event 4624 (đăng nhập thành công) sau một chuỗi 4625 $\rightarrow$ Cô lập ngay host đó để kiểm tra xem attacker đã drop malware chưa.

## 4. Post-Incident
* Bật Multi-Factor Authentication (MFA) cho toàn bộ dịch vụ RDP/VPN.
* Cấu hình Account Lockout Policy trong Group Policy (GPO) (Ví dụ: Khóa tài khoản 15 phút sau 5 lần nhập sai).
