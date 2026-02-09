---
title: KnightCTF 2026
date: 2026-01-20 15:30:00 +0700
categories: [Security, CTF]
tags: [networking, pcap]
---

# Reconnaissance

**Category:** Network Forensics  
**File:** `pcap1.pcapng`

### 1. Phân tích đề bài
*   **Tình huống:** Hệ thống IDS phát hiện hoạt động quét mạng (scanning) nhắm vào cơ sở hạ tầng công ty.
*   **Nhiệm vụ:** Xác định có bao nhiêu cổng (ports) được tìm thấy là **Mở (Open)** trên hệ thống đích.
*   **Kiến thức cơ bản:** Trong kỹ thuật TCP Connect Scan hoặc SYN Scan, để biết một cổng có mở hay không, kẻ tấn công gửi gói `SYN`. Nếu cổng mở, máy nạn nhân sẽ phản hồi bằng gói **`SYN, ACK`**.

### 2. Các bước giải quyết

#### Bước 1: Lọc gói tin phản hồi "Cổng Mở"
Mở file bằng Wireshark. Để tìm các cổng mở, ta cần lọc các gói tin mà máy đích phản hồi lại cho kẻ tấn công chấp nhận kết nối. Filter cần dùng là:
```
tcp.flags.syn == 1 && tcp.flags.ack == 1
```

#### Bước 2: Xác định IP Mục tiêu (Target) và Loại bỏ nhiễu
Sau khi lọc (như trong hình ảnh đính kèm), ta quan sát cột **Source** và **Info**:

1.  **Quan sát IP Source (Nguồn):**
    *   Ta thấy IP **`192.168.1.102`** xuất hiện liên tục trong cột Source, gửi phản hồi về cho `192.168.1.104` và `192.168.1.110`. Điều này chứng tỏ `192.168.1.102` là máy nạn nhân đang bị quét.
    *   Các IP khác như `20.42.73.24`, `151.101...`, `57.155...`: Đây là các địa chỉ Public IP (Internet) phản hồi cổng 443 (HTTPS). Đây là lưu lượng duyệt web thông thường của người dùng trong mạng ra Internet (Noise), không phải là kết quả của việc Attacker quét hệ thống nội bộ công ty. Ta **loại bỏ** các IP này.

2.  **Đếm số Port mở trên `192.168.1.102`:**
    Nhìn vào cột **Info** hoặc chi tiết gói tin của các dòng có Source là `192.168.1.102`:
    *   **Port 80:** Xuất hiện rất nhiều lần (Ví dụ: dòng 124, 126, 7656...).
        *   Gói tin: `80 -> [Port_Attacker] [SYN, ACK]`.
    *   **Port 22:** Xuất hiện tại dòng số **9582**.
        *   Gói tin: `22 -> 53810 [SYN, ACK]`.

#### Bước 3: Tổng hợp kết quả
Chỉ có 2 cổng duy nhất từ máy đích `192.168.1.102` phản hồi cờ `SYN, ACK` là:
1.  Port **80** (HTTP)
2.  Port **22** (SSH)

Các port 443 đến từ IP lạ bên ngoài Internet nên không tính.

### 3. Kết luận

Tổng số cổng mở tìm thấy là: **2**.

**Flag:**
```
KCTF{2}
```