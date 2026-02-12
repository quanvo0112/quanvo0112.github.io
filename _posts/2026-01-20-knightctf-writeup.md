---
title: KnightCTF 2026
date: 2026-01-20 15:30:00 +0700
categories: [Security, CTF]
tags: [networking, pcap]
---

## Reconnaissance

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

## Gateway Identification
**File:** `pcap1.pcapng`

### 1. Phân tích đề bài
*   **Mục tiêu:** Xác định hãng sản xuất (Vendor) của thiết bị làm **Default Gateway** (Cổng mặc định/Router) trong mạng.
*   **Kiến thức mạng căn bản:**
    *   Trong mô hình mạng, khi một gói tin đi từ Internet (WAN) vào mạng nội bộ (LAN) để đến máy tính đích, nó bắt buộc phải đi qua Router (Gateway).
    *   Tại lớp liên kết dữ liệu (Layer 2 - Ethernet), khi Router chuyển tiếp gói tin đó cho máy tính trong mạng LAN, nó sẽ thay thế địa chỉ **MAC Nguồn (Source MAC)** của gói tin bằng **MAC Address của chính Router**.
    *   **Chiến thuật:** Tìm một gói tin bất kỳ đi từ Internet (Public IP) vào mạng nội bộ, sau đó kiểm tra *Ethernet Source MAC Address* để tìm danh tính của Gateway.

### 2. Các bước giải quyết (Step-by-step)

#### Bước 1: Lọc gói tin từ Internet
Chúng ta cần tìm một gói tin có địa chỉ IP nguồn không thuộc dải mạng nội bộ (`192.168.1.x`).
*   Sử dụng Wireshark, tìm đến gói tin số **1302** (hoặc dùng filter `!ip.src == 192.168.1.0/24`).
*   **Source IP:** `20.42.73.24` (Đây là IP của Microsoft - External).
*   **Destination IP:** `192.168.1.103` (IP máy nạn nhân - Internal).

#### Bước 2: Kiểm tra Ethernet Header
Tại khung chi tiết gói tin (Packet Details) của gói tin **1302**, ta phân tích lớp **Ethernet II**:

*   Quan sát dòng **Source**:
    ```
    Ethernet II, Src: NetisTechnol_38:d7:a0 (88:bd:09:38:d7:a0)
    ```
*   **Phân tích:** Wireshark tự động giải mã 3 byte đầu (OUI) của địa chỉ MAC `88:bd:09...` và hiển thị tên nhà sản xuất là **NetisTechnol**.

#### Bước 3: Xác định Vendor
Từ tên hiển thị "NetisTechnol", ta xác định được vendor của thiết bị Gateway là **Netis**.

### 3. Kết luận
Kẻ tấn công hoặc người dùng đang sử dụng Router của hãng Netis làm Gateway cho mạng này.

**Flag:**
```
KCTF{Netis}
```

## Exploitation
**File:** `pcap2.pcapng`

### 1. Phân tích đề bài
*   **Tình huống:** Kẻ tấn công đã xác định được một ứng dụng web đang chạy trên máy chủ.
*   **Nhiệm vụ:** Tìm **Phiên bản (Version)** của ứng dụng và **Tên người dùng (Username)** bị nhắm mục tiêu.
*   **Flag Format:** `KCTF{version_username}`

### 2. Quá trình phân tích

#### Bước 1: Xác định Ứng dụng Web
Mở file pcap bằng Wireshark và lọc giao thức `http`. Quan sát các đường dẫn (URI) trong các gói tin `GET` và `POST`.
*   Xuất hiện các đường dẫn như: `/wordpress/`, `/wordpress/wp-login.php`, `/wordpress/wp-admin/`.
*   **Kết luận:** Ứng dụng mục tiêu là **WordPress CMS**.

#### Bước 2: Tìm Phiên bản (Version) của ứng dụng
Thông tin phiên bản thường nằm trong mã nguồn HTML của trang chủ (trong thẻ `<meta name="generator">`).

1.  **Filter:** Lọc các gói tin phản hồi thành công từ server:
    ```
    http.response.code == 200
    ```
2.  **Thao tác:**
    *   Chọn một gói tin `HTTP/1.1 200 OK` (ví dụ Frame **55**).
    *   Chuột phải -> **Follow** -> **HTTP Stream** để xem toàn bộ mã nguồn trang web.
3.  **Tìm kiếm:**
    *   Sử dụng tính năng Find (`Ctrl + F`) với từ khóa: `generator`.
    *   **Kết quả:** Tìm thấy dòng code HTML:
        ```html
        <meta name="generator" content="WordPress 6.9" />
        ```
    *   => **Version: 6.9**

#### Bước 3: Tìm Username (Tên người dùng)
Tên người dùng thường bị lộ khi kẻ tấn công thực hiện hành vi dò quét (User Enumeration) hoặc cố gắng đăng nhập (Login). Dữ liệu đăng nhập thường được gửi qua phương thức `POST`.

1.  **Filter:** Lọc các gói tin gửi dữ liệu lên server:
    ```
    http.request.method == POST
    ```
2.  **Phân tích gói tin đăng nhập:**
    *   Tìm đến gói tin POST gửi tới `/wordpress/wp-login.php` (Frame **61991**).
    *   Tại khung **Packet Details**, mở rộng phần **HTML Form URL Encoded**.
    *   Quan sát các trường dữ liệu:
        *   `log` (Username): **`kadmin_user`**
        *   `pwd` (Password): `f750d046`
3.  **Xác nhận:** Trước đó (tại Frame **61960**), kẻ tấn công cũng đã dò quét thành công user này qua đường dẫn `/wordpress/index.php/author/kadmin_user/`.
    *   => **Username: kadmin_user**

### 3. Tổng hợp kết quả

*   Version: `6.9`
*   Username: `kadmin_user`

Ghép theo định dạng `KCTF{version_username}`.

**Flag:**
```
KCTF{6.9_kadmin_user}
```

Chúc mừng bạn đã tìm ra Flag! Đây là một bài học kinh điển về định dạng Flag trong CTF: đôi khi chúng ta tìm đúng thông tin nhưng định dạng (format) yêu cầu thay đổi ký tự đặc biệt (từ `-` sang `_`).

Dưới đây là bản **Write-up (WU)** chi tiết và chuyên nghiệp cho bài này.

---

## Vulnerability Exploitation
**File:** `pcap2.pcapng`

### 1. Phân tích đề bài
*   **Tình huống:** Website bị xâm nhập thông qua một lỗ hổng đã biết (known vulnerability) trong một Plugin.
*   **Nhiệm vụ:** Tìm tên Plugin và Phiên bản (Version) của nó.
*   **Flag Format:** `KCTF{plugin_name_version}` (Lưu ý: định dạng tên plugin có thể thay đổi).

### 2. Quá trình điều tra (Step-by-Step)

#### Bước 1: Sàng lọc hoạt động do thám Plugin
Kẻ tấn công thường bắt đầu bằng việc quét (scan) các thư mục plugin để xem plugin nào được cài đặt và phiên bản của chúng là bao nhiêu. Cách phổ biến nhất là truy cập file `readme.txt` hoặc `changelog.txt`.

*   **Wireshark Filter:**
    ```
    http.request.uri contains "readme.txt"
    ```
*   **Kết quả:** Quan sát danh sách gói tin, ta thấy kẻ tấn công truy cập thành công (HTTP 200 OK) vào file readme của 2 plugin:
    1.  `social-warfare`
    2.  `thim-blocks`

#### Bước 2: Xác định Plugin mục tiêu
Trong hai plugin trên, **Social Warfare** nổi tiếng với lỗ hổng thực thi mã từ xa (RCE - CVE-2019-9978) cực kỳ nghiêm trọng, thường xuyên được sử dụng trong các bài Lab/CTF. Đây là đối tượng tình nghi số 1.

#### Bước 3: Xác định Phiên bản (Version)
Để biết phiên bản chính xác đang chạy trên server, ta cần đọc nội dung phản hồi từ Server khi kẻ tấn công yêu cầu file `readme.txt`.

1.  Tìm gói tin phản hồi **HTTP 200 OK** của yêu cầu `GET /.../social-warfare/readme.txt` (Gói tin số **54295**).
2.  Thao tác: Chuột phải -> **Follow** -> **HTTP Stream**.
3.  Phân tích nội dung: Tìm dòng `Stable tag`.
    ```text
    === WordPress Social Sharing Plugin - Social Warfare ===
    ...
    Stable tag: 3.5.2
    ```
    => **Version: 3.5.2**

#### Bước 4: Xử lý định dạng Flag
*   Tên plugin theo đường dẫn URL (Slug): `social-warfare`
*   Phiên bản: `3.5.2`
*   Thử Flag theo chuẩn thông thường: `KCTF{social-warfare_3.5.2}` -> **Sai**.
*   **Điều chỉnh:** Trong một số bài CTF, format yêu cầu thay đổi ký tự gạch ngang `-` thành gạch dưới `_` trong tên đối tượng để đồng bộ.
*   Thử lại: `social_warfare`.

### 3. Kết luận

*   Plugin: **Social Warfare**
*   Version: **3.5.2**
*   Format tên: **social_warfare**

**Flag:**
```
KCTF{social_warfare_3.5.2}
```

Dưới đây là bài **Write-up (WU)** hoàn chỉnh và chi tiết cho thử thách này. Bạn có thể sử dụng nó để lưu trữ tài liệu hoặc chia sẻ với team.

---

## Post-Exploitation
**File:** `pcap3.pcapng`

### 1. Phân tích đề bài
*   **Tình huống:** Kẻ tấn công đã khai thác thành công lỗ hổng và thiết lập kết nối bền vững (persistent connection) về máy chủ điều khiển (C2).
*   **Nhiệm vụ:**
    1.  Tìm cổng **HTTP** mà kẻ tấn công dùng để gửi file mã độc (payload) xuống máy nạn nhân.
    2.  Tìm cổng **TCP** mà máy nạn nhân kết nối ngược về (Reverse Shell).
*   **Flag Format:** `KCTF{httpPort_revshellPort}`

### 2. Quá trình điều tra (Step-by-Step)

#### Bước 1: Xác định HTTP Port (Payload Delivery)
Kẻ tấn công thường lừa máy nạn nhân tải về một file script (ví dụ: `.sh`, `.php`, `.txt`) thông qua giao thức HTTP.

1.  **Filter:** Lọc các yêu cầu tải file từ máy nạn nhân (`192.168.1.102`):
    ```
    http.request.method == GET && ip.src == 192.168.1.102
    ```
2.  **Phân tích:**
    *   Tại gói tin số **77254** (Time: `882.308`), ta thấy một yêu cầu đáng ngờ:
        `GET /payload.txt?swp_debug=get_user_options HTTP/1.1`
    *   Đây là hành vi khai thác lỗ hổng Social Warfare để tải file `payload.txt`.
3.  **Xác định Port:**
    *   Để biết Port, ta nhìn vào quá trình bắt tay TCP (3-way handshake) xảy ra ngay trước gói tin HTTP này.
    *   Tại gói tin số **77251** (Time: `882.306`), máy nạn nhân gửi gói `SYN` đến máy tấn công (`192.168.1.104`).
    *   Cổng đích (Destination Port) là: **8767**.
    *   => **HTTP Port: 8767**.

#### Bước 2: Xác định Reverse Shell Port
Sau khi file `payload.txt` được tải về và thực thi, nó sẽ kích hoạt một kết nối ngược (Reverse Shell) từ máy nạn nhân về máy tấn công để kẻ tấn công có thể gõ lệnh điều khiển.

1.  **Filter:** Lọc các kết nối TCP mới được khởi tạo từ máy nạn nhân đến máy tấn công (bỏ qua cổng HTTP vừa tìm được):
    ```
    tcp.flags.syn == 1 && ip.src == 192.168.1.102 && ip.dst == 192.168.1.104
    ```
2.  **Phân tích:**
    *   Quan sát mốc thời gian: Reverse Shell phải xảy ra **sau** khi tải payload.
    *   Ngay sau gói tin tải payload (Time `882.308`), tại gói tin số **77261** (Time `882.384`), xuất hiện một kết nối mới.
3.  **Xác định Port:**
    *   Gói tin `39582 -> 9576 [SYN]` cho thấy máy nạn nhân đang chủ động kết nối đến cổng **9576** của kẻ tấn công.
    *   Đây là cổng lắng nghe (Listening Port) của Reverse Shell.
    *   => **RevShell Port: 9576**.

### 3. Kết luận

*   **HTTP Port:** 8767
*   **Reverse Shell Port:** 9576

Ghép theo định dạng `KCTF{httpPort_revshellPort}`:

**Flag:**
```
KCTF{8767_9576}
```

Dưới đây là bản **Write-up (WU)** hoàn chỉnh cho thử thách cuối cùng này. Bạn có thể sử dụng nội dung này để tổng hợp lại quá trình điều tra của mình.

---

## Database Credentials Theft
**File:** `pcap3.pcapng`

### 1. Phân tích đề bài
*   **Tình huống:** Sau khi chiếm quyền điều khiển hệ thống (Post-Exploitation), kẻ tấn công đã tìm cách đánh cắp thông tin đăng nhập Cơ sở dữ liệu (Database).
*   **Mục tiêu:** Tìm Username và Password của Database.
*   **Kiến thức cơ sở:** Trên hệ thống mã nguồn mở WordPress, thông tin cấu hình Database luôn được lưu trữ trong tệp tin **`wp-config.php`**. Kẻ tấn công thường đọc file này ngay sau khi có quyền truy cập shell.

### 2. Quá trình điều tra (Step-by-Step)

#### Bước 1: Xác định luồng dữ liệu (Traffic) cần phân tích
Dựa trên kết quả của thử thách trước, ta đã xác định được kết nối Reverse Shell (kết nối dòng lệnh từ xa) giữa máy nạn nhân và kẻ tấn công đang diễn ra trên cổng TCP **9576**.
*   **Filter Wireshark:**
    ```
    tcp.port == 9576
    ```

#### Bước 2: Tái tạo phiên làm việc (TCP Stream)
Để xem kẻ tấn công đã gõ lệnh gì và server trả về kết quả gì, ta cần tái tạo lại luồng dữ liệu dưới dạng văn bản thuần.
*   **Thao tác:** Chuột phải vào bất kỳ gói tin nào sau khi lọc -> Chọn **Follow** -> **TCP Stream**.

#### Bước 3: Trích xuất thông tin nhạy cảm
Trong cửa sổ TCP Stream, ta thấy toàn bộ nội dung hiển thị trên màn hình Terminal của kẻ tấn công.
*   **Quan sát:** Kẻ tấn công đã thực hiện lệnh (ví dụ: `cat wp-config.php`) để in nội dung file cấu hình ra màn hình.
*   **Tìm kiếm:** Tìm đến đoạn định nghĩa hằng số kết nối Database (thường bắt đầu bằng `DB_USER` và `DB_PASSWORD`).

**Kết quả tìm thấy trong stream:**
```php
/** MySQL database username */
define( 'DB_USER', 'wpuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'wp@user123' );
```

#### Bước 4: Tổng hợp Flag
*   Database Username: **wpuser**
*   Database Password: **wp@user123**

Ghép theo định dạng yêu cầu `KCTF{username_password}`.

### 3. Kết luận

**Flag:**
```
KCTF{wpuser_wp@user123}
```