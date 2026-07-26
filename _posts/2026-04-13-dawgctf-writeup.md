---
title: DawgCTF 2026
date: 2026-04-13 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, osint, misc]
math: true
image:
  path: /assets/img/DawgCTF2026/logo.png
---

> OSINT của giải này như bài CIA Entry Test trên Tryhackme, độ khó trải đều không nặng đô quá cho việc OSINT. Và giải này được host trên MetaCTF nên là việc viết WU phải chăm chỉ xíu.  

## **Misc**

### **Frequency 3000**
- Tác giả: Jebloo
- Mô tả:

One of my favorite TV shows of all time has to be Futurama. I decided to hide a message that can be solved by frequenting its pilot episode. Good luck and remember to drink lots of Slurm, "it's highly addictive!".

*Hint 1 (no penalty): Two stage challenge where the second stage you use the transcript.*

- Attachments: `Space Pilot 3000 Transcript.txt`, `flag.txt`
- Cách giải:

**Stage 1: Giải mã file flag.txt**

Mở file `flag.txt`, chúng ta nhận được một chuỗi Hexa:
`44 61 77 67 43 54 46 7b 20 33 39 30 20 31 30 30 32 20 35 38 30 20 31 33 31 34 20 31 39 31 20 31 35 38 39 20 33 33 20 31 35 32 36 20 31 34 31 20 37 36 32 20 33 35 32 20 38 38 20 31 32 39 33 20 33 37 39 20 35 30 20 7d`

Sử dụng CyberChef hoặc Python để decode chuỗi Hex này sang định dạng ASCII, thu được format của flag chứa một dãy số:
`DawgCTF{ 390 1002 580 1314 191 1589 33 1526 141 762 352 88 1293 379 50 }`

**Stage 2: Phân tích kịch bản (Transcript)**

Từ khóa "frequenting" trong mô tả và việc các con số bên trong flag khá lớn (như 1589, 1314, 1526), ta có thể suy luận đây là dạng bài đếm tần suất xuất hiện của các ký tự (Character Frequency) thay vì đếm từ (Word Index) trong file kịch bản `Space Pilot 3000 Transcript.txt`.

Tiến hành viết một đoạn script Python để thống kê số lần xuất hiện của từng ký tự trong file text và đối chiếu với dãy số của flag:

```python
import string
from collections import Counter

with open("Space Pilot 3000 Transcript.txt", "r", encoding="utf-8") as f:
    text = f.read()

indices = [390, 1002, 580, 1314, 191, 1589, 33, 1526, 141, 762, 352, 88, 1293, 379, 50]

# Trường hợp 1: Chỉ đếm chữ cái a-z
char_counts_lower = Counter([c for c in text.lower() if c in string.ascii_lowercase])
freq_to_char_1 = {v: k for k, v in char_counts_lower.items()}
flag_1 = "".join([freq_to_char_1.get(num, "?") for num in indices])
print(f"Case 1 (a-z): {flag_1}")

# Trường hợp 2: Đếm toàn bộ ký tự gốc
all_char_counts = Counter(text)
freq_to_char_2 = {v: k for k, v in all_char_counts.items()}
flag_2 = "".join([freq_to_char_2.get(num, "?") for num in indices])
print(f"Case 2 (All chars): {flag_2}")
```

Kết quả in ra từ 2 trường hợp đếm:
* Case 1 (Chỉ a-z): `w h y ? ? t z ? ? d b ? ? ? ?`
* Case 2 (Ký tự gốc): `? ? ? ? 0 ? ? ? ! ? ? 3 ? ? ?`

Ghép (Overlay) cả 2 kết quả lại với nhau theo đúng vị trí, ta được chuỗi:
`w h y _ 0 t z _ ! d b 3 _ _ _`

Với chủ đề của bài là Futurama và văn phong Leetspeak (sử dụng số/ký tự đặc biệt thay cho chữ cái), chuỗi này gợi nhớ ngay đến câu nói/meme huyền thoại của nhân vật Zoidberg: **"Why not Zoidberg?"**. 

Điền nốt các ký tự Leetspeak còn thiếu (`n`, `o`, `r`, `g`, `?`) vào khoảng trống, ta có được flag hoàn chỉnh khớp với 15 vị trí tần suất.

> Flag: `DawgCTF{whyn0tzo!db3rg?}`
{: .prompt-flag }

> Cách giải này không hay lắm nhưng mà đoán mò để có flag sớm cùng với 1 vài dữ kiện nhỏ cũng ok.

## **OSINT**

### **Better Call AT&T!**
- Tác giả: BFE
- Mô tả: 

I was watching my favorite show Better Call Saul recently and noticed something peculiar, can you figure out what the phone number for this parking garage is? I wanna recreate the shot...
Your flag will be the number for the garage without dashes, e.g DawgCTF{2015552124}.

- Attachments: `liners.png`
- Cách giải:

![](assets/img/DawgCTF2026/liners.png)

  1. **Xác định bối cảnh phim:** Bức ảnh là một cảnh quay nổi tiếng trong tập **"Pimento" (Mùa 1, Tập 9)** của series *Better Call Saul*. Trong cảnh này, nhân vật Mike Ehrmantraut đang đợi ở tầng thượng của một bãi đỗ xe.
  2. **Định vị địa điểm (Geolocate):** 
     - Dấu hiệu nhận biết quan trọng nhất là tòa nhà ở giữa có logo **AT&T** (đây là tòa nhà *AT&T Switching Center* tại 111 3rd St NW, Albuquerque).
     - Dựa vào góc nhìn đối diện tòa nhà AT&T và tháp anten, ta xác định được vị trí Mike đang đứng là tầng thượng của **Nhà để xe Fourth & Copper (VSA Garage)**, địa chỉ tại **401 4th St NW, Albuquerque, NM 87102**.
  3. **Tìm kiếm số điện thoại "đặc biệt":**
     - Đề bài đề cập đến việc "muốn tái hiện lại cảnh quay" (recreate the shot). Điều này gợi ý chúng ta cần tìm thông tin liên hệ trực tiếp tại cơ sở này, thường là số hỗ trợ hoặc an ninh thay vì số tổng đài chung của thành phố.
     - Kiểm tra các biển báo thực tế tại nhà xe này thông qua Google Street View hoặc các trang thông tin về đỗ xe của thành phố Albuquerque (CABQ Parking Division). 
     - Mặc dù số tổng đài chung là 311 hoặc đầu số `768-3405`, nhưng số điện thoại được niêm yết cụ thể cho bộ phận **An ninh và Hỗ trợ (Security/Assistance)** tại các nhà xe khu vực Downtown (bao gồm Fourth & Copper) là **505-768-4575**.
  4. **Xác nhận Flag:** Loại bỏ các dấu gạch ngang theo định dạng yêu cầu.

> Flag: `DawgCTF{5057684575}`
{: .prompt-flag }

### **Computer Repair I**

  - Tác giả: BFE
  - Mô tả:

I just started a computer repair store and a client dropped this off to my warehouse guy. Can you help me out and figure out what memory size and speed this laptop was sold with, along with the model and size of the hard drive?
The flag format will look like this, if the RAM was 32GB 3200Mhz and the hard drive was a 980PRO 1TB: DawgCTF{32GB\_3200MHZ\_1TB\_980PRO}

*Hint 1 (no penalty): Make sure you're filling the flag out right, and make sure you consider that the prompt says "sold with", not what it might currently have in it.*

  - Attachments: `r1.png`
  - Cách giải:

![](assets/img/DawgCTF2026/r1.png)

1.  **Phân tích dữ kiện:** Đề bài cung cấp hình ảnh mặt đáy của một chiếc laptop và yêu cầu tìm cấu hình nguyên bản lúc mới xuất xưởng ("sold with"), bao gồm 4 thông số: Dung lượng RAM, Tốc độ RAM, Dung lượng ổ cứng và Model ổ cứng. Gợi ý số 1 nhấn mạnh việc phải tìm cấu hình xuất xưởng chứ không phải cấu hình hiện tại.
2.  **Trích xuất mã định danh:** Nhìn kỹ vào tem thông tin ở mặt đáy của chiếc laptop (mang đặc trưng thiết kế của hãng Dell), ta cần đọc ra được mã **Service Tag** (gồm 7 ký tự alphanumeric) được in trên đó.
3.  **Tra cứu hệ thống chuỗi cung ứng:** Truy cập vào trang web [Dell Support](https://www.dell.com/support/home/), nhập mã Service Tag thu được từ bức ảnh vào thanh tìm kiếm để truy xuất hồ sơ của thiết bị.
4.  **Phân tích cấu hình gốc (Original Configuration):** Bỏ qua các thông tin tổng quan, ta cần tìm đến phần **"View product specs"** và chọn tab **"Original Configuration"**. Tại đây liệt kê chi tiết toàn bộ Part Number (mã linh kiện) đã được lắp ráp vào máy tại nhà máy. Rà soát danh sách, ta thu được các thông số chính xác:
      - Memory Size (Dung lượng RAM): **16GB**
      - Memory Speed (Tốc độ RAM): **2666MHZ**
      - Hard Drive Size (Dung lượng ổ cứng): **256GB**
      - Hard Drive Model (Mã ổ cứng): **35PK2** (Đây là Dell Part Number nội bộ định danh chính xác cho mẫu SSD được lắp ráp).
5.  **Định dạng Flag:** Nối các thông số vừa trích xuất được theo đúng cấu trúc đề bài yêu cầu (viết hoa toàn bộ và cách nhau bằng dấu gạch dưới).

> Flag: `DawgCTF{16GB_2666MHZ_256GB_35PK2}`
{: .prompt-flag }

### **Computer Repair II**

- Tác giả: BFE
- Mô tả:

I just got another pic from the warehouse, not a lot to go on here, but could you figure out the screen size of this laptop?

The flag format will look like DawgCTF{18.9IN}.

- Attachments: `r2.jpg`
- Cách giải: 

![](assets/img/DawgCTF2026/r2.jpg)

Cùng lúc tra cứu trên web [Dell Support](https://www.dell.com/support/home/) thì tôi thấy luôn kích thước màn hình nên là lấy flag

> Flag: `DawgCTF{15.6IN}`
{: .prompt-flag }

### **Computer Repair III**
- Tác giả: BFE
- Mô tả:

My technician is working on this Dell device of some sort, and he's trying to figure out what it is so he can order a replacement component. Can you identify what Dell product this is? The flag will be six characters, capital letters and numbers, such as DawgCTF{T4CH95}

*Limit of ten attempts.*

- Attachments: `cr3.zip` giải nén `cr3_1.jpg`, `cr3_2.jpg`
- Cách giải:

1. **Phân tích tổng quan thiết bị:** Bức ảnh `cr3_1.jpg` cho thấy một bo mạch (mainboard) đang được tháo rời. Phía sau nó là một bộ vỏ hộp nhựa màu đen dẹt với logo Dell dập nổi. Kích thước khung máy nhỏ gọn, kết hợp với quạt tản nhiệt cỡ lớn (mã `DC28000NZD0`) và dàn cổng kết nối ngoại vi dày đặc (USB, RJ45 LAN, giắc nguồn DC) khẳng định đây là cấu trúc bên trong của một chiếc Docking Station (trạm kết nối mở rộng) dành cho laptop Dell.
2. **Nhận dạng cấu trúc đặc trưng:** Điểm mấu chốt để xác định dòng máy nằm ở cụm chân cắm màu đen khổng lồ ở cạnh trái của bo mạch. Đây là khe cắm chờ dành cho thiết kế cáp dạng module có thể tháo rời — một tính năng độc quyền và nổi bật nhất của dòng dock **Dell WD19**. Thiết kế này cho phép thay thế cụm cáp đầu vào mà không cần thay toàn bộ bo mạch chính. 
3. **Phân tích chi tiết linh kiện:** Bức ảnh `cr3_2.jpg` chụp cận cảnh khu vực góc bo mạch chứa vi điều khiển PIC32MX. Đáng chú ý nhất là cụm ngàm nhựa màu đen ở góc dưới cùng bên phải. Đây chính là cơ chế cơ học của nút nguồn (nằm trên nắp vỏ dock), được thiết kế với một ống rỗng để dẫn sáng cho đèn `LED1` và truyền lực cơ học xuống nút bấm `SW2` ngay bên cạnh. Kết cấu này hoàn toàn khớp với sơ đồ bo mạch của gia đình WD19.
4. **Đối chiếu định dạng Flag:** Đề bài yêu cầu định dạng flag gồm **6 ký tự** (chữ in hoa và số). Dòng dock Dell WD19 có nhiều biến thể tuỳ thuộc vào module cáp được gắn vào (WD19, WD19S, WD19TB, WD19TBS, WD19DC). Trong số các model này, phiên bản sử dụng cáp Thunderbolt cực kỳ phổ biến trong giới IT và khớp hoàn hảo với độ dài 6 ký tự là **WD19TB**.

> Flag: `DawgCTF{WD19TB}`
{: .prompt-flag }

> [Video Hướng dẫn Tháo lắp Dell WD19](https://www.youtube.com/watch?v=GdheYMzpvTs): Video này cung cấp góc nhìn toàn cảnh về quá trình bung máy dòng dock WD19, giúp dễ dàng đối chiếu hình dáng bo mạch và cụm nút nguồn xuất hiện trong hình ảnh của đề bài.

### **Gateway to the Turnpike**

- Tác giả: blahaj
- Mô tả: 

They say all roads lead to Rome, but in this part of the mid-Atlantic, all roads lead to a very confusing set of gas stations. I snapped this photo on a road trip a while back. Do you think you could tell me the ZIP code of the place this was taken?

*Limit of ten attempts.*

- Attachment: `gateway.jpeg`
- Cách giải:

![](assets/img/DawgCTF2026/gateway.jpeg)

1.  **Phân tích hình ảnh:**
    *   **Biển báo giao thông:** Có biển báo chỉ hướng cho đường cao tốc **I-70** (West/East) và **PENNA TURNPIKE** (Pennsylvania Turnpike).
    *   **Tên đường:** Một biển báo màu xanh ghi **"S Breezev... Rd"**, rất có thể là **South Breezewood Road**.
    *   **Các thương hiệu:** McDonald's, Sheetz, Days Inn, Perkins, Exxon. Sự tập trung dày đặc các trạm xăng và nhà hàng ven đường này rất đặc trưng.
    *   **Đặc điểm địa lý:** Khu vực đồi núi, có tuyết mỏng, phù hợp với vùng Pennsylvania, Mỹ.
    *   **Gợi ý từ đề bài:** "Gateway to the Turnpike" (Cửa ngõ vào xa lộ thu phí) và "confusing set of gas stations" (một cụm các trạm xăng gây bối rối) là những mô tả kinh điển về thị trấn **Breezewood, Pennsylvania**.

2.  **Xác định địa điểm:**
    *   Breezewood nổi tiếng là nơi xa lộ I-70 bị ngắt quãng và người lái xe buộc phải đi qua một đoạn đường quốc lộ với hàng loạt trạm xăng và đèn giao thông để nối vào Pennsylvania Turnpike. Đây là một địa điểm cực kỳ nổi tiếng trong giới du lịch đường bộ ở Mỹ.
    *   Vị trí chụp ảnh chính xác là tại nút giao giữa đường **US-30 (Lincoln Highway)** và **S Breezewood Rd**.

3.  **Tìm mã ZIP:**
    *   Tìm kiếm mã bưu điện (ZIP code) của **Breezewood, PA**.
    *   Mã ZIP của Breezewood, Pennsylvania là **15533**.

> Flag: `15533`
{: .prompt-flag }

### **Locksmith**

  - Tác giả: BFE
  - Mô tả:

I saw this weird lock at the escape room I work at. Can you figure out what series it is, and how tall the lock body is?
The flag will be in the following format: DawgCTF{BEST500\_95MM}

  - Attachments: `lock.jpg`
  - Cách giải:

![](assets/img/DawgCTF2026/lock.jpg)

1.  **Phân tích hình ảnh:** Quan sát kỹ bức ảnh ổ khóa, ta có thể thấy rõ dòng chữ **SIMPLEX** được khắc dọc ngay trên mặt núm vặn. Kết hợp với thiết kế hình giọt nước đặc trưng, núm xoay nằm phía trên và bàn phím cơ gồm 5 nút bấm được bao quanh bởi các chữ số La Mã từ I đến V, ta có thể xác định đây là loại khóa cơ học **Simplex 900 Series** (thuộc thương hiệu Kaba / dormakaba).
2.  **Tìm kiếm thông số kỹ thuật:** Biết được chính xác tên dòng sản phẩm, ta tiến hành tra cứu tài liệu thông số kỹ thuật (specification sheet) chính thức của hãng cho dòng khóa Simplex 900.
3.  **Xác định chiều cao:** Theo tài liệu từ nhà sản xuất cung cấp, thông số chiều cao của mặt khóa ngoài (exterior body height) là **3-3/4 inches**, quy đổi sang hệ mét tương đương **95 mm**.
4.  **Tạo flag:** Lắp ráp các dữ kiện vừa tìm được (Tên hãng và dòng khóa: SIMPLEX900, Chiều cao: 95MM) vào định dạng mẫu của đề bài `DawgCTF{BEST500_95MM}`.

> Flag: `DawgCTF{SIMPLEX900_95MM}`
{: .prompt-flag }

### **owo?**

- Tác giả: blahaj
- Mô tả: 

Took this photo on a roadtrip a while back and want to go back to this Pizza Hut, but I forgot where it was. Do you think you could find me the ZIP code of the town this was in?

*Limit of ten attempts.*

- Attachment: `20241117_132821.jpg`
- Cách giải:

![](assets/img/DawgCTF2026/20241117_132821.jpg)

1. **Biển hiệu Pizza Hut & Cảnh quan:** Bức ảnh cho thấy một biển hiệu Pizza Hut với dòng chữ troll cố ý ("TATSY CRI2PY WIИGS OwO"). Phía sau là một dãy núi dốc, trụi lá, mang đặc trưng rõ nét của vùng đồi núi Appalachian (Ridge-and-Valley Appalachians). 
2. **Biểu ngữ "Hometown Heroes":** Trên cột điện có treo một lá cờ vinh danh cựu chiến binh với dải màu đỏ ở trên và xanh ở dưới. Đây là một chương trình rất phổ biến ở các thị trấn nhỏ thuộc bang West Virginia, Pennsylvania và Maryland.
3. **Bức tượng con gà trống màu xanh (Blue Rooster):** Đây là manh mối "tử huyệt" của bài toán. Rất nhiều người chơi OSINT khi tìm kiếm "Rooster statue WV" sẽ ngay lập tức tìm ra dự án nghệ thuật **"Moorefield Rooster Project"** ở thị trấn Moorefield, West Virginia (nơi có hàng loạt tượng gà trống bằng sợi thủy tinh được sơn màu rực rỡ). Đó là lý do tại sao mã ZIP của Moorefield (**26836**) đã được thử nhưng lại bị báo **Sai**.
4. **Vị trí thực sự:** Mặc dù dự án gà trống bắt nguồn từ Moorefield, bức tượng gà màu xanh cụ thể này đã được một người dân/doanh nghiệp mua lại và đặt tại thị trấn ngay sát bên cạnh: **Petersburg, West Virginia**.
   * Cửa hàng Pizza Hut này nằm ở địa chỉ **213 N Main St, Petersburg, WV**.
   * Con đường N Main St (US-220) chạy ra khỏi thị trấn, do đó biển giới hạn tốc độ **45 mph** xuất hiện ngay phía trước.
   * Tòa nhà bằng gạch với mái tôn màu nâu ngay bên phải Pizza Hut chính là chi nhánh của ngân hàng **Summit Community Bank** (ở số 215 N Main St).
   * Dãy núi dựng đứng ở phía hậu cảnh chính là sườn dốc của rặng núi Patterson Creek Mountain nằm ngay bên kia bờ sông South Branch Potomac.

Do đó, mã ZIP chính xác của thị trấn Petersburg, nơi chụp bức ảnh này là: **26847**

> Flag: `26847`
{: .prompt-flag }

### **Plane Spotting Pt. 1**

- Tác giả: blahaj
- Mô tả: 

This photo was transmitted from a cyberdawg documenting their travel right before they went missing. We didn't have a GPS tracker and it's imperative you identify the location the photo was taken.

Flag Format: DawgCTF{IATA}
Make sure you have the proper format.

*Limit of ten attempts.*

- Attachment: `20260301_160018.jpg`
- Cách giải:

![](assets/img/DawgCTF2026/20260301_160018.jpg)

Dựa vào các chi tiết trong bức ảnh, chúng ta có thể xác định chính xác sân bay nơi bức ảnh được chụp:

1.  **Xe bồn tiếp nhiên liệu (Fuel Truck):** Chiếc xe tải màu trắng trong ảnh có in rõ ràng dòng chữ và logo của **USAirports**.
2.  **Thông tin về USAirports:** USAirports (USAirports Flight Support) là một công ty dịch vụ hàng không cố định (FBO - Fixed Base Operator) thuộc sở hữu gia đình, hoạt động duy nhất tại **Sân bay Quốc tế Frederick Douglass - Greater Rochester** (Rochester, New York).
3.  **Hãng hàng không:** Phía sau xe bồn là một chiếc máy bay của hãng Southwest Airlines (loại Boeing 737). Southwest Airlines có khai thác các chuyến bay thương mại tại sân bay Rochester này. Ngoài ra, tuyết tan trên mặt đất và cảnh quan phía sau cũng hoàn toàn phù hợp với khí hậu và địa hình của sân bay vào mùa đông/đầu xuân ở ngoại ô New York.

Mã IATA của Sân bay Quốc tế Frederick Douglass - Greater Rochester là **ROC**.

> Flag: `DawgCTF{ROC}`
{: .prompt-flag }

### **Plane Spotting Pt. 2**

- Tác giả: blahaj
- Mô tả: 

You saw this plane approaching; what airport was it coming from?

Use the flag from Plane Spotting Pt. 1 to unlock the image. Flag format: DawgCTF{IATA}

*Limit of six attempts. Flag format strictly enforced.*

- Attachments: `planespotting2.zip` giải nén `planespotting2.jpg`
- Cách giải: 

![](/assets/img/DawgCTF2026/planespotting2.jpg)

Theo hướng dẫn truyền thống của OSINT, chúng ta sẽ phải phân tích tọa độ GPS từ dữ liệu Exif của ảnh (bầu trời tại công viên Andover Park gần sân bay BWI), xem lại lịch sử các chuyến bay của Southwest Airlines hạ cánh vào đúng thời điểm đó (15:22 chiều ngày 5 tháng 4) để truy ra sân bay cất cánh. Tuy nhiên, việc tra cứu dữ liệu radar lịch sử đôi khi gặp khó khăn hoặc không cho ra kết quả duy nhất.

Vì đề bài giới hạn số lần nộp flag trên hệ thống (chỉ 6 lần) nhưng lại tiết lộ **định dạng cờ** là `DawgCTF{IATA}`, chúng ta có thể lợi dụng đặc điểm thiết kế của giải CTF này: **Cờ của phần trước chính là mật khẩu giải nén file ZIP cho phần tiếp theo** (ở đây là file `planespotting3.zip`).

Mã IATA của một sân bay chỉ bao gồm 3 chữ cái viết hoa (từ AAA đến ZZZ). Do đó, tổng số trường hợp có thể xảy ra chỉ là $26^3 = 17,576$ mật khẩu. Đây là một không gian mẫu (keyspace) cực kỳ nhỏ, hoàn toàn có thể bị phá mã (brute-force) trong vòng chưa tới 1 giây!

**Bước 1: Tạo wordlist chứa tất cả các mã IATA**
Chúng ta viết một đoạn script Python ngắn gọn sử dụng thư viện `itertools` để sinh ra tất cả các tổ hợp 3 chữ cái và định dạng chúng thành chuẩn cờ của giải:

```python
import string
import itertools

with open("iata_wordlist.txt", "w") as f:
    chars = string.ascii_uppercase
    for combo in itertools.product(chars, repeat=3):
        iata = "".join(combo)
        f.write(f"DawgCTF{% raw %}{{{iata}}}{% endraw %}\n")

print("Đã tạo xong wordlist iata_wordlist.txt")
```

**Bước 2: Tiến hành Brute-force file ZIP**
Sau khi chạy script trên để lấy file `iata_wordlist.txt`, chúng ta sử dụng công cụ `fcrackzip` (một công cụ phá mật khẩu file zip rất phổ biến trên Linux) để tấn công file `planespotting3.zip` của bài kế tiếp:

```bash
fcrackzip -u -D -p iata_wordlist.txt planespotting3.zip
```

* `-u`: Kiểm tra mật khẩu bằng cách giải nén thử (unzip).
* `-D`: Sử dụng chế độ tấn công bằng từ điển (dictionary attack).
* `-p`: Chỉ định file từ điển (`iata_wordlist.txt`).

```bash
PASSWORD FOUND!!!!: pw == DawgCTF{NAS}
```

> Flag: `DawgCTF{NAS}`
{: .prompt-flag }

> Thực ra việc limit lần thử của tác giả cũng có thể thử nhiều lần bằng cách dò pass cái file .zip nhưng mà cũng có thể crack pass file .zip để lấy flag. Đây là cách giải hơi khôn lỏi, không hay đối với **OSINT**

### **The Lookout's Legend**

  - Tác giả: blahaj
  - Mô tả:

High above the birthplace of the MTO, this mountain offers a view that spans six counties. What do the locals call this spot?

  - Attachments: `lookout.jpeg`
  - Cách giải:

![](/assets/img/DawgCTF2026/lookout.jpeg)

1.  **Giải mã "Birthplace of the MTO":** Chi tiết đầu tiên là "MTO", từ viết tắt của "Made To Order" - một nhãn hiệu thực đơn đồ ăn mang tính biểu tượng của chuỗi cửa hàng tiện lợi Sheetz. Nơi khai sinh và cũng là trụ sở chính của Sheetz nằm ở thành phố **Altoona, Pennsylvania**.
2.  **Truy tìm địa điểm ngắm cảnh:** Dữ kiện "High above... offers a view that spans six counties" (Nằm trên cao... mang đến tầm nhìn bao trọn 6 quận) hướng chúng ta tới ngọn núi **Wopsononock Mountain** nằm sừng sững ngay phía trên Altoona. Đài quan sát trên đỉnh núi này nổi tiếng trong lịch sử với góc nhìn toàn cảnh bao quát 6 quận khác nhau của bang Pennsylvania (Blair, Bedford, Cambria, Centre, Clearfield, và Huntingdon).
3.  **Kiểm chứng qua hình ảnh:** Bức ảnh chụp lại một khu vực phủ đầy tuyết trắng với nhiều tháp ăng-ten viễn thông/vô tuyến và một tòa nhà có ghi chữ "KBS". Nhờ lợi thế về độ cao, đỉnh núi Wopsononock đóng vai trò là trạm phát sóng chính cho khu vực Altoona, và cơ sở hạ tầng này hoàn toàn trùng khớp với thực tế.
4.  **Tìm tên gọi địa phương:** Vì cái tên "Wopsononock" khá dài và trẹo lưỡi, người dân địa phương đã rút gọn nó lại. Họ thường gọi ngọn núi cũng như điểm ngắm cảnh này bằng một cái tên ngắn gọn và thân thuộc hơn là **Wopsy** (hoặc Wopsy Lookout).

> Flag: `Wopsy`
{: .prompt-flag }

### **The Temple of Doom**

- Tác giả: BFE
- Mô tả: 

I used to work at this crazy looking building. I've attached a picture of it, can you guess where it is? If you can, the flag is the nickname the building has. For instance, if the nickname was "The Dragon Building", the flag would be DawgCTF{The_Dragon_Building}.

- Attachments: `temple.jpg`
- Cách giải: 

![](/assets/img/DawgCTF2026/temple.jpg)

1. **Phân tích hình ảnh:** Bức ảnh cho thấy một tòa nhà khổng lồ có màu vàng mù tạt với kiến trúc cực kỳ độc đáo theo dạng kim tự tháp bậc thang (stepped pyramid). Kiểu kiến trúc này rất giống với các đền đài **Ziggurat** cổ đại ở vùng Lưỡng Hà. Xung quanh là bãi đậu xe rộng lớn và hàng cây cọ, gợi ý địa điểm thuộc khu vực Nam California, Hoa Kỳ.
2. **Tìm kiếm dữ liệu:** Sử dụng kỹ thuật Google Reverse Image Search hoặc tìm kiếm với từ khóa: `"yellow stepped pyramid building California"` hoặc `"mustard yellow ziggurat building"`.
3. **Xác định địa điểm:** Kết quả dẫn đến **Tòa nhà Liên bang Chet Holifield (Chet Holifield Federal Building)** tọa lạc tại Laguna Niguel, California. Tòa nhà này được thiết kế bởi kiến trúc sư nổi tiếng William Pereira (người cũng thiết kế Kim tự tháp Transamerica ở San Francisco).
4. **Xác định biệt danh (Nickname):** Do hình dáng đặc thù, tòa nhà này được người dân địa phương và giới kiến trúc gọi rộng rãi bằng biệt danh là **"The Ziggurat"**. 
5. **Định dạng Flag:** Dựa vào ví dụ trong mô tả `The_Dragon_Building`, ta kết hợp biệt danh phổ biến nhất của tòa nhà vào định dạng yêu cầu. Tên đầy đủ của biệt danh này thường được gọi là **The Ziggurat Building**.

> Flag: `DawgCTF{The_Ziggurat_Building}`
{: .prompt-flag }

### **Дмитрий-шесть**

- Tác giả: BFE
- Mô tả: 

My friend from Ukraine sent me this weird picture, he says that it's the key to a secret treasure room underground.

Do you know where this picture was taken? The flag will be the official name of it, and should be 6 letters total, all capital letters.

*Limit of ten attempts.*

- Attachments: `dmetri6.jpeg`
- Cách giải: 

![](/assets/img/DawgCTF2026/dmetri6.jpeg)

Dựa trên các manh mối từ hình ảnh và đề bài, đây là lời giải cho thử thách OSINT **Дмитрий-шесть** (Dmitry-Six):

1.  **Phân tích hình ảnh:**
    *   Các hình ảnh được cung cấp là những bức ảnh thực tế rất nổi tiếng về hệ thống tàu điện ngầm bí mật ở Moscow, Nga, thường được giới khám phá đô thị gọi là **Metro-2**.
    *   Ảnh trên cùng cho thấy một toa xe dịch vụ loại **AS1A** (thường được sử dụng trong các đường dây bí mật hoặc công vụ) bên trong một đường hầm có lớp vỏ kim loại đặc trưng.
    *   Các ảnh dưới cho thấy cấu trúc đường hầm sâu, hiện đại, không giống với các ga tàu điện ngầm công cộng thông thường.

2.  **Giải mã tiêu đề và mối liên hệ:**
    *   **"Дмитрий-шесть"** dịch từ tiếng Nga sang tiếng Anh là **"Dmitry-Six"** (D-6).
    *   **D-6 (Д-6)** chính là tên mã chính thức (codename) của hệ thống Metro-2 này theo hồ sơ của KGB.
    *   Sự kiện "người bạn từ Ukraine" gửi ảnh và gọi đó là chìa khóa dẫn đến "căn phòng kho báu dưới lòng đất" (treasure room) là một tham chiếu trực tiếp đến loạt trò chơi và tiểu thuyết **Metro 2033** của tác giả **Dmitry Glukhovsky**. Trong cốt truyện (do hãng 4A Games của Ukraine phát triển), **D6** là một boongke quân sự/kho vũ khí khổng lồ chứa đầy công nghệ và vũ khí "kho báu" từ thời tiền chiến.

3.  **Xác định tên chính thức (Official Name):**
    *   Mặc dù thường được gọi là "Metro-2", nhưng đó là tên không chính thức (informal designation).
    *   Theo các tài liệu giải mật và thông tin từ cơ quan quản lý (như GUSP - Tổng cục Các chương trình Đặc biệt của Tổng thống Nga), hệ thống này có tên mã chính thức là **D-6**.
    *   Tuy nhiên, yêu cầu của đề bài là **"6 letters total, all capital letters"** (tổng cộng 6 chữ cái, viết hoa toàn bộ).
    *   Cụm từ **METRO2** (M-E-T-R-O-2) gồm đúng 6 ký tự. Trong nhiều thử thách CTF, tên hệ thống này thường được định dạng là `METRO2` để làm flag. Một lựa chọn khác phù hợp với 6 chữ cái (letters) và bối cảnh là **BUNKER** (do D6 trong game/truyện được gọi là Boongke), nhưng tên gọi phổ biến nhất liên quan đến Metro-2 là **METRO2**.

> Flag: `METRO2`
{: .prompt-flag }
