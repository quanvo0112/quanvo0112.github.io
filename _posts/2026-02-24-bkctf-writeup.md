---
title: Batman's Kitchen CTF 2026
date: 2026-02-24 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, misc, osint, minecraft]
image:
  path: /assets/img/BKCTF2026/logo.png
---

## **Misc**

### **Read the rules**
- Tác giả: BatmansKitchen
- Mô tả: 

Join the discord and read the rules

> Flag: `bkctf{1_r34d_th3_ru13z_4nd_1t_w4s_gr34t}`
{: .prompt-flag }

### **Speedrunning**
- Tác giả: Jono
- Mô tả: 

I speedran minecraft but MCSR didn't accept my run :(

- Attachments: challenge.zip
- Cách giải:

Khi vào thế giới
![](/assets/img/BKCTF2026/speedrunning-1.png)

`/tp 0 ~ 0` tới đảo chính The End

![](/assets/img/BKCTF2026/speedrunning-2.png)

Vào cổng The End trở về thế giới Overworld, rồi đi ngược lên mặt đất:

![](/assets/img/BKCTF2026/speedrunning-3.png)

Đã giải được 3/4 mảnh Flag, còn mảnh cuối thì ta dựa vào Folder `Screenshots` của Attachments:

![](/assets/img/BKCTF2026/speedrunning-4.png)

Tôi thấy rằng ảnh `1.png` khả năng là nơi chứa mảnh flag cuối cùng. Sử dụng **MCA Selector** và chọn Filter Chunks như trong hình:
![](/assets/img/BKCTF2026/speedrunning-5.png)

`/tp -576 ~ 75` và đi xuống phía dưới

![](/assets/img/BKCTF2026/speedrunning-6.png)

Ghép lại toàn bộ ta nhận được flag hoàn chỉnh:

> Flag: `bkctf{m1nc3dr4ft_m4nhunt_0n3_hunt3r}`
{: .prompt-flag }

## **OSINT**

### **MOM GET THE CAMERA**

- Tác giả: Jono
- Mô tả:

Mom! Mom! Im on google maps!

The flag format is the house that I lived at formatted like bkctf{12345_ne_67th_st}

HINT: The kid (who may or may not be me) is outside a lemonade stand with his friends. It will be clear when you are at the correct house.

HINT 2: The house in the image is NOT the correct house.

- Attachments: momgetthecamera.png
- Cách giải:

![](/assets/img/BKCTF2026/momgetthecamera.png)

> Flag: `bkctf{20514_ne_23rd_ct}`
{: .prompt-flag }

### **Eye on the Sky 2**

- Tác giả: Aramdana
- Mô tả: 

can you dedeuce where this photo was taken?

Flag format is the name of the location the image was taken from (ie the location of the photographer). All lower case, remove spaces. Example: bkctf{goldengatebridge}

- Attachments: sky.jpg
- Cách giải: 

Bước 1: Xác định Landmark cốt lõi

Điểm nổi bật nhất trong bức ảnh là ngọn núi lửa phủ tuyết. Đặc điểm nhận diện quan trọng nhất là một mỏm đá sắc nhọn, lởm chởm nhô ra ở sườn bên trái của ngọn núi.

* Qua đối chiếu hình ảnh địa lý, đây chắc chắn là **Mount Rainier** thuộc bang Washington, Mỹ.
* Mỏm đá nhọn bên trái chính là **Little Tahoma Peak**.

Bước 2: Phân tích góc chụp (Camera Angle)

Việc Little Tahoma Peak (nằm ở sườn phía Đông của Mount Rainier) xuất hiện rõ nét ở bên *trái* đỉnh chính (Columbia Crest) cho thấy người chụp đang đứng ở phía Bắc ngọn núi và nhìn về hướng Nam / Đông Nam.

Ban đầu, các địa điểm nổi tiếng như `kerrypark` hay `spaceneedle` có thể được nghĩ đến. Tuy nhiên, có hai điểm bất thường trong ảnh giúp loại trừ giả thuyết này:

1. **Không có cảnh quan đô thị:** Toàn bộ thành phố Seattle không hề xuất hiện trong khung hình.
2. **Tiền cảnh (Foreground):** Thay vì các tòa nhà, phía trước ngọn núi là các dải đồi núi phủ rừng (foothills) xếp lớp lên nhau do hiệu ứng nén (compression) của ống kính tele.

Điều này chứng tỏ nhiếp ảnh gia không đứng ở trung tâm Seattle mà đứng ở một điểm cao thuộc vùng ngoại ô, có tầm nhìn vắt ngang qua các rặng núi khác (khu vực Issaquah Alps).

Bước 3: Kết nối Dữ kiện & Mảnh ghép cuối cùng

Gợi ý lớn nhất nằm ở tên của challenge: **"Eye on the Sky"**.

* Một trong những điểm ngắm Mount Rainier từ trên cao nổi tiếng nhất ở ngoại ô phía Đông Seattle—nơi con người thực sự hòa mình vào bầu trời—chính là bãi cất cánh dành cho môn thể thao dù lượn (paragliding).
* Địa điểm này có tên là **Poo Poo Point** (nằm trên núi Tiger Mountain thuộc Issaquah).
* Góc nhìn thẳng từ đỉnh đồi Poo Poo Point về hướng Nam hoàn toàn khớp với profile của ngọn núi (Little Tahoma Peak bên trái) và các dải đồi nhấp nhô phía dưới chân núi Rainier.

*(Lưu ý thêm: Chiếc máy bay trong ảnh là một pivot point tuyệt vời. Trong môi trường thực tế hoặc nếu có metadata/timestamp, ta có thể dùng Flightradar24 hoặc ADSBexchange để tra cứu chuyến bay. Đường thẳng nối từ Mount Rainier đi qua tọa độ máy bay trên bản đồ sẽ chỉ thẳng hàng về Poo Poo Point).*

Kết luận: Vị trí chụp ảnh là điểm nhảy dù lượn nổi tiếng Poo Poo Point.

> Flag: `bkctf{poopoopoint}`
{: .prompt-flag }


