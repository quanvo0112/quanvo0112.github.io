---
title: BITSCTF 2026
date: 2026-02-23 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, misc, osint, minecraft]
image:
  path: /assets/img/BITSCTF2026/logo.png
---

## **Misc**

### **Wifies_Lover # 1**
- Tác giả: kekwman
- Mô tả: 

The old capital is silent. Concrete skeletons stretch into the sky where surveillance towers once stood. The Government called it stability. The people called it control. Somewhere in the wreckage, the Resistance has rebuilt. Not openly. Not recklessly. You have received an image. The image is not decoration. It is not scenery. It is not random. It shows the location of a functioning Resistance relay — one of the few places where real technology still operates.

Usage of the /guess Command /guess (Coordinate_X) (Coordinate_Y) (Coordinate_Z) For example if the coordinates were 100,100,100 the usage for /guess would be /guess 100 100 100 VERSION:1.21.8

> minecraft.bitskrieg.in:25565

- Attachment: `2026-02-19_00.20.22.png`
- Cách giải:

**Bước 1: Chuẩn bị và kết nối**  
Khởi động game Minecraft Java Edition với phiên bản chính xác là `1.21.8`. Sau đó, tiến hành kết nối vào server thông qua địa chỉ IP: `minecraft.bitskrieg.in:25565`.

**Bước 2: Phân tích dữ kiện hình ảnh (OSINT in-game)**  
Quan sát bức ảnh được cung cấp, ta có thể rút ra một số đặc điểm nhận diện chính của khu vực cần tìm:  
* **Kiến trúc:** Một tòa nhà đổ nát được xây chủ yếu bằng gạch đá (Stone Bricks), có những mảng tường rêu phong (Mossy Stone Bricks).
* **Thiên nhiên:** Có rất nhiều dây leo, cây cối mọc um tùm xuyên qua các bức tường, và một hồ nước nhỏ nằm ngay giữa tàn tích. 
* **Góc nhìn:** Khung cảnh nhìn qua một vòm cửa lớn bị vỡ, hướng ra một bãi cỏ và một tảng đá đằng xa.

**Bước 3: Truy tìm vị trí**  
Dựa vào các đặc điểm trên, người chơi cần di chuyển và khám phá (explore) xung quanh khu vực map của server để tìm đến đúng khu di tích hoang tàn này. Quá trình này đòi hỏi sự kiên nhẫn và khả năng định vị, so sánh góc nhìn trong game với góc nhìn của bức ảnh mẫu.

**Bước 4: Xác định tọa độ và lấy Flag**  
Khi đã đứng đúng vị trí trùng khớp với góc chụp của bức ảnh gốc, người chơi mở màn hình thông số (nhấn phím `F3`) để lấy tọa độ hiện tại `(X, Y, Z)`. 

Tại vị trí chính xác này, tọa độ hiển thị là `524 60 753`.
Mở chat trong game và nhập cú pháp:
`/guess 524 60 753`

Hệ thống ghi nhận tọa độ chính xác và trả về flag.

> Flag: `BITSCTF{G0D5p33d_F3ll0w_reb3l}`
{: .prompt-flag }

## **OSIN**T

### **Nostalgia Trip**

- Tác giả: kekwman
- Mô tả: 

Go back in time maybe a decade or so, And play Geoguessr from a world you may or may not know.

Enjoy :)

> Website: http://minecraft.bitskrieg.in

- Attachment: 
- Cách giải:

Unknown Signal Source 01: 796, -898 (Mumbo Jumbo's base)

> Bài này mình không đủ thời gian để ngồi check video của series Hermitcraft S6, thành ra chỉ giải được một task của thử thách
