---
title: TexSaw 2026
date: 2026-03-31 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, osint]
image:
  path: /assets/img/TexSAW2026/logo.jpg
---

## **OSINT**

### **Summer Trip**

- Mô tả: 

Ohno, I took a photo of a poster on a trip and, I can not remember where I took it. Please help me find the coordinates. The only things I remember was there was a yellow money exchange machine and a popular roast beef restraunt. Flag format: texsaw{coordinates here} For example the cordinates for the plinth at UTD are 32°59'14.26"N 96°44'53.87"W Used google Earth for cordinates by placing place mark. Plinth: https://calendar.utdallas.edu/su_mall_plinth ex: texsaw{32_59_14N-96_45_53W}

- Attachments: `Summer_Trip.jpeg`
- Cách giải: 

![](/assets/img/TexSAW2026/Summer_Trip.jpeg)

Đầu tiên, chúng ta phân tích các dữ kiện có được từ bức ảnh và đoạn mô tả:
1. Bức ảnh là một poster cảnh báo chống khủng bố có in dòng chữ Nhật **"警視庁"** (Sở Cảnh sát Thủ đô Tokyo). Điều này xác nhận địa điểm ở Tokyo, Nhật Bản.
2. Từ khóa ở mô tả: **"Ohno..."** và **"popular roast beef restraunt"** -> Cách chơi chữ này ám chỉ trực tiếp đến chuỗi nhà hàng thịt bò nướng rất nổi tiếng ở Tokyo là **Roast Beef Ohno**.
3. Từ khóa tiếp theo: **"yellow money exchange machine"** -> Tại các khu du lịch ở Nhật Bản, các máy đổi tiền ngoại tệ tự động màu vàng của thương hiệu **SMART EXCHANGE** rất phổ biến.

Tiến hành rà soát các chi nhánh của nhà hàng Roast Beef Ohno và tìm kiếm sự xuất hiện của máy đổi tiền màu vàng xung quanh đó. Ta tìm được một sự trùng khớp hoàn hảo: 
Chi nhánh **Roast Beef Ohno Harajuku** nằm ở tầng hầm B1F của tòa nhà **COXY188** (trên con phố sầm uất Takeshita). Ngay tại tầng trệt (khu vực sử dụng chung) của tòa nhà này có đặt một bốt SMART EXCHANGE màu vàng rực rỡ.

Sử dụng Google Earth và cắm Place Mark vào vị trí của tòa nhà COXY188 (địa chỉ: *1 Chome-8-8 Jingumae, Shibuya City, Tokyo*), ta thu được tọa độ thập phân:
- Vĩ độ (Latitude): `35.669865° N`
- Kinh độ (Longitude): `139.706225° E`

Thực hiện quy đổi sang định dạng Độ/Phút/Giây (DMS):
- Vĩ độ: `35°` + `(0.669865 * 60) = 40.1919'` -> `(0.1919 * 60) = 11.514"` => **35° 40' 11" N**
- Kinh độ: `139°` + `(0.706225 * 60) = 42.3735'` -> `(0.3735 * 60) = 22.41"` => **139° 42' 22" E**

Cuối cùng, format tọa độ theo yêu cầu của đề bài (loại bỏ phần thập phân của giây như ví dụ UTD).

> Flag: `texsaw{35_40_11N-139_42_22E}`
{: .prompt-flag }

### **Just A Tree**
- Tác giả: Auric115
- Mô tả:

Find the tree featured prominently in this photo (the tall one in the center). Identify it's type (species) and location (longitude and latitude to 3 decimal places).

Flag format: texsaw{tree_type@(latitude,logitude)} ex: texsaw{coast_redwood@(41.381,-124.044)} the flag is all lowercase

- Attachments: `tree.png`
- Cách giải:

![](/assets/img/TexSAW2026/tree.png)

  1. **Nhận diện địa điểm:** Dựa trên các đặc điểm kiến trúc trong ảnh, ta xác định được địa điểm là khuôn viên **Đại học Texas ở Dallas (UTD)**. Phía xa bên trái là tháp truyền hình **TAGER**, và tòa nhà bên phải là **Sciences Building (SCI)**.
  2. **Xác định vị trí qua Street View:** Sử dụng [Google Maps Street View](https://www.google.com/maps/place/%C4%90%E1%BA%A1i+h%E1%BB%8Dc+Texas+%E1%BB%9F+Dallas/@32.991057,-96.7478397,3a,27.2y,257.39h,94.01t/data=!3m10!1e1!3m8!1sOc3uqwXlXQmUTlQmI2uCqA!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D-4.010000000000005%26panoid%3DOc3uqwXlXQmUTlQmI2uCqA%26yaw%3D257.39!7i16384!8i8192!9m2!1b1!2i36!4m16!1m8!3m7!1s0x864c21ff895e4aa5:0xd9098b32e9aa1331!2zxJDhuqFpIGjhu41jIFRleGFzIOG7nyBEYWxsYXM!8m2!3d32.9859295!4d-96.7503304!10e5!16zL20vMDJtdDJu!3m6!1s0x864c21ff895e4aa5:0xd9098b32e9aa1331!8m2!3d32.9859295!4d-96.7503304!10e5!16zL20vMDJtdDJu?entry=ttu&g_ep=EgoyMDI2MDMyOS4wIKXMDSoASAFQAw%3D%3D), ta tìm được góc chụp tương ứng tại khu vực **Texas Instruments Plaza**, hướng nhìn về phía Tây Bắc.
  3. **Xác định loài cây:** Để có kết quả chính xác nhất về loài cây, ta sử dụng hệ thống quản lý cây xanh của trường qua [ArborPro Viewer](https://app.arborprousa.com/viewer/zV7oJABRbjSUs1FS/legacy_tree/h7tw64jrkt). Tại vị trí sân TI Plaza, hệ thống xác nhận cây lớn nhất ở giữa là **American Elm**.
  4. **Trích xuất tọa độ:** Tọa độ thu được từ hệ thống và Google Maps là `32.991057, -96.7478397`. Tiến hành làm tròn đến 3 chữ số thập phân theo yêu cầu của đề bài: `32.991` và `-96.748`.

> Flag: `texsaw{american_elm@(32.991,-96.748)}`
{: .prompt-flag }
