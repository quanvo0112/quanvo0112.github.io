---
title: Full Weak Engineer CTF 2025
date: 2025-09-06 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, steganography, osint, minecraft]
---

## Misc

### Flagcraft

- **Độ khó:** Easy
- **Mô tả:** 
フラグをめっちゃ遠いところに隠したよ！見つけられるかな？(マイクラを買わなくても解けます)
I hid a flag really far away! Can you find it? (You don’t have to buy Minecraft to solve this chal)

- **Cách giải:**

Đầu tiên tôi mở file world thế giới mà kiểm tra thấy một folder `playerdata` thấy có 2 file **.dat**, tôi kiểm tra **.dat_old** thông qua một trang web là https://nbteditor.com/ 

Kéo xuống một chút và bấm vào phần Pos để lấy toạ độ  
![](/assets/img/fweCTF2025/flagcraft-1.png)  
Mở thế giới bằng minecraft phiên bản 1.16.5 (version của map) TP đến toạ độ đã lấy thông qua `/tp @a -3941108 120 99912988`  
![](/assets/img/fweCTF2025/flagcraft-2.png)  
Sau đó quét mã QR này để nhận flag thông qua (https://qrscanner.net/)  
![](/assets/img/fweCTF2025/flagcraft-3.png)  

- **Flag:** `fwectf{1_th1nk_m1n3cr4ft_15_th3_635t_94m3}`