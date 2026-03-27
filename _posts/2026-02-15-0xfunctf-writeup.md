---
title: 0xFun CTF 2026
date: 2026-02-15 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, osint]
image:
  path: /assets/img/0xFunCTF2026/logo.png
---

## **OSINT**

### **MultiVerse**

- Tác giả: x03e
- Mô tả:  

I have a friend named **Massive-Equipment393** who’s obsessed with music. Try to figure out what his favorite genre is.

- Attachment:
- Cách giải: 

Search **Massive-Equipment393** thì GG trả về:

![](/assets/img/0xFunCTF2026/multiverse-1.png)

Bấm vào link reddit

![](/assets/img/0xFunCTF2026/multiverse-2.png)

Giải phần playlist thì với đoạn mã `49Rak48kGp7nJoUq9ofCX` với Base58

![](/assets/img/0xFunCTF2026/multiverse-3.png)

Nhìn lại tiêu đề Reddit với `Ph0n8xV1me`, khá khả nghi nên search thử:

![](/assets/img/0xFunCTF2026/multiverse-4.png)

Vào link Spotify: 

![](/assets/img/0xFunCTF2026/multiverse-5.png)

Kiểm tra từng playlist thì tôi phát hiện:

![](/assets/img/0xFunCTF2026/multiverse-6.png)

Phần mô tả của playlist có một đoạn mã `MHhmdW57c3AwdDFmeV8=`

Đem vào Cyberchef.org 

![](/assets/img/0xFunCTF2026/multiverse-7.png)

Bây giờ ta có 2 phần của flag: `0xfun{sp0t1fy_pl4yl1st`

Kiểm tra tiếp 2 playlist còn lại của tài khoản `Ph0n8xV1me` thì 1 playlist rỗng và 1 playlist lưu 11 bài hát

Nhìn vào playlist 11 bài hát, lấy từ kí tự đầu ở phần tên của mỗi bài hát ta có `_M0R3_TR4X}`. Ở đây thì do bài hát cuối và có dấu `{` không phù hợp nên chọn `}`

> Flag: `0xfun{sp0t1fy_pl4yl1st_3xt3nd_M0R3_TR4X}`
{: .prompt-flag }

> Đây là một bài OSINT cổ điển, không ngờ có ngày thấy nó lại. 
