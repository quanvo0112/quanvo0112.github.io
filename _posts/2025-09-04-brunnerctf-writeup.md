---
title: BrunnerCTF 2025
date: 2025-09-04 09:00:00 +0700
categories: [Security, CTF]
tags: [writeup, steganography, crypto, osint, web-security, python, lfi, command-injection, minecraft]
---

# Shake & Bake
## Join the Discord!
- **Độ khó:** Intro
- **Tác giả:** BrunnerCTF
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/join-the-discord.png)
- **Cách giải:**  
1. Nhấn vào link discord trên phần mô tả của challenge.
2. Trong mô tả có đề cập phần announcements (thông báo), do đó nhấn vào announcements.
3. Kiểm tra phần thông báo khai mạc cuộc thi thì thấy tin nhắn ẩn (hidden), click vào để hiện thì thu được flag.
- **Flag:** `brunner{1t5_4_P13C3_0f_c4K3_T0_B4k3_4_pr3TTy_C4k3!}`

---
## TheBakingCase/Misc-Steganography
- **Độ khó:** Beginner
- **Tác giả:** H4N5
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/misc-steganography.png)
- **Cách giải:**  
```python  
puzzle_text = """
i UseD to coDE liKe A sLEEp-dEprIVed SqUirRel smasHInG keYs HOPinG BugS would dISApPear THrOugh fEAr tHeN i sPilled cOFfeE On mY LaPTop sCReameD iNTerNALly And bakeD BanaNa bREAd oUt oF PAnIc TuRNs OUT doUGh IS EasIEr tO dEbUG ThaN jaVASCrIPt Now I whIsPeR SWEEt NOtHIngs TO sOurDoUGh StARtERs aNd ThReATEN CrOissaNts IF they DoN'T rIsE My OVeN haS fEWeR CRasHEs tHAN mY oLD DEV sErvER aNd WHeN THInGS BurN i jUSt cAlL iT cARAMElIzEd FeatUReS no moRE meetInGS ThAt coUlD HAVE bEeN emailS JUst MufFInS THAt COulD HAvE BEen CupCAkes i OnCE tRIeD tO GiT PuSh MY cInnAmON rOLLs aND paNICkED WHEn I coUldn't reVErt ThEm NOw i liVe IN PeaCE uNLESs tHe yEast getS IDeas abOVe iTs StATion oR a COOkiE TrIES To sEgfAult my toOTH FILlings
"""

binary_string = ""
for char in puzzle_text:
    if char.isalpha():
        if char.islower():
            binary_string += "0"
        elif char.isupper():
            binary_string += "1"

hidden_message = ""
for i in range(0, len(binary_string), 8):
    byte = binary_string[i:i+8]
    if len(byte) == 8:
        decimal_value = int(byte, 2)
        hidden_message += chr(decimal_value)

print(f"The hidden message is: {hidden_message}")
```

- **Flag:** `brunner{I_like_Baking_More_That_Programming}`

## BasedBrunner/Misc
- **Độ khó:** Beginner
- **Tác giả:** Nissen
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/based-brunner.png)

- **Cách giải:**  
```python     
def decode_step(text: str, base: int) -> str:
    encoded_parts = text.split(' ')  
    decoded_chars = [chr(int(part, base)) for part in encoded_parts]
    return "".join(decoded_chars)

file_path = "../based.txt" 
with open(file_path, "r") as f:
    text = f.read().strip()

for base in range(2, 11):
    text = decode_step(text, base)

print("Decoded Flag:")
print(text)
```  

- **Flag:** `brunner{1s_b4s3d}`

## Whisk/Crypto
- **Độ khó:** Beginner
- **Tác giả:** rvsms
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/whisk.png)
- **Cách giải:**  
```python  
ciphertext = """
DR🥐 C🥐TZ🥐D 🧁SXZ🥐A🧁🥐SD 🧁C 🍰KE🍰FC K🍩M🥐. D🍩 O🍰Q🥐 🍰 Y🥐ZP🥐TD
OZ🥖SCM🧁X🥐Z, H🥐KD O🥖DD🥐Z E🧁DR OZ🍩ES C🥖X🍰Z, Y🍩🥖Z 🧁D 🍩M🥐Z DR🥐 E🍰ZH
A🍩🥖XR, 🍰SA K🥐D DR🥐 CFZ🥖Y C🥐🥐Y 🧁SD🍩 🥐M🥐ZF T🍩ZS🥐Z. D🍰CD🥐, CH🧁K🥐,
🍰SA Z🥐H🥐HO🥐Z: CR🍰Z🧁SX Y🍰CDZF N🍩F 🧁C H🍰SA🍰D🍩ZF.
OZ🥖SS🥐Z{S0_H0Z3_K🥖HYF_T1YR3Z}
"""

# cipher_crib = "OZ🥖SCM🧁X🥐Z"
# plain_crib = "BRUNSVIGER"

substitution_map = {
    # Letters
    'A': 'D', 'C': 'S', 'D': 'T', 'E': 'W', 'F': 'Y',
    'H': 'M', 'K': 'L', 'L': 'F', 'M': 'V', 'N': 'J',
    'O': 'B', 'Q': 'K', 'R': 'H', 'S': 'N', 'T': 'C',
    'X': 'G', 'Y': 'P', 'Z': 'R',
    # Emojis
    '🥐': 'E', '🧁': 'I', '🍰': 'A', '🍩': 'O', '🥖': 'U'
}

def decrypt(text, key_map):
    plaintext = ""
    for char in text:
        plaintext += key_map.get(char, char)
    return plaintext

decrypted_message = decrypt(ciphertext, substitution_map)

print("--- Decrypted Message ---")
print(decrypted_message)
print("\n" + "="*25 + "\n")
```  

- **Flag:** `brunner{N0_M0R3_LUMPY_C1PH3R}`

---

# Misc
## The Yeast Key
- **Độ khó:** Easy
- **Tác giả:** H4N5
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/the-yeast-key.png)
- **Cách giải:**  
```python  
import base64

dna_sequence = "CGAGCTAGCTCCCGTGCGTGCGCCCTAGCTGTATACCGGCATAACGTGATATCGTACCTTCTAAATAACGGCATACATCACGTGATATCCTTCGTCATCAATCCATCTATATCTAGCCTTATAACGCGCCTTATCCATAACTCCCTAGCGCAATAACTCCATCGCGGACCTTCTAAATCAATCCATCCCTAACGGACTAGATCAATCCATATCCTTATACATCCCCTTCGATCTAGATAAATACATCCATCCATCACGTGATCTCCCGATCACTCCATACATCTAGACATGCATATCTTC"
dna_to_base4 = {
    'A': 0,
    'C': 1,
    'G': 2,
    'T': 3
}
base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
encoded_base64_string = ""

for i in range(0, len(dna_sequence), 3):
    codon = dna_sequence[i:i+3]
    val1 = dna_to_base4[codon[0]]
    val2 = dna_to_base4[codon[1]]
    val3 = dna_to_base4[codon[2]]
    decimal_value = (val1 * 16) + (val2 * 4) + val3
    encoded_base64_string += base64_chars[decimal_value]

print("--- Step 1: Generated Base64 String ---")
print(encoded_base64_string)
print("\n" + "="*40 + "\n")

try:
    decoded_bytes = base64.b64decode(encoded_base64_string)
    vault_key = decoded_bytes.decode('utf-8')

    print("--- Step 2: Decoded Vault Key ---")
    print(vault_key)
except Exception as e:
    print(f"An error occurred during Base64 decoding: {e}")
```  
- **Flag:** 
`brunner{1i0n3l_p0i14n3_m4573r_0f_50urd0u6h_p455phr453_15_cr01554n7V4u17!93}`

---
## Pie Recipe
- **Độ khó:** Easy
- **Tác giả:** H4N5
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/pie-recipe.png)  
- **Cách giải:**  
```python  
import base64

def solve_phi_recipe(encoded_string: str) -> str:
    zeckendorf_groups = encoded_string.strip().split('|')
    ascii_codes = [
        sum(int(num) for num in group.split('.'))
        for group in zeckendorf_groups
    ]
    base64_string = "".join([chr(code) for code in ascii_codes])
    try:
        decoded_bytes = base64.b64decode(base64_string)
        final_answer = decoded_bytes.decode('utf-8')
    except Exception as e:
        return f"An error occurred during Base64 decoding: {e}"

    return {
        "ascii_codes": ascii_codes,
        "base64_string": base64_string,
        "final_answer": final_answer
    }

if __name__ == "__main__":
    recipe_code = "89|89.21|55.13.5.1|34.13.2|89.8.1|89.13.5.2|34.13.5.1|89.13.5.1|89.8.2|89.21|89.21.5|34.13.3.1|89.8|55.13|55.21.2|89.13|89.1|89.21.8.3.1|55.8.2|89.21.8.2|89.1|55.13|55.21.2|89.21.5.2|55.21.8.3.1|34.13.3.1|55.8.3|89.21.1|55.21.1|55.21.8.2|55.1|89.21.8.1|89.1|89.13.5.1|55.2|34.13.5.2|89.1|55.21.8.3|55.21.2|89.21.3.1|89.1|55.21.8.3|34.13.5.1|89.13.5|89.8.1|34.13.3.1|55.13.5.1|89.13.5.2|89.13|55.21.5|55.5.1|55.5.1"
    results = solve_phi_recipe(recipe_code)

    print(f"  The creator of the recipe is: {results['final_answer']}")
```  
- **Flag:** `brunner{7h3_g01d3n_ph1_0f_zeckendorf}`

---

## Cake Vault
- **Độ khó:** Medium
- **Tác giả:** OddNorseman
- **Mô tả:**  
![](/assets/img/BrunnerCTF2025/cake-vault.png)
- **Cách giải:**  
1. Tải file zip từ thử thách về, khá bất ngờ đó là một file map của game Minecraft
2. Khá may mắn là có game Minecraft trong máy, sau đó copy file map được cho vào thư mục `/saves` từ thư mục của game.
3. Tôi có thử tạm một phiên bản 1.21.4 để kiểm tra rằng map được tạo ra từ phiên bản nào thì phát hiện map được tạo ra ở phiên bản 1.21.8.
4. Tôi thoát game và thay đổi phiên bản 1.21.8 sau đó khởi động lại game.
5. Tôi vào thế giới và phát hiện một cuốn sách đặt được trên kệ (Lactern), mở ra thì là lời chào tới map.
6. Sau đó nhìn xung quanh thì tôi thấy có một tảng đá hay hang nhỏ nhân tạo với một bức tường khối bê tông xám (Gray Concrete Powder). Trên đó có một bảng ghi là 'Unlock me ...'. 
7. Kế bên đó là một công trình Redstone nhằm mục đích gì đó. Nó khá là to nên tôi có đi xung quanh để xem thử.
8. Cảm thấy hơi bế tắc, tôi đã nghĩ rằng sẽ có bí ẩn gì đó đang được giấu cho nên tôi đã dùng phím tắt `F3 + F4`. Đây là một phím tắt giúp chuyển đổi các chế độ trong Minecraft. Khi tôi chuyển sang chế độ Khán giả (Spectator Mode).
9. Tôi đã bay vào "hang đá nhỏ" để xem bên trong liệu có giấu gì hay không. Tôi kiểm tra từng cái thùng gỗ (Barrel) nhưng không thấy có gì bất thường. Quan sát xung quanh để xem có rương ẩn hay không thì cũng không thấy gì cả.
10. Tôi bay vào phần công trình Redstone thì thấy có một đường đá đỏ dẫn đến "hang đá nhỏ". Đường đá đỏ đó dùng để kích hoạt "cửa hang" (Gravity Blocks Piston Door)
11. Việc cần làm của tôi là bấm các nút đá (Stone Button) ở các khối đèn đồng bị ôxy hoá (Oxidized Copper Bulb) để làm cho "cửa hang" mở ra
12. Sau khi "cửa hang" mở, tôi đã gõ toàn bộ độ sáng của các khối đèn đồng bị ôxy hoá, với bật sáng là 1, tắt là 0
![](/assets/img/BrunnerCTF2025/cake-vault-2.png)
```
0110101101100001011001110110010101101101011000010110111001100100
```
13. Sau đó tôi dùng Cyberchef đổi mã nhị phân sang ASCII: `kagemand`

- **Flag:** `brunner{kagemand}`

---

# OSINT
## There Is a Lovely Land
- **Độ khó:** Easy
- **Tác giả:** Toxicd
- **Mô tả:**

The Danish national anthem is called "Der er et yndigt land" ("There Is a Lovely Land"), and I fully agree. 
A friend of mine took this picture, but I don't know the name of the bridge! Please help me find it so I can go see it!
**Flag format:**  `brunner{<bridge name in Danish in lowercase>}`  
**Example:**  `brunner{storebæltsbroen}`

- **Cách giải:**
![](/assets/img/BrunnerCTF2025/there-is-a-lovely-land.png)

- **Flag:** `brunner{sallingsundbroen}`

---
## Train Mania
- **Độ khó:** Easy
- **Tác giả:** Quack
- **Mô tả:**

I recently stumpled upon this cool train! But I'd like to know a bit more about it... Can you please tell me the operating company, model number and its maximum service speed (km/h in regular traffic)?
The flag format is brunner{OPERATOR-MODELNUMBER-SERVICESPEED}.
So if the operator you have found is DSB, the model number RB1, and the maximum service speed is 173 km/h, the flag would be brunner{DSB-RB1-173}.


- **Cách giải:**

![](/assets/img/BrunnerCTF2025/train-mania.png)

- **Flag:** `brunner{SJ-X2-200}`

---

# Web
## Brunsviger Huset
- **Độ khó:** Easy-Medium
- **Tác giả:** ha1fdan
- **Mô tả:**

Welcome to "Brunsviger Huset" (House of Brunsviger), the oldest Danish bakery in town! Our bakers have been perfecting their craft for over 150 years, and our signature brunsviger is a favorite among locals and tourists alike. But, it seems like our bakery has a secret ingredient that's not on the menu...

Can you find the hidden flag that's been baked into our website? Be warned, our bakers are notorious for their clever hiding spots!

- **Cách giải:**
Kiểm tra trang web thông qua curl
```
curl https://brunsviger-huset-9fca8e5675be40db.challs.brunnerne.xyz/
```
![](/assets/img/BrunnerCTF2025/brunsviger-huset-1.png)  
Kiểm tra có thấy một đoạn code thêm vào một file `robots.txt`. Do đó thử thêm đoạn robots.txt trên URL của Challenge  
![](/assets/img/BrunnerCTF2025/brunsviger-huset-2.png)
Từ đây tôi nghĩ rằng mình cần truy cập thử vào `print.php` hoặc là `secrets.php`  
Tôi có thử command injection để biết mã nguồn thì kết quả trả về như thế này  
![](/assets/img/BrunnerCTF2025/brunsviger-huset-3.png)  
```
PD9waHAKaWYgKGlzc2V0KCRfR0VUWydmaWxlJ10pKSB7CiAgICAkZmlsZSA9ICRfR0VUWydmaWxlJ107CgogICAgaWYgKHN0cnBvcygkZmlsZSwgJ3BocDovLycpID09PSAwIHx8IGZpbGVfZXhpc3RzKCRmaWxlKSkgewogICAgICAgIGluY2x1ZGUoJGZpbGUpOwogICAgfSBlbHNlIHsKICAgICAgICBlY2hvICJGaWxlIG5vdCBmb3VuZC4iOwogICAgfQp9IGVsc2UgewogICAgZWNobyAiTm8gZmlsZSBzcGVjaWZpZWQuIjsKfQo
```
Tôi liền sử dụng **CyberChef** để biết được đoạn mã hoá base64 tôi đã kéo về từ mã nguồn của trang web  
![](/assets/img/BrunnerCTF2025/brunsviger-huset-4.png)  
Từ đây tôi thấy mình đã đúng hướng giải challenge này. Sau đó tôi tiếp tục dựa vào đoạn code base64 đã được giải mã để khai thác tiếp  
```
https://brunsviger-huset-9fca8e5675be40db.challs.brunnerne.xyz/print.php?file=php://filter/convert.base64-encode/resource=secrets.php
```
![](/assets/img/BrunnerCTF2025/brunsviger-huset-5.png)  

- **Flag:** `brunner{l0c4l_f1l3_1nclus10n_1n_th3_b4k3ry}`

---
## Baking Bad
- **Độ khó:** 
- **Tác giả:** 0xjeppe
- **Mô tả:**

This new kid on the block, Bake'n'berg, has taken over the market with some new dough that has 99.2% purity. Ours is not even 60%!

Our bakers have been trying to come up with a new P2P-recipe trying all sorts of weird ingredients to raise the purity, but it's so costly this way.

Luckily, the developers at Brunnerne have come up with a bash -c 'recipe' that can simulate the baking process.
This way we can test ingredients in a simulator to find ingredients that result in a higher purity - without wasting any ressources.
- **Cách giải:**
Tôi thử injection một tí, kết quả khá là oke 
![](/assets/img/BrunnerCTF2025/baking-bad-1.png)
Sau đó tôi có mò thêm các command injection có sẵn trên mạng thì kết quả đã có
![](/assets/img/BrunnerCTF2025/baking-bad-2.png)
- **Flag:** `brunner{d1d_1_f0rg37_70_b4n_s0m3_ch4rz?}`