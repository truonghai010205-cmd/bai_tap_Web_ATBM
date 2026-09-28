# -*- coding: utf-8 -*-
"""
CÀI ĐẶT THUẬT TOÁN AES-128 (Advanced Encryption Standard)
==========================================================
Cài đặt "from scratch" (không dùng thư viện mã hoá có sẵn) để thể hiện
đúng quy trình của thuật toán: SubBytes, ShiftRows, MixColumns, AddRoundKey.

AES-128 làm việc trên khối 128 bit (16 byte), khoá 128 bit (16 byte), 10 vòng lặp.
"""

# ----------------------------------------------------------------------------
# 1. BẢNG THẾ S-BOX VÀ INVERSE S-BOX (dùng cho bước SubBytes)
# ----------------------------------------------------------------------------
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

# Hằng số vòng (Round constant) dùng trong sinh khoá mở rộng
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

Nb = 4      # số cột của state (cố định = 4 cho AES)
Nk = 4      # số từ (word) của khoá gốc, AES-128 => 4
Nr = 10     # số vòng lặp, AES-128 => 10


# ----------------------------------------------------------------------------
# 2. CÁC PHÉP TOÁN TRÊN GF(2^8) (dùng cho MixColumns)
# ----------------------------------------------------------------------------
def gmul(a, b):
    """Nhân 2 phần tử trong trường hữu hạn GF(2^8) theo đa thức AES x^8+x^4+x^3+x+1."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return p


# ----------------------------------------------------------------------------
# 3. CÁC PHÉP BIẾN ĐỔI CHÍNH TRONG MỖI VÒNG
# ----------------------------------------------------------------------------
def sub_bytes(state):
    return [[S_BOX[b] for b in row] for row in state]


def inv_sub_bytes(state):
    return [[INV_S_BOX[b] for b in row] for row in state]


def shift_rows(state):
    """Dịch trái vòng: hàng r dịch trái r vị trí."""
    return [state[r][r:] + state[r][:r] for r in range(4)]


def inv_shift_rows(state):
    """Dịch phải vòng: hàng r dịch phải r vị trí."""
    return [state[r][-r:] + state[r][:-r] if r else state[r][:] for r in range(4)]


def mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3]
        new_state[1][c] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        new_state[2][c] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        new_state[3][c] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
    return new_state


def inv_mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        new_state[0][c] = gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9)
        new_state[1][c] = gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13)
        new_state[2][c] = gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11)
        new_state[3][c] = gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
    return new_state


def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# ----------------------------------------------------------------------------
# 4. SINH KHOÁ MỞ RỘNG (KEY EXPANSION / KEY SCHEDULE)
# ----------------------------------------------------------------------------
def key_expansion(key: bytes):
    """Từ khoá 16 byte, sinh ra 11 round key (mỗi round key 16 byte)."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]                 # RotWord
            temp = [S_BOX[b] for b in temp]             # SubWord
            temp[0] ^= RCON[i // Nk - 1]                 # XOR với Rcon
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(Nr + 1):
        rk = [[0] * 4 for _ in range(4)]
        for c in range(4):
            word = w[r * 4 + c]
            for row in range(4):
                rk[row][c] = word[row]
        round_keys.append(rk)
    return round_keys


# ----------------------------------------------------------------------------
# 5. CHUYỂN ĐỔI GIỮA BYTES <-> STATE (ma trận 4x4, đổ theo cột)
# ----------------------------------------------------------------------------
def bytes_to_state(data: bytes):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def state_to_bytes(state) -> bytes:
    data = [0] * 16
    for i in range(16):
        data[i] = state[i % 4][i // 4]
    return bytes(data)


# ----------------------------------------------------------------------------
# 6. MÃ HOÁ / GIẢI MÃ 1 KHỐI 16 BYTE (lõi thuật toán AES)
# ----------------------------------------------------------------------------
def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    assert len(plaintext) == 16 and len(key) == 16
    round_keys = key_expansion(key)
    state = bytes_to_state(plaintext)

    state = add_round_key(state, round_keys[0])          # vòng 0: chỉ AddRoundKey
    for rnd in range(1, Nr):                              # vòng 1..9
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    # vòng cuối (10): không có MixColumns
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[Nr])

    return state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    assert len(ciphertext) == 16 and len(key) == 16
    round_keys = key_expansion(key)
    state = bytes_to_state(ciphertext)

    state = add_round_key(state, round_keys[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ----------------------------------------------------------------------------
# 7. CHẾ ĐỘ CBC + PADDING PKCS#7 (để mã hoá được dữ liệu độ dài bất kỳ)
# ----------------------------------------------------------------------------
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = pkcs7_pad(plaintext)
    ciphertext = b""
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = aes_encrypt_block(xored, key)
        ciphertext += enc
        prev = enc
    return ciphertext


def aes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = aes_decrypt_block(block, key)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += xored
        prev = block
    return pkcs7_unpad(plaintext)


# ----------------------------------------------------------------------------
# 8. DEMO + KIỂM TRA VỚI TEST VECTOR CHUẨN FIPS-197
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("KIỂM TRA VỚI TEST VECTOR CHUẨN FIPS-197 (NIST)")
    print("=" * 60)
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    ct = aes_encrypt_block(pt, key)
    print("Khoá        :", key.hex())
    print("Bản rõ      :", pt.hex())
    print("Bản mã tính :", ct.hex())
    print("Bản mã chuẩn:", expected_ct.hex())
    print("=> KẾT QUẢ MÃ HOÁ:", "ĐÚNG" if ct == expected_ct else "SAI")

    dec = aes_decrypt_block(ct, key)
    print("Giải mã lại :", dec.hex())
    print("=> KẾT QUẢ GIẢI MÃ:", "ĐÚNG" if dec == pt else "SAI")

    print()
    print("=" * 60)
    print("DEMO: MÃ HOÁ VĂN BẢN ĐỘ DÀI BẤT KỲ (chế độ CBC)")
    print("=" * 60)
    key2 = b"ThisIsASecretKey"          # khoá 16 byte = 128 bit
    iv = b"1234567890abcdef"            # IV 16 byte
    message = "Xin chao, day la bai tap AES cua Nhom!".encode("utf-8")

    ciphertext = aes_encrypt_cbc(message, key2, iv)
    plaintext_back = aes_decrypt_cbc(ciphertext, key2, iv)

    print("Khoá (16 byte) :", key2)
    print("Bản rõ         :", message.decode("utf-8"))
    print("Bản mã (hex)   :", ciphertext.hex())
    print("Giải mã lại    :", plaintext_back.decode("utf-8"))
    print("=> KHỚP VỚI BẢN RÕ GỐC:", "ĐÚNG" if plaintext_back == message else "SAI")
