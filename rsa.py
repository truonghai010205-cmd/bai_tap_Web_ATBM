# -*- coding: utf-8 -*-
"""
CÀI ĐẶT THUẬT TOÁN RSA (mã hoá bất đối xứng / mã hoá khoá công khai)
=====================================================================
Gồm:
  - Sinh cặp khoá công khai (e, n) / bí mật (d, n)
  - Mã hoá / giải mã (đảm bảo BÍ MẬT nội dung)
  - Ký số / xác thực chữ ký (đảm bảo XÁC THỰC người gửi)
"""
import random
import hashlib


# ----------------------------------------------------------------------------
# 1. KIỂM TRA SỐ NGUYÊN TỐ (Miller-Rabin) VÀ SINH SỐ NGUYÊN TỐ LỚN
# ----------------------------------------------------------------------------
def is_prime(n: int, k: int = 20) -> bool:
    """Kiểm tra số nguyên tố bằng thuật toán Miller-Rabin (xác suất)."""
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small_primes:
        if n % p == 0:
            return n == p

    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


# ----------------------------------------------------------------------------
# 2. THUẬT TOÁN EUCLID MỞ RỘNG (tìm nghịch đảo modulo)
# ----------------------------------------------------------------------------
def egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Không tồn tại nghịch đảo modulo (a, m không nguyên tố cùng nhau)")
    return x % m


# ----------------------------------------------------------------------------
# 3. SINH CẶP KHOÁ RSA
# ----------------------------------------------------------------------------
def generate_keypair(bits: int = 1024):
    """
    Sinh cặp khoá RSA với modulus n có độ dài `bits`.
    Trả về ((e, n), (d, n))  =  (khoá CÔNG KHAI, khoá BÍ MẬT)

    Các bước:
      1. Chọn 2 số nguyên tố lớn p, q
      2. Tính n = p * q               (modulus, dùng cho cả 2 khoá)
      3. Tính phi(n) = (p-1)(q-1)     (hàm Euler)
      4. Chọn e sao cho 1 < e < phi(n) và gcd(e, phi(n)) = 1
      5. Tính d = e^-1 mod phi(n)     (nghịch đảo modulo của e)
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # số mũ công khai phổ biến (Fermat prime F4), tối ưu tốc độ mã hoá
    if egcd(e, phi)[0] != 1:
        e = 3
        while egcd(e, phi)[0] != 1:
            e += 2

    d = modinv(e, phi)
    return (e, n), (d, n)


# ----------------------------------------------------------------------------
# 4. MÃ HOÁ / GIẢI MÃ
# ----------------------------------------------------------------------------
def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(m: int) -> bytes:
    length = max((m.bit_length() + 7) // 8, 1)
    return m.to_bytes(length, "big")


def rsa_encrypt(message: bytes, pubkey) -> int:
    """c = m^e mod n"""
    e, n = pubkey
    m = _bytes_to_int(message)
    if m >= n:
        raise ValueError("Thông điệp quá lớn so với khoá, hãy dùng khoá dài hơn hoặc chia nhỏ dữ liệu")
    return pow(m, e, n)


def rsa_decrypt(ciphertext: int, privkey) -> bytes:
    """m = c^d mod n"""
    d, n = privkey
    m = pow(ciphertext, d, n)
    return _int_to_bytes(m)


# ----------------------------------------------------------------------------
# 5. KÝ SỐ / XÁC THỰC CHỮ KÝ
#    (băm thông điệp bằng SHA-256 rồi ký lên giá trị băm, thay vì ký cả bản
#     tin dài - đây là cách làm chuẩn trong thực tế, vừa nhanh vừa an toàn)
# ----------------------------------------------------------------------------
def rsa_sign(message: bytes, privkey) -> int:
    """Người gửi ký bằng khoá BÍ MẬT của chính mình."""
    d, n = privkey
    h = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
    return pow(h, d, n)


def rsa_verify(message: bytes, signature: int, pubkey) -> bool:
    """Người nhận xác thực bằng khoá CÔNG KHAI của người gửi."""
    e, n = pubkey
    h = int.from_bytes(hashlib.sha256(message).digest(), "big") % n
    h_from_sig = pow(signature, e, n)
    return h == h_from_sig


# ----------------------------------------------------------------------------
# 6. DEMO: 3 MÔ HÌNH ÁP DỤNG RSA
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    import time

    print("Đang sinh khoá RSA-1024 cho Alice (người gửi) và Bob (người nhận)...")
    t0 = time.time()
    pub_A, priv_A = generate_keypair(1024)
    pub_B, priv_B = generate_keypair(1024)
    print(f"(mất {time.time() - t0:.2f} giây)\n")

    message = "Chuyen 1000000 VND cho Bob".encode("utf-8")
    print("Thông điệp gốc:", message.decode("utf-8"))
    print()

    print("=" * 65)
    print("MÔ HÌNH 1: XÁC THỰC NGƯỜI GỬI (chữ ký số)")
    print("=" * 65)
    sig = rsa_sign(message, priv_A)
    ok = rsa_verify(message, sig, pub_A)
    print("- Alice KÝ thông điệp bằng khoá BÍ MẬT của Alice")
    print("- Bob XÁC THỰC bằng khoá CÔNG KHAI của Alice")
    print("- Kết quả xác thực:", "HỢP LỆ (đúng là Alice gửi)" if ok else "KHÔNG HỢP LỆ")
    print("- Đặc điểm: đảm bảo đúng người gửi + chống chối bỏ, KHÔNG bảo mật nội dung")
    print()

    print("=" * 65)
    print("MÔ HÌNH 2: XÁC THỰC NGƯỜI NHẬN (mã hoá bảo mật)")
    print("=" * 65)
    ct = rsa_encrypt(message, pub_B)
    pt = rsa_decrypt(ct, priv_B)
    print("- Alice MÃ HOÁ thông điệp bằng khoá CÔNG KHAI của Bob")
    print("- Chỉ Bob GIẢI MÃ được bằng khoá BÍ MẬT của Bob")
    print("- Bob nhận được:", pt.decode("utf-8"))
    print("- Đặc điểm: đảm bảo bí mật nội dung, KHÔNG xác thực ai là người gửi")
    print()

    print("=" * 65)
    print("MÔ HÌNH 3: KẾT HỢP CẢ HAI (ký + mã hoá)")
    print("=" * 65)
    sig2 = rsa_sign(message, priv_A)          # (1) Alice ký bằng khoá bí mật của Alice
    ct2 = rsa_encrypt(message, pub_B)         # (2) Alice mã hoá bằng khoá công khai của Bob
    # --- gửi (sig2, ct2) cho Bob ---
    pt2 = rsa_decrypt(ct2, priv_B)            # (3) Bob giải mã bằng khoá bí mật của Bob
    ok2 = rsa_verify(pt2, sig2, pub_A)        # (4) Bob xác thực bằng khoá công khai của Alice
    print("- Bob giải mã được nội dung:", pt2.decode("utf-8"))
    print("- Bob xác thực chữ ký:", "HỢP LỆ, đúng là Alice gửi" if ok2 else "KHÔNG HỢP LỆ")
    print("- Đặc điểm: đảm bảo ĐỒNG THỜI bí mật nội dung VÀ xác thực người gửi")
