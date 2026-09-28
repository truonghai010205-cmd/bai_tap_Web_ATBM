# -*- coding: utf-8 -*-
"""
SO SÁNH THỜI GIAN MÃ HOÁ / GIẢI MÃ GIỮA AES VÀ RSA
====================================================
Đo trực tiếp trên máy chạy chương trình (số liệu thực tế, không phải số liệu
tra cứu) để trả lời yêu cầu "so sánh thời gian mã hoá/giải mã của RSA với AES".
"""
import os
import time

from aes import aes_encrypt_cbc, aes_decrypt_cbc
from rsa import generate_keypair, rsa_encrypt, rsa_decrypt


def benchmark():
    key = os.urandom(16)
    iv = os.urandom(16)

    print("Đang sinh khoá RSA-1024 ...")
    t0 = time.perf_counter()
    pub, priv = generate_keypair(1024)
    print(f"  (sinh khoá RSA mất {time.perf_counter() - t0:.4f} giây)\n")

    print(f"{'Kích thước (byte)':<20}{'AES mã hoá (ms)':<20}{'AES giải mã (ms)':<20}")
    print("-" * 60)
    aes_64_enc_time = aes_64_dec_time = None
    for size in [16, 64, 256, 1024, 4096]:
        data = os.urandom(size)
        t0 = time.perf_counter()
        ct = aes_encrypt_cbc(data, key, iv)
        t1 = time.perf_counter()
        pt = aes_decrypt_cbc(ct, key, iv)
        t2 = time.perf_counter()
        enc_ms, dec_ms = (t1 - t0) * 1000, (t2 - t1) * 1000
        print(f"{size:<20}{enc_ms:<20.4f}{dec_ms:<20.4f}")
        if size == 64:
            aes_64_enc_time, aes_64_dec_time = enc_ms, dec_ms

    print()
    print("RSA-1024 (mỗi lần mã hoá tối đa ~117 byte do giới hạn độ dài khoá):")
    data = os.urandom(64)
    t0 = time.perf_counter()
    ct = rsa_encrypt(data, pub)
    t1 = time.perf_counter()
    pt = rsa_decrypt(ct, priv)
    t2 = time.perf_counter()
    rsa_enc_ms, rsa_dec_ms = (t1 - t0) * 1000, (t2 - t1) * 1000
    print(f"  Mã hoá (64 byte) : {rsa_enc_ms:.4f} ms")
    print(f"  Giải mã (64 byte): {rsa_dec_ms:.4f} ms")

    print()
    print("=" * 60)
    print("KẾT LUẬN (so sánh cùng kích thước dữ liệu 64 byte):")
    print(f"  RSA mã hoá chậm hơn AES mã hoá khoảng  {rsa_enc_ms / aes_64_enc_time:.1f} lần")
    print(f"  RSA giải mã chậm hơn AES giải mã khoảng {rsa_dec_ms / aes_64_dec_time:.1f} lần")
    print("=" * 60)


if __name__ == "__main__":
    benchmark()
