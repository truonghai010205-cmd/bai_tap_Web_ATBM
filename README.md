# Bài tập về nhà

Deadline: **23h59 ngày 28/9/2026** — làm trên máy cá nhân, đẩy code lên GitHub (repo public).

## Cấu trúc thư mục

```
bai-tap-ve-nha/
├── an-toan-bao-mat/          # Môn An toàn và bảo mật thông tin
│   ├── README.md             # Lý thuyết DES/AES/RSA + mô hình + so sánh tốc độ
│   ├── aes.py                # Cài đặt AES-128 từ đầu (đã test đúng chuẩn FIPS-197)
│   ├── rsa.py                # Cài đặt RSA: sinh khoá, mã hoá/giải mã, ký số
│   └── benchmark_rsa_aes.py  # So sánh tốc độ AES vs RSA (số liệu đo thực tế)
│
└── lap-trinh-web/            # Môn Lập trình web
    ├── README.md              # Hướng dẫn cài đặt/chạy chi tiết từng bước
    ├── bai-tap-1/              # WSL/VM + Docker Compose (nginx, nodered, mariadb,
    │                            # phpmyadmin, cloudflared) + nginx 2 domain
    └── bai-tap-2/              # API Node-RED + nginx proxy + HTML/JS gọi API
```

Xem chi tiết lý thuyết, giải thích và hướng dẫn chạy trong README của từng thư mục con.

## Kiểm tra nhanh phần đã chạy được ngay (không cần Docker/domain)

```bash
cd an-toan-bao-mat
python3 aes.py                # kiểm tra AES đúng test vector FIPS-197
python3 rsa.py                # demo 3 mô hình áp dụng RSA
python3 benchmark_rsa_aes.py  # so sánh tốc độ AES vs RSA
```

Phần `lap-trinh-web/` cần Docker + domain thật nên phải chạy trên máy bạn theo hướng dẫn
trong [`lap-trinh-web/README.md`](lap-trinh-web/README.md).

## Đẩy code lên GitHub

```bash
cd bai-tap-ve-nha
git init
git add .
git commit -m "Bai tap ve nha: An toan bao mat + Lap trinh web"
git branch -M main
git remote add origin <URL_REPO_GITHUB_CUA_BAN>
git push -u origin main
```

(Repo GitHub nhớ để **Public** theo đúng yêu cầu đề bài.)
