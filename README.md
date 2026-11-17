# LEX Crypto Project
## 1. Giới thiệu (Overview)

**LEX Crypto Project** là dự án nghiên cứu và triển khai thuật toán mật mã dòng **LEX (Leak Extraction)**, được đề xuất bởi Alex Biryukov và xây dựng dựa trên cấu trúc của AES (Advanced Encryption Standard).

Khác với việc sử dụng AES trực tiếp như một mật mã khối, LEX trích xuất một số byte từ trạng thái trung gian trong các vòng biến đổi AES để tạo ra dòng khóa (keystream). Dòng khóa được kết hợp với bản rõ thông qua phép XOR để thực hiện mã hóa và giải mã.

## 2. Mục tiêu (Objectives)

- Tìm hiểu cơ sở lý thuyết và nguyên lý hoạt động của LEX.
- Triển khai quá trình khởi tạo và sinh dòng khóa.
- Xây dựng chức năng mã hóa và giải mã dữ liệu.
- Kiểm thử tính đúng đắn của thuật toán bằng các test vector phù hợp.
- Đánh giá hiệu năng và tìm hiểu các hạn chế về an toàn mật mã.
- Xây dựng tài liệu kỹ thuật và quy trình kiểm thử tự động.

## 3. Nguyên lý hoạt động (How It Works)

LEX sử dụng các phép biến đổi của AES làm nền tảng để sinh dòng khóa. Ở mức khái quát, quá trình gồm các bước:

1. Khởi tạo trạng thái từ khóa bí mật (secret key) và vector khởi tạo (IV).
2. Thực hiện các vòng biến đổi dựa trên AES.
3. Trích xuất các byte được quy định từ trạng thái trung gian để sinh keystream.
4. Kết hợp keystream với dữ liệu đầu vào bằng phép XOR.

Công thức mã hóa và giải mã:

$$C = P \oplus Z$$

$$P = C \oplus Z$$

Trong đó:

- `P`: Plaintext — bản rõ.
- `C`: Ciphertext — bản mã.
- `Z`: Keystream — dòng khóa.
- `⊕`: Phép XOR.

Chi tiết về vị trí byte trích xuất và quá trình khởi tạo phụ thuộc vào đặc tả phiên bản LEX được triển khai.

## 4. Cấu trúc dự án (Project Structure)

```text
lex-crypto-project/
├── .github/
│   └── workflows/    # Cấu hình CI/CD
├── docs/             # Tài liệu nghiên cứu và đặc tả thuật toán
├── src/              # Mã nguồn triển khai LEX
├── tests/            # Kiểm thử thuật toán
├── .gitignore        # Các tệp không được Git theo dõi
├── LICENSE           # Giấy phép dự án
└── README.md         # Tài liệu tổng quan
```

## 5. Phân công công việc (Team Responsibilities)

| Thành viên | Phần việc | Branch | File phụ trách |
| :---: | --- | --- | --- |
| Ngọc | GF256, AES transforms | `feature/gf256-transforms` | `core/gf256.py`, `core/matrix_state.py`, `aes/sbox.py`, `aes/transforms.py` |
| Quân | Key schedule, AES chuẩn | `feature/aes-core` | `aes/key_schedule.py`, `aes/standard_aes.py` |
| Khánh | LEX engine, leak | `feature/lex-engine` | `lex/extractor.py`, `lex/round_engine.py` |
| Dương | Context, IV setup | `feature/context-setup` | `lex/validation.py`, `lex/context.py`, `lex/iv_setup.py` |
| Quyết | Keystream buffer, API | `feature/stream-api` | `lex/keystream.py`, `lex/api.py`, `run_demo.py` |

Mỗi thành viên phát triển trên branch được phân công và tạo Pull Request để tích hợp mã nguồn sau khi kiểm thử.

## 6. Cài đặt (Getting Started)

Clone repository về máy:

```bash
git clone https://github.com/hbaongoc/lex-crypto-project.git
cd lex-crypto-project
```

Hướng dẫn cài đặt môi trường, chạy chương trình và thực hiện kiểm thử sẽ được bổ sung sau khi hoàn thiện phần triển khai.

## 7. Tiến độ (Roadmap)

- [x] Khởi tạo repository và cấu trúc dự án.
- [ ] Nghiên cứu đặc tả thuật toán LEX.
- [ ] Triển khai các phép biến đổi AES cần thiết.
- [ ] Triển khai khởi tạo trạng thái và sinh keystream.
- [ ] Triển khai mã hóa và giải mã.
- [ ] Xây dựng test vector và unit test.
- [ ] Thiết lập kiểm thử tự động với GitHub Actions.
- [ ] Đánh giá hiệu năng và hoàn thiện tài liệu.

## 8. Tài liệu tham khảo (References)

- Alex Biryukov — *The Design of a Stream Cipher LEX*.
- [eSTREAM — The ECRYPT Stream Cipher Project](https://www.ecrypt.eu.org/stream/)
- [NIST FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)

