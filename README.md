# 🛡️ Mini AI VPN Gateway LSTM

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/TensorFlow--CPU-2.15-orange?style=for-the-badge&logo=tensorflow&logoColor=white" alt="TensorFlow CPU" />
  <img src="https://img.shields.io/badge/Zeek-IDS-green?style=for-the-badge&logo=security&logoColor=white" alt="Zeek IDS" />
  <img src="https://img.shields.io/badge/WireGuard-VPN-purple?style=for-the-badge&logo=wireguard&logoColor=white" alt="WireGuard VPN" />
  <img src="https://img.shields.io/badge/OS-Ubuntu%2024.04%2F25.04-red?style=for-the-badge&logo=ubuntu&logoColor=white" alt="OS Ubuntu" />
</p>

---

## 📖 1. Giới thiệu tổng quan (Overview)

**Mini AI VPN Gateway LSTM** là một hệ thống Phát hiện và Ngăn chặn Xâm nhập (IPS) thời gian thực thế hệ mới, được tích hợp trực tiếp tại Gateway của mạng riêng ảo WireGuard. 

Khác biệt hoàn toàn với các giải pháp IPS truyền thống dựa trên luật tĩnh (Rule-based) vốn dễ bị qua mặt và tốn công bảo trì, hệ thống này đã được nâng cấp toàn diện sang kiến trúc **Trí tuệ Nhân tạo (Deep Learning)**. Bằng việc sử dụng mạng nơ-ron hồi quy **LSTM (Long Short-Term Memory)**, hệ thống có khả năng phân tích sâu chuỗi hành vi mạng theo thời gian thực để phát hiện các kỹ thuật tấn công tinh vi như **Port Scan**, **C2 Beaconing (mã độc giao tiếp định kỳ)** và **DNS Tunneling**.

Đặc biệt, hệ thống được thiết kế theo triết lý tối giản và siêu nhẹ để triển khai trực tiếp trên các thiết bị Edge hoặc Máy ảo (Ubuntu VM), sử dụng động cơ suy luận tối ưu **tensorflow-cpu** với bộ nhớ RAM cực kỳ tiết kiệm.

---

## 🛠️ 2. Pipeline Hoạt động (Operation Pipeline)

Sơ đồ ASCII dưới đây mô tả chi tiết đường ống xử lý dữ liệu khép kín từ lúc Client gửi gói tin qua VPN cho đến khi AI đưa ra quyết định chặn tường lửa:

```text
==========================================================================================
                     MẠNG RIÊNG ẢO WIREGUARD VPN & PIPELINE XỬ LÝ AI IPS
==========================================================================================

   [ VPN Client ]          [ Bình thường / Whitelist ]   ----------> Cho phép truy cập
         │                                                            ▲
         ▼ (wg0 Interface)                                           │
  ┌──────────────┐         ┌─────────────────────────┐               │
  │  Zeek Engine │ ───►   │ Whitelist Parser        │ ──── (Bypass) ──┘
  │  (conn.log)  │         │ (whitelist.conf)        │
  └──────────────┘         └────────────┬────────────┘
                                        │ (Nếu không nằm trong Whitelist)
                                        ▼
                           ┌─────────────────────────┐
                           │ Log Discretizer         │ ◄─── rolling FIFO deque
                           │ (Mã hóa chuỗi 20 ký tự)  │      (collections.deque)
                           └────────────┬────────────┘
                                        │
                                        ▼
                           ┌─────────────────────────┐
                           │ Cold Start Checker      │ ─── (Chuỗi < 20 ký tự) ──► Graceful Wait
                           └────────────┬────────────┘
                                        │ (Chuỗi đã nạp đủ 20 ký tự)
                                        ▼
                           ┌─────────────────────────┐
                           │ AI Scoring Engine V2    │
                           │ (lstm_model.tflite)     │ ◄─── tensorflow-cpu (Edge)
                           └────────────┬────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼ (Risk Score < 80.0%)        ▼ (Risk Score >= 80.0%)
                    [ SAFE TRAFFIC ]            [ MALICIOUS DETECTED ]
                         │                             │
                         ▼                             ▼
                 Cho phép đi qua               ┌───────────────┐
                                               │ iptables DROP │ (Tống xuất khỏi VPN)
                                               └───────────────┘
==========================================================================================
```

---

## ✨ 3. Tính năng nổi bật (Features)

*   **⚡ Loại bỏ hoàn toàn luật tĩnh (Zero Hardcoded Rules):** Không còn các luật so khớp tĩnh hay hệ thống cộng trừ điểm thủ công dễ bị bypass. Hệ thống trao quyền quyết định hoàn toàn cho mạng Deep Learning LSTM tự động nhận diện mẫu hành vi độc hại.
*   **🧠 Mạng nơ-ron hồi quy LSTM nâng cấp:** Khả năng ghi nhớ và phân tích mối liên hệ thời gian giữa các kết nối liên tiếp, cực kỳ nhạy bén với các hành vi C2 Beaconing phát tín hiệu ngắt quãng định kỳ.
*   **🔄 Cơ chế Sliding Window FIFO (collections.deque):** Bộ đệm lưu trữ chuỗi ký tự của mỗi IP sử dụng cửa sổ trượt trơn tru có độ dài tối đa 20 ký tự. Khi kết nối thứ 21 tới, ký tự cũ nhất sẽ tự động được giải phóng để nạp ký tự mới, đảm bảo AI luôn luôn giám sát 20 hành vi gần nhất mà không làm phình to bộ nhớ.
*   **🛡️ Khởi động nguội an toàn (Cold Start / Graceful Wait):** Ngăn ngừa tuyệt đối lỗi crash không khớp chiều dữ liệu (dimension mismatch). Khi IP mới kết nối và có ít hơn 20 kết nối, hệ thống sẽ chỉ ghi nhận chuỗi tích lũy mà bỏ qua suy luận AI cho đến khi đủ điều kiện.
*   **🛡️ Tự động chặn chủ động (Active Response):** Khi xác suất độc hại vượt ngưỡng **80.0%** (Threat Threshold), hệ thống ngay lập tức gọi lệnh hệ thống áp cấu trúc chặn cứng IP nguồn qua `iptables DROP` để ngăn chặn rò rỉ dữ liệu hoặc leo thang đặc quyền.
*   **📈 Tối ưu hóa tuyệt đối cho Edge VM:** Bằng việc nạp file mô hình siêu nhẹ dạng TFLite (`lstm_model.tflite`) và chạy trên `tensorflow-cpu`, hệ thống chỉ tốn **~15MB RAM** vận hành, giảm 97% tài nguyên so với việc nạp đầy đủ framework TensorFlow truyền thống.

---

## 🔬 4. Cảm hứng & So sánh với Stratosphere Slips

Dự án này kế thừa và phát triển từ kiến trúc cốt lõi của **Stratosphere Linux IPS (Slips)** – một hệ thống phát hiện xâm nhập hành vi mạng mã nguồn mở nổi tiếng do Đại học Kỹ thuật Séc (CTU) phát triển.

### 🤝 Điểm giống nhau
- **Triết lý Behavioral Letters:** Kế thừa trọn vẹn ý tưởng gom nhóm các luồng mạng theo từng địa chỉ IP từ log Zeek và mã hóa các thuộc tính (Duration, Size, Interval) thành các ký tự chữ cái đại diện. Chuỗi ký tự này tạo thành một bức tranh toàn cảnh về hành vi kết nối của Client.

### 🚀 Điểm khác biệt (Sự tối ưu hóa)

| Tiêu chí so sánh | 🌐 Stratosphere Slips (Bản gốc) | ⚡ Mini AI VPN Gateway (Dự án này) |
| :--- | :--- | :--- |
| **Kiến trúc hệ thống** | Cực kỳ đồ sộ, chạy đa tiến trình phức tạp. Phụ thuộc nặng vào Redis DB để truyền tin. | Tinh giản, khép kín, hoạt động dưới dạng Single-Process bất đồng bộ gọn nhẹ. Không cần Redis. |
| **Động cơ quyết định** | Tổ hợp nhiều module rule-based, thống kê, chuỗi Markov và học máy cổ điển chạy song song. | **Loại bỏ hoàn toàn luật tĩnh.** Tập trung toàn bộ "hỏa lực" vào một lõi Deep Learning LSTM duy nhất. |
| **Tiêu hao bộ nhớ (RAM)**| Thường yêu cầu từ **1.5 GB - 3 GB+ RAM**, không phù hợp cho các thiết bị Edge cấu hình thấp. | Cực kỳ tiết kiệm, chỉ tốn **~15 MB RAM** nhờ mô hình LSTM TFLite và engine suy luận tối giản. |
| **Khả năng tự động chặn** | Hỗ trợ nhiều script mở rộng cấu hình phức tạp. | Gọi lệnh `iptables` trực tiếp hoặc giả lập chặn thông minh cực nhanh (<30ms latency). |

> [!NOTE]
> Bằng cách cắt tỉa toàn bộ các module rule-based cồng kềnh của Slips, Mini AI VPN Gateway tập trung giải quyết bài toán cốt lõi: Phân tích chuỗi hành vi bằng Deep Learning với tài nguyên siêu nhẹ, mang lại hiệu năng tối đa cho các hệ thống biên (Edge VM / CPE).

---

## 📋 5. Yêu cầu hệ thống (Prerequisites)

*   **Hệ điều hành:** Ubuntu Linux (Khuyến nghị **24.04 / 25.04 LTS**).
*   **VPN Gateway:** Đã cài đặt dịch vụ **WireGuard** hoạt động trên interface `wg0`.
*   **IDS Logs:** Đã cài đặt **Zeek IDS** cấu hình giám sát interface `wg0` và xuất log ra thư mục mặc định (`/opt/zeek/logs/current/conn.log` hoặc thư mục tự chọn).
*   **Môi trường:** Python **3.11** cài đặt sẵn trên hệ điều hành.

---

## 💾 6. Hướng dẫn Cài đặt (Installation)

Hãy triển khai môi trường Python ảo độc lập để cô lập các thư viện MLOps một cách chuyên nghiệp theo các bước sau:

**Bước 1: Tạo môi trường ảo Python 3.11**
```bash
python3.11 -m venv vpn_env
```

**Bước 2: Kích hoạt môi trường ảo**
```bash
source vpn_env/bin/activate
```

**Bước 3: Cài đặt các thư viện AI chuẩn xác**
```bash
pip install tensorflow-cpu "numpy<2.0.0" colorama pyyaml
```

> [!IMPORTANT]
> - Việc sử dụng `numpy<2.0.0` là bắt buộc để tương thích tuyệt đối với cấu trúc dữ liệu của thư viện suy luận `tensorflow-cpu`.
> - Thư viện `pyyaml` được sử dụng để phân tích cú pháp tệp cấu hình slips.yaml.

---

## 🚀 7. Hướng dẫn Sử dụng (Usage)

Do hệ thống phải tương tác trực tiếp với tường lửa Linux (`iptables`) để khóa các IP xâm nhập, bạn bắt buộc phải khởi chạy Gateway bằng quyền **root (sudo)** và trỏ trực tiếp vào Python của môi trường ảo:

```bash
sudo ./vpn_env/bin/python main_vpn_ids.py
```

### Cấu hình hệ thống linh hoạt:
- **`config/slips.yaml`:** Quản lý tham số hệ thống (ngưỡng xác suất chặn Threat Threshold, đường dẫn log Zeek, chế độ giả lập chặn - simulation mode).
- **`config/whitelist.conf`:** Định nghĩa các IP nguồn, IP đích, CIDR hoặc tên miền tin cậy (ví dụ: `8.8.8.8`, `wikipedia.org`) để bypass sớm ở cổng vào, giúp tối ưu hóa CPU tối đa.

---

## 🧪 8. Kịch bản Kiểm thử Tích hợp (Testing Scenarios)

Dự án cung cấp sẵn một kịch bản kiểm thử tích hợp tự động hoàn chỉnh mô phỏng các hành vi thực tế để bạn kiểm tra luồng hoạt động mà không cần setup VPN hay Zeek thật:

### Chạy kiểm thử tự động 4 kịch bản:
```bash
./vpn_env/bin/python scripts/test_system_v2.py
```

Khi chạy script trên, hệ thống sẽ giả lập luồng log Zeek ghi vào `dataset/conn.log` và xác minh 4 hành vi sau:

### 🟢 Kịch bản 1: Whitelist Bypass (IP & Domain tin cậy)
- **Hành vi giả lập:** Gửi log từ IP nguồn `8.8.8.8` hoặc truy vấn DNS đến `wikipedia.org`.
- **Kết quả hiển thị trên Terminal:**
  ```text
  [WHITELIST] Bypass/Ignore luồng kết nối tin cậy: SRC=8.8.8.8
  ```
- **Ý nghĩa:** Traffic an toàn được bypass ngay lập tức trước khi đi vào lõi AI, bảo vệ tài nguyên CPU.

### 🟡 Kịch bản 2: Cold Start Protection (Khởi động nguội)
- **Hành vi giả lập:** IP mới `192.168.10.12` bắt đầu gửi các kết nối đầu tiên.
- **Kết quả hiển thị trên Terminal:**
  ```text
  [COLD_START] IP 192.168.10.12 đang thu thập dữ liệu chuỗi: 12/20 ký tự (Chưa đủ điều kiện suy luận AI)
  ```
- **Ý nghĩa:** Bảo vệ Graceful Wait hoạt động đúng, bỏ qua suy luận AI cho đến khi thu thập đủ 20 ký tự.

### 🔵 Kịch bản 3: Normal Traffic (Hành vi an toàn)
- **Hành vi giả lập:** IP gửi gói tin ngẫu nhiên, khoảng cách thời gian và kích thước ngẫu nhiên (chuỗi ký tự hỗn loạn không tuần hoàn).
- **Kết quả hiển thị trên Terminal:**
  ```text
  [LSTM_SCORER] Phân tích chuỗi IP 192.168.10.12: a.B.c.D.e.F... -> Malicious Probability: 12.45% -> [SAFE]
  ```
- **Ý nghĩa:** Lõi AI LSTM phân loại chính xác các kết nối bình thường, không gây ra báo động giả (False Positive).

### 🔴 Kịch bản 4: C2 Beaconing Attack (Chặn và khóa IP độc hại)
- **Hành vi giả lập:** IP `192.168.10.12` gửi liên tiếp các gói tin đều đặn theo chu kỳ cố định (chuỗi ký tự lặp lặp tuần hoàn `AAAAAAAAAAAAAAAAAAAA`).
- **Kết quả hiển thị trên Terminal:**
  ```text
  [LSTM_SCORER] Phân tích chuỗi IP 192.168.10.12: AAAAAAAAAAAAAAAAAAAA -> Malicious Probability: 96.84% -> [MALICIOUS DETECTED]
  [FIREWALL] Thực thi chặn IP: 192.168.10.12 -> Lệnh áp dụng: iptables -A INPUT -s 192.168.10.12 -j DROP
  ```
- **Ý nghĩa:** Phát hiện chuẩn xác các hành vi tấn công tự động của Botnet/C2 Beaconing và tự động chặn cứng IP ở tầng tường lửa hệ thống.
