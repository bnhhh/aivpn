# 🛡️ Mini AI VPN Gateway (AIVPN)

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version" />
  <img src="https://img.shields.io/badge/TensorFlow--CPU-2.15-orange?style=for-the-badge&logo=tensorflow&logoColor=white" alt="TensorFlow CPU" />
  <img src="https://img.shields.io/badge/Zeek-IDS-green?style=for-the-badge&logo=security&logoColor=white" alt="Zeek IDS" />
  <img src="https://img.shields.io/badge/WireGuard-VPN-purple?style=for-the-badge&logo=wireguard&logoColor=white" alt="WireGuard VPN" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License MIT" />
</p>

---

## 📝 Mục lục (Table of Contents)
1. [Giới thiệu tổng quan (Overview)](#-1-gioi-thieu-tong-quan-overview)
2. [Kiến trúc hệ thống (Core Architecture)](#-2-kien-truc-he-thong-core-architecture)
   - [Kiến trúc Bằng chứng (Evidence-based)](#a-kien-truc-bang-chung-evidence-based)
   - [Cơ chế Bất đồng bộ (Producer-Consumer Queue)](#b-co-che-bat-dong-bo-producer-consumer-queue)
   - [Sơ đồ Luồng xử lý (Pipeline Diagram)](#c-so-do-luong-xu-ly-pipeline-diagram)
3. [Bộ ba "Thợ săn" lớp 3 (Detection Modules)](#-3-bo-ba-tho-san-lop-3-detection-modules)
   - [AI LSTM Core](#i-ai-lstm-core-dynamic-rhythm-analysis)
   - [Static Scan Detector](#ii-static-scan-detector-port-scan-hunter)
   - [DNS Detector](#iii-dns-detector-dga--tunneling-hunter)
4. [Lớp Bồi thẩm đoàn & Luật kép lớp 4 (Evidence Manager)](#-4-lop-boi-tham-doan--luat-kep-lop-4-evidence-manager)
   - [Lọc rác bằng chứng (Time-To-Live)](#a-loc-rac-bang-chung-time-to-live-ttl)
   - [Hệ thống Luật kép (Dual-Rule System)](#b-he-thong-luat-kep-dual-rule-system)
5. [Hướng dẫn Cài đặt & Sử dụng (Quick Start)](#-5-huong-dan-cai-dat--su-dung-quick-start)
   - [Yêu cầu hệ thống](#a-yeu-cau-he-thong)
   - [Cài đặt Môi trường](#b-cai-dat-moi-truong)
   - [Khởi chạy Gateway](#c-khoi-chay-gateway)
6. [Kịch bản Kiểm thử Tích hợp (Testing Scenarios)](#-6-kich-ban-kiem-thu-tich-hop-testing-scenarios)

---

## 📖 1. Giới thiệu tổng quan (Overview)

**Mini AI VPN Gateway (AIVPN)** là một giải pháp Phát hiện và Ngăn chặn Xâm nhập (IPS/IDS) biên thời gian thực siêu nhẹ, được thiết kế chuyên biệt để tích hợp trực tiếp vào các cổng ngõ VPN (WireGuard Gateway) hoặc thiết bị phần cứng nhúng (Edge Devices) chạy hệ điều hành Ubuntu Linux. 

Kế thừa và tối ưu hóa sâu sắc triết lý phân tích hành vi từ hệ thống danh tiếng **Stratosphere Slips (Đại học Kỹ thuật Séc - CTU)**, dự án này đã loại bỏ hoàn toàn các cấu trúc chấm điểm rule-based cồng kềnh và cơ sở dữ liệu Redis nặng nề. Thay vào đó, AIVPN sử dụng mạng nơ-ron hồi quy **Deep Learning LSTM** kết hợp với bộ thợ săn tĩnh phân tích lưu lượng, đưa ra khả năng phát hiện chủ động các mối đe dọa như **C2 Beaconing**, **Port Scan** và **DNS Tunneling** với mức tiêu thụ tài nguyên cực kỳ tối giản (chỉ tốn **~15MB RAM**).

---

## 🏗️ 2. Kiến trúc hệ thống (Core Architecture)

AIVPN được nâng cấp toàn diện lên kiến trúc phân lớp hiện đại để giải quyết triệt để các hạn chế về hiệu năng và độ tin cậy trong môi trường an ninh mạng thực tế.

### A. Kiến trúc Bằng chứng (Evidence-based)
Hệ thống tuân thủ nghiêm ngặt nguyên lý tách biệt trách nhiệm (Separation of Concerns):
*   **Lớp Phát hiện (Layer 3 - Hunters):** Bao gồm AI LSTM, Static Scan Detector, và DNS Detector. Các module này hoạt động hoàn toàn độc lập, **chỉ làm nhiệm vụ thu thập và gửi bằng chứng (`Evidence`)** chứa địa chỉ IP, tên module phát hiện, độ tự tin (Confidence), loại tấn công và timestamp. Lớp này tuyệt đối không có quyền chặn iptables hay in cảnh báo block.
*   **Lớp Quyết định (Layer 4 - Jury):** Được quản lý tập trung bởi **Bồi thẩm đoàn (`EvidenceManager`)**. Bồi thẩm đoàn sẽ tích lũy bằng chứng, định danh tội danh mã độc dựa trên các dấu vết phối hợp và trực tiếp thực thi tường lửa Linux thông qua `FirewallBlocker`.

### B. Cơ chế Bất đồng bộ (Producer-Consumer Queue)
Để ngăn chặn nguy cơ nghẽn cổ chai I/O khi lưu lượng log Zeek (`conn.log`) tăng đột biến, hệ thống triển khai mô hình đa luồng thông qua một Thread-Safe **`queue.Queue`**:
*   **Luồng chính (Producer - Reader Thread):** Đọc file log liên tục, thực hiện whitelist check cực nhanh, cập nhật bộ discretizer và chạy quét cổng tĩnh phi blocking, sau đó đóng gói dữ liệu và đẩy vào hàng đợi `log_queue`. Luồng này được giải phóng ngay lập tức ($<1\text{ms}$) để tránh mất mát log.
*   **Luồng Worker (Consumer - Worker Thread):** Chạy độc lập dưới nền, lấy sự kiện ra khỏi hàng đợi để thực hiện các phép suy luận AI LSTM (Deep Learning) tiêu tốn năng lực CPU và nạp bằng chứng cho Bồi thẩm đoàn.

### C. Sơ đồ Luồng xử lý (Pipeline Diagram)

```text
==================================================================================================
                        WIREGUARD VPN GATEWAY & PIPELINE XỬ LÝ AI IPS
==================================================================================================

   [ VPN Clients ] ───( wg0 Interface )───► [ Zeek Log Engine ] ───► [ conn.log (Log Stream) ]
                                                                             │
                                                                             ▼
                                                                ┌─────────────────────────┐
                                                                │ Whitelist Parser        │ ── (Bypass) ─► [ SAFE ]
                                                                └────────────┬────────────┘
                                                                             │ (Nếu không Whitelist)
                                                                             ▼
                                                             +───────────────────────────────+
                                                             |   Producer Thread (Reader)    |
                                                             +───────────────────────────────+
                                                                             │
                                           ┌─────────────────────────────────┼────────────────────────────────┐
                                           ▼                                 ▼                                ▼
                                ┌─────────────────────┐           ┌─────────────────────┐          ┌─────────────────────┐
                                │ Static Scan Hunter  │           │ AI Sequence Encoder │          │     DNS Hunter      │
                                │  (Quét cổng 10s)    │           │ (Sliding Window 20) │          │  (Entropy & Subdom) │
                                └──────────┬──────────┘           └──────────┬──────────┘          └──────────┬──────────┘
                                           │ (Có bằng chứng)                 │ (Chuỗi trượt đủ 20 ký tự)  │ (Có bằng chứng)
                                           ▼                                 ▼                            ▼
                         =================================== [ Thread-Safe queue.Queue ] ===================================
                                                                             │
                                                                             ▼
                                                             +───────────────────────────────+
                                                             |   Consumer Thread (Worker)    |
                                                             +───────────────────────────────+
                                                                             │
                                                               ┌─────────────┴─────────────┐
                                                               ▼                           ▼
                                                    [ Bằng chứng Hunter ]        [ Chạy suy luận LSTM AI ]
                                                               │                           │ (Xác suất >= 0.8)
                                                               ▼                           ▼
                                                    +──────────────────────────────────────────────+
                                                    |  Bồi thẩm đoàn (EvidenceManager - Layer 4)    |
                                                    +──────────────────────────────────────────────+
                                                                             │
                                                            ┌────────────────┴────────────────┐
                                                            ▼ (Thỏa mãn Luật kép)             ▼ (Không đủ điểm)
                                                    [ JURY VERDICT: KẾT ÁN ]                 [ TIẾP TỤC GIÁM SÁT ]
                                                            │
                                                            ▼
                                                    ┌───────────────────────┐
                                                    │ FirewallBlocker (L4)  │ ──► [ iptables DROP ]
                                                    └───────────────────────┘
==================================================================================================
```

---

## 🕵️ 3. Bộ ba "Thợ săn" lớp 3 (Detection Modules)

Lớp 3 tích hợp ba công cụ phát hiện với các thuật toán phân tích đa chiều:

### I. AI LSTM Core (Dynamic Rhythm Analysis)
*   **Cơ chế:** Gom nhóm kết nối theo từng IP nguồn và mã hóa các tham số (Duration, Size, Interval) thành chuỗi các ký tự chữ cái hành vi đại diện (*Behavioral Letters*).
*   **FIFO Sliding Window:** Sử dụng bộ đệm trượt rolling liên tục `collections.deque(maxlen=20)`. Khi kết nối thứ 21 tới, ký tự đầu tiên tự động bị đẩy ra để nạp ký tự mới, đảm bảo AI luôn nhìn thấy bức tranh toàn cảnh 20 kết nối gần nhất.
*   **Cold Start Protection:** Ràng buộc bảo vệ "Graceful Wait". Hệ thống tuyệt đối bỏ qua suy luận AI cho các IP mới kết nối có ít hơn 20 kết nối để tránh lỗi crash dimension.
*   **Mô hình suy luận:** Tải file `lstm_model.tflite` qua thư viện tối giản `tensorflow-cpu`. Khi xác suất nguy hại $\ge 0.80$, sinh bằng chứng `Evidence` với `confidence=prob`, `attack_type="Suspicious_Rhythm"`.

### II. Static Scan Detector (Port Scan Hunter)
*   **Cơ chế:** Đếm số lượng cổng đích (`id.resp_p`) duy nhất mà một IP nguồn (`id.orig_h`) truy cập trong cửa sổ trượt 10 giây.
*   **Ngưỡng phát hiện:** Nếu số cổng đích duy nhất $> 10$ trong 10 giây $\rightarrow$ Sinh bằng chứng `Evidence` với `confidence=0.7`, `attack_type="High_Connection_Rate"`.
*   **Cooldown:** Tích hợp bộ đệm Cooldown 10 giây cho mỗi IP để tránh hiện tượng spam dồn dập bằng chứng cho cùng một đợt quét.

### III. DNS Detector (DGA & Tunneling Hunter)
*   **Phát hiện DGA (Shannon Entropy):** Áp dụng công thức toán học Shannon Entropy tính độ hỗn loạn thông tin của chuỗi tên miền đầy đủ:
    $$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
    Nếu tên miền có $H(X) > 4.2$ (mức độ hỗn loạn rất cao của thuật toán sinh tên miền động của mã độc) $\rightarrow$ Sinh bằng chứng với `confidence=0.85`, `attack_type="DGA_Malware"`.
*   **Phát hiện DNS Tunneling (Subdomain Length):** Tự động bóc tách subdomain từ FQDN. Nếu độ dài subdomain $> 45$ ký tự (dấu hiệu rò rỉ dữ liệu hoặc mã hóa gói tin qua trường DNS Query) $\rightarrow$ Sinh bằng chứng với `confidence=0.90`, `attack_type="DNS_Tunneling"`.

---

## ⚖️ 4. Lớp Bồi thẩm đoàn & Luật kép lớp 4 (Evidence Manager)

`EvidenceManager` là "bộ não" đưa ra phán quyết cuối cùng dựa trên các hồ sơ bằng chứng thu thập được.

### A. Lọc rác bằng chứng (Time-To-Live - TTL)
Để tránh việc các cảnh báo riêng lẻ tích lũy vô hạn theo thời gian gây nghẽn bộ nhớ RAM và dẫn đến phán quyết sai lệch, mỗi bằng chứng nạp vào Bồi thẩm đoàn đều được áp **TTL = 5 phút (300 giây)**. Sau 5 phút, bằng chứng hết hiệu lực sẽ tự động bị đào thải ra khỏi profile của IP đó.

### B. Hệ thống Luật kép (Dual-Rule System)
Bồi thẩm đoàn kiểm thử hồ sơ IP qua hai luật chặn khẩn cấp để đảm bảo tính an toàn tuyệt đối:

> [!NOTE]
> **Luật 1: Luật Đồng thuận (Consensus Rule)**
> Áp dụng cho các đợt tấn công phối hợp cường độ trung bình/nhỏ. Từng hành vi đơn lẻ chưa đủ nguy hiểm để chặn, nhưng sự cộng dồn của chúng tạo nên mối đe dọa lớn.
> $$\text{Tổng điểm tích lũy (Confidence)} = \sum \text{Confidence} \ge 1.5$$
> *Ví dụ:* IP thực hiện Port Scan (điểm 0.7) kết hợp với AI phát hiện nhịp điệu Beaconing nghi ngờ nhẹ (điểm 0.8), tổng điểm = 1.5 $\rightarrow$ **BLOCK**. Định danh tội danh: `Botnet/C2 (LSTM Beaconing + Port Scan)`.

> [!IMPORTANT]
> **Luật 2: Luật Phủ quyết khẩn cấp (Critical Bypass)**
> Dành riêng cho các đợt tấn công mức độ nguy hiểm cực kỳ cao và rõ ràng. Bất kể tổng điểm tích lũy là bao nhiêu, nếu xuất hiện **BẤT KỲ một bằng chứng đơn lẻ nào có Confidence $\ge 0.85$**, IP đó sẽ bị **BLOCK NGAY LẬP TỨC**.
> *Ví dụ:* AI LSTM phát hiện nhịp Beacon rõ ràng với độ tin cậy 0.96 $\rightarrow$ Chặn ngay lập tức! Hoặc DNS Detector phát hiện DNS Tunneling với độ tin cậy 0.90 $\rightarrow$ Chặn ngay lập tức!

---

## 🚀 5. Hướng dẫn Cài đặt & Sử dụng (Quick Start)

### A. Yêu cầu hệ thống
*   **Hệ điều hành:** Ubuntu Linux (Khuyên dùng 24.04 / 25.04 LTS).
*   **Dịch vụ nền:** Đã cấu hình chạy **WireGuard VPN** (`wg0`) và **Zeek IDS** (giám sát `wg0`).
*   **Môi trường:** Python version **3.11**.

### B. Cài đặt Môi trường
Tạo và kích hoạt môi trường ảo Python cô lập:

```bash
# 1. Tạo môi trường ảo
python3.11 -m venv vpn_env

# 2. Kích hoạt môi trường ảo
source vpn_env/bin/activate

# 3. Cài đặt các thư viện MLOps & System tương thích
pip install tensorflow-cpu "numpy<2.0.0" colorama pyyaml
```

> [!CAUTION]
> Bắt buộc phải cài đặt `numpy<2.0.0` để tương thích hoàn toàn với nhân suy luận của `tensorflow-cpu` và tránh các lỗi không tương thích kiểu dữ liệu mảng.

### C. Khởi chạy Gateway
Chạy chương trình với quyền **root (sudo)** bằng đường dẫn Python của môi trường ảo để hệ thống có quyền cấu hình tường lửa:

```bash
sudo ./vpn_env/bin/python main_vpn_ids.py
```

*   **`config/slips.yaml`:** Quản lý cấu hình linh hoạt (ngưỡng AI, Simulation Mode, đường dẫn log Zeek).
*   **`config/whitelist.conf`:** Định nghĩa IP, CIDR và Domain an toàn để bypass nhanh ở cổng vào, bảo vệ CPU.

---

## 🧪 6. Kịch bản Kiểm thử Tích hợp (Testing Scenarios)

Dự án cung cấp một bộ công cụ kiểm thử tích hợp tự động hoàn chỉnh **[test_system_v2.py](file:///d:/HUST/2025.2/ATHTTT/openslips/scripts/test_system_v2.py)** giúp giả lập và xác minh chính xác cả 7 kịch bản logic cốt lõi của hệ thống mà không cần cài đặt VPN hay Zeek thật:

```bash
./vpn_env/bin/python scripts/test_system_v2.py
```

**Kết quả kiểm thử thực tế đạt điểm chất lượng tuyệt đối (100% PASSED):**

```text
================================================================================
 KẾT QUẢ ĐÁNH GIÁ CHẤT LƯỢNG HỆ THỐNG 
================================================================================
 - Kịch bản WHITELIST_BYPASS         : ĐẠT (PASSED) -> Bypass 8.8.8.8 & wikipedia.org
 - Kịch bản COLD_START_SAFE          : ĐẠT (PASSED) -> Graceful Wait cho IP kết nối < 20 lần
 - Kịch bản NORMAL_TRAFFIC_SAFE      : ĐẠT (PASSED) -> IP hành vi sạch, AI đánh giá Safe (40% rủi ro)
 - Kịch bản CRITICAL_BYPASS_BLOCKED  : ĐẠT (PASSED) -> LSTM Beaconing (0.96) kích hoạt Luật Phủ Quyết
 - Kịch bản CONSENSUS_BLOCKED        : ĐẠT (PASSED) -> Scan (0.7) + LSTM (0.8) kích hoạt Luật Đồng Thuận
 - Kịch bản DNS_DGA_BLOCKED          : ĐẠT (PASSED) -> DNS DGA (Entropy 4.70 > 4.2) kích hoạt Luật Phủ Quyết
 - Kịch bản DNS_TUNNELING_BLOCKED    : ĐẠT (PASSED) -> DNS Tunnel (Subdomain 60 ký tự) kích hoạt Luật Phủ Quyết
================================================================================
 KẾT LUẬN: HỆ THỐNG ĐẠT ĐIỂM TUYỆT ĐỐI, SẴN SÀNG TRIỂN KHAI V2! 
================================================================================
```
