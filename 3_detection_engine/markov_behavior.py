#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 3: Detection Engine (Beaconing Detector - Jitter/CV)
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Phát hiện tín hiệu C2 (Command & Control) Beaconing dựa trên phân tích hành vi thời gian.
    - Thuật toán nâng cao chuẩn Threat Hunting (lấy cảm hứng từ RITA và SANS):
      Sử dụng Hệ số biến thiên (Coefficient of Variation - CV), đại diện cho mức độ biến động Jitter.
    - Công thức: CV = σ / μ (Độ lệch chuẩn / Giá trị trung bình của khoảng trễ thời gian).
    - CV < 0.1 (Jitter dưới 10%) là bằng chứng đanh thép cho thấy các kết nối diễn ra với chu kỳ cực kỳ đều đặn,
      không thể là hành vi tự nhiên của con người mà chỉ có thể là bot/mã độc được lập trình sẵn.
"""

import sys
import time
import statistics
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# Cố gắng import colorama để hiển thị giao diện SOC chuyên nghiệp
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Đảm bảo in UTF-8 trơn tru trên Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class Colors:
    MAGENTA = Fore.MAGENTA if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""


class BehavioralDetector:
    """
    Bộ phát hiện hành vi C2 Beaconing bằng phép đo Jitter qua Hệ số biến thiên (CV).
    """
    def __init__(self, history_limit: int = 10, cv_threshold: float = 0.10, min_interval: float = 1.0, cooldown_time: float = 10.0):
        self.history_limit = history_limit        # Số lượng timestamps lưu trữ tối đa cho mỗi cặp IP
        self.cv_threshold = cv_threshold          # Ngưỡng Hệ số biến thiên (mặc định < 0.10 tương đương biến động < 10%)
        self.min_interval = min_interval          # Khoảng trễ trung bình tối thiểu (tránh bắt nhầm luồng stream/web thường)
        self.cooldown_time = cooldown_time        # Giới hạn tần suất cảnh báo chặn spam (giây)

        # Lưu trữ lịch sử timestamp kết nối của từng cặp IP: { (src_ip, dst_ip): [timestamp1, timestamp2, ...] }
        self.connection_history: Dict[Tuple[str, str], List[float]] = {}
        
        # Ghi nhớ thời gian cảnh báo gần nhất để tránh spam: { (src_ip, dst_ip): last_alert_timestamp }
        self.last_alerts: Dict[Tuple[str, str], float] = {}

    def process_log(self, log_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Xử lý kết nối từ log mạng và phân tích chu kỳ kết nối bằng Jitter / Coefficient of Variation (CV).
        
        ========================================================================================
        GIẢI THÍCH THUẬT TOÁN TOÁN HỌC PHÁT HIỆN BEACONING (CV):
        1. Khoảng trễ (Time Deltas):
           Đo lường thời gian trễ giữa các kết nối liên tiếp: Δt_i = t_(i+1) - t_i.
           Cần tối thiểu 5 giá trị Δt (tương đương 6 timestamps kết nối liên tiếp) để phân tích thống kê đáng tin cậy.
           
        2. Tính Giá trị trung bình (Mean - μ):
           μ = (sum(Δt_i)) / N
           Đại diện cho khoảng thời gian chu kỳ gửi tin (ví dụ: cứ mỗi 5 giây gửi tin 1 lần).
           
        3. Tính Độ lệch chuẩn (Standard Deviation - σ):
           σ = sqrt( (sum(Δt_i - μ)^2) / (N - 1) )
           Đo lường mức độ phân tán hoặc biến động (Jitter) của các khoảng thời gian kết nối.
           
        4. Tính Hệ số biến thiên (Coefficient of Variation - CV):
           CV = σ / μ
           Tại sao sử dụng CV thay vì Phương sai (Variance) thông thường?
           - Phương sai phụ thuộc rất nhiều vào quy mô thời gian (Scale-dependent). Ví dụ: Một chu kỳ 60 giây
             có jitter chỉ lệch 1-2 giây thì phương sai đã lên tới 4.0, trong khi chu kỳ 2 giây lệch 0.5 giây
             có phương sai chỉ là 0.25. Dù vậy, chu kỳ 60 giây thực tế đều đặn hơn rất nhiều!
           - Hệ số biến thiên (CV) giải quyết triệt để vấn đề này bằng cách chia stdev cho mean. Nó đưa độ lệch 
             về dạng tỉ lệ phần trăm không đơn vị.
             
        5. Điều kiện cảnh báo (CV < 0.10):
           Jitter biến động nhỏ hơn 10% của chu kỳ kết nối. Con người truy cập web luôn ngẫu nhiên (CV > 0.5), 
           chỉ có bot/mã độc được lập trình gửi tin tuần hoàn mới đạt được mức độ đều đặn chuẩn xác này (CV < 0.10).
        ========================================================================================
        """
        ts = log_dict.get("timestamp")
        src_ip = log_dict.get("id.orig_h")
        dst_ip = log_dict.get("id.resp_h")

        # Bỏ qua nếu thiếu trường thông tin cốt lõi
        if ts is None or not src_ip or not dst_ip:
            return None

        try:
            ts = float(ts)
        except (ValueError, TypeError):
            return None

        ip_pair = (src_ip, dst_ip)

        # Khởi tạo danh sách kết nối nếu cặp IP này lần đầu xuất hiện
        if ip_pair not in self.connection_history:
            self.connection_history[ip_pair] = []

        # Thêm timestamp hiện tại vào lịch sử của cặp IP
        self.connection_history[ip_pair].append(ts)

        # Giữ lại số lượng kết nối tối đa chỉ định trong giới hạn lịch sử
        if len(self.connection_history[ip_pair]) > self.history_limit:
            self.connection_history[ip_pair].pop(0)

        timestamps = self.connection_history[ip_pair]
        n_timestamps = len(timestamps)
        
        # Cần tối thiểu 6 timestamps để tạo ra ít nhất 5 khoảng trễ (Time Deltas)
        if n_timestamps < 6:
            return None

        # 1. Tính toán các khoảng trễ thời gian (Time Deltas) giữa các kết nối liên tiếp
        deltas = [timestamps[i+1] - timestamps[i] for i in range(n_timestamps - 1)]

        # 2. Tính giá trị trung bình (Mean - μ)
        mean_interval = statistics.mean(deltas)

        # Bỏ qua nếu các kết nối diễn ra quá nhanh liên tục (ví dụ: tải file, streaming tốc độ cao)
        if mean_interval < self.min_interval:
            return None

        # 3. Tính Độ lệch chuẩn (Standard Deviation - σ)
        stdev = statistics.stdev(deltas)

        # 4. Tính Hệ số biến thiên (Coefficient of Variation - CV)
        # Tránh chia cho 0 nếu mean_interval bằng 0 (kết nối đồng thời)
        cv = stdev / mean_interval if mean_interval != 0 else float('inf')

        # 5. Kiểm tra điều kiện Beaconing (Jitter < 10% -> CV < 0.10)
        if cv < self.cv_threshold:
            # Áp dụng cơ chế Cooldown chặn lụt cảnh báo
            last_alert = self.last_alerts.get(ip_pair, 0.0)
            if ts - last_alert >= self.cooldown_time:
                self.last_alerts[ip_pair] = ts
                
                weight = 0.8
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

                # In cảnh báo ra Terminal màu Magenta nổi bật chuẩn SOC
                msg = (f"Phát hiện C2 Beaconing đến {dst_ip}! IP {src_ip} kết nối cực kỳ đều đặn "
                       f"chu kỳ {mean_interval:.1f}s. Hệ số biến thiên CV = {cv:.4f} (Jitter: {cv*100:.2f}%)")
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.MAGENTA}{Colors.BRIGHT}[BEACON_DETECT]{Colors.RESET} "
                    f"{Colors.MAGENTA}{msg}{Colors.RESET}"
                )

                # Tạo Evidence object trả về cho Layer 4
                return {
                    "ip": src_ip,
                    "alert_type": "C2_BEACONING",
                    "weight": weight,
                    "timestamp": ts,
                    "details": f"Destination: {dst_ip}, Mean Interval: {mean_interval:.2f}s, CV: {cv:.4f} (Jitter < 10%)"
                }

        return None


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 75)
    print(f" {Colors.MAGENTA}{Colors.BRIGHT}Kiểm thử độc lập: BehavioralDetector (CV/Jitter Algorithm){Colors.RESET} ")
    print("=" * 75)

    # Khởi tạo detector: yêu cầu CV < 0.10, lưu tối đa 10 logs
    detector = BehavioralDetector(history_limit=10, cv_threshold=0.10, min_interval=1.0)
    now = time.time()

    # KỊCH BẢN 1: Kết nối không đều đặn (Giao thông web tự nhiên của con người)
    print("\n[TEST 1] Mô phỏng truy cập Web ngẫu nhiên (Không cảnh báo)...")
    random_intervals = [2.5, 7.8, 1.3, 12.4, 4.2, 8.9] # Khoảng trễ biến động cực lớn
    curr_time = now
    web_logs = []
    for interval in random_intervals:
        curr_time += interval
        web_logs.append({"timestamp": curr_time, "id.orig_h": "10.38.50.4", "id.resp_h": "10.38.50.1"})
        
    has_alert_1 = False
    for log in web_logs:
        ev = detector.process_log(log)
        if ev:
            has_alert_1 = True
            print(f"-> Thất bại: Cảnh báo nhầm hành vi ngẫu nhiên: {ev}")
            
    if not has_alert_1:
        print("-> Test 1: ĐẠT (Không cảnh báo nhầm người dùng thực)")
    else:
        print("-> Test 1: THẤT BẠI")

    # KỊCH BẢN 2: Mã độc gửi tín hiệu Heartbeat Beaconing (Chu kỳ đều đặn mỗi 5 giây, có jitter siêu nhỏ 0.15s)
    print("\n[TEST 2] Mô phỏng C2 Beaconing chu kỳ 5 giây, độ lệch nhiễu cực nhỏ ~3% (Phải cảnh báo)...")
    beacon_logs = []
    curr_time = now
    
    # Tạo 8 kết nối liên tiếp cách nhau ~5 giây
    # Mean ≈ 5s, Jitter (Stdev) ≈ 0.15s => CV ≈ 0.15 / 5 = 0.03 (< 0.10)
    for i in range(8):
        curr_time += 5.0
        jitter = 0.15 if i % 2 == 0 else -0.15
        beacon_logs.append({"timestamp": curr_time + jitter, "id.orig_h": "10.38.50.3", "id.resp_h": "10.38.50.1"})

    has_alert_2 = False
    for log in beacon_logs:
        ev = detector.process_log(log)
        if ev:
            has_alert_2 = True
            print(f"-> Trả về Evidence: {ev}")
            
    if has_alert_2:
        print("-> Test 2: ĐẠT (Phát hiện C2 Beaconing đều đặn thành công)")
    else:
        print("-> Test 2: THẤT BẠI")
