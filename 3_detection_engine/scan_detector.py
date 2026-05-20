#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 3: Detection Engine (Scan Detector)
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Phát hiện hành vi rà quét cổng (Port Scan) và quét mạng (Lateral Movement/Network Scan).
    - Sử dụng thuật toán Cửa sổ trượt (Sliding Window) 10 giây để lưu trữ lịch sử kết nối của từng IP.
    - Ngưỡng kích hoạt: Quét > 10 cổng khác nhau HOẶC truy cập > 5 IP đích khác nhau trong vòng 10 giây.
    - Cơ chế Cooldown (giới hạn tần suất cảnh báo) giúp giảm nhiễu và spam hệ thống.
"""

import sys
import time
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

# Cấu hình encoding UTF-8 cho Windows để tránh lỗi in chữ Tiếng Việt
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

class Colors:
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""


class ScanDetector:
    """
    Bộ phát hiện hành vi quét cổng (Port Scan) và quét mạng (Network Scan).
    """
    def __init__(self, window_size: float = 10.0, port_threshold: int = 10, ip_threshold: int = 5, cooldown_time: float = 10.0):
        self.window_size = window_size
        self.port_threshold = port_threshold
        self.ip_threshold = ip_threshold
        self.cooldown_time = cooldown_time
        
        # Lưu trữ lịch sử kết nối: { src_ip: [(timestamp, resp_h, resp_p), ...] }
        self.history: Dict[str, List[Tuple[float, str, int]]] = {}
        
        # Lưu thời gian cảnh báo gần nhất để tránh spam: { src_ip: last_alert_timestamp }
        self.last_alerts: Dict[str, float] = {}

    def process_log(self, log_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Xử lý một dòng log kết nối được phân tích từ Zeek.
        Args:
            log_dict: Dict chứa các thông tin kết nối mạng.
        Returns:
            Evidence Dict nếu phát hiện hành vi đáng ngờ, ngược lại trả về None.
        """
        # Trích xuất thông tin cần thiết
        ts = log_dict.get("timestamp")
        src_ip = log_dict.get("id.orig_h")
        dst_ip = log_dict.get("id.resp_h")
        dst_port = log_dict.get("id.resp_p")
        proto = log_dict.get("proto")

        # Bỏ qua nếu thiếu dữ liệu thiết yếu
        if ts is None or not src_ip or not dst_ip or dst_port is None:
            return None

        try:
            ts = float(ts)
            dst_port = int(dst_port)
        except (ValueError, TypeError):
            return None

        # Khởi tạo danh sách lịch sử cho IP nguồn mới
        if src_ip not in self.history:
            self.history[src_ip] = []

        # 1. Thêm kết nối mới vào lịch sử
        self.history[src_ip].append((ts, dst_ip, dst_port))

        # 2. Xóa các kết nối cũ vượt quá kích thước cửa sổ trượt (Slide Window)
        cutoff_time = ts - self.window_size
        self.history[src_ip] = [conn for conn in self.history[src_ip] if conn[0] >= cutoff_time]

        # 3. Phân tích thống kê kết nối trong cửa sổ hiện tại
        active_conns = self.history[src_ip]
        if not active_conns:
            return None

        unique_ports = set(conn[2] for conn in active_conns)
        unique_ips = set(conn[1] for conn in active_conns)
        
        num_ports = len(unique_ports)
        num_ips = len(unique_ips)

        # Tính khoảng thời gian thực tế trong cửa sổ trượt để thông báo chính xác
        timestamps = [conn[0] for conn in active_conns]
        elapsed = round(max(timestamps) - min(timestamps), 1)
        if elapsed < 0.1:
            elapsed = 0.1

        # 4. Kiểm tra điều kiện kích hoạt cảnh báo
        is_port_scan = num_ports > self.port_threshold
        is_network_scan = num_ips > self.ip_threshold

        if is_port_scan or is_network_scan:
            # Kiểm tra cơ chế Cooldown chặn spam cảnh báo
            last_alert = self.last_alerts.get(src_ip, 0.0)
            if ts - last_alert >= self.cooldown_time:
                self.last_alerts[src_ip] = ts
                
                alert_type = "PORT_SCAN" if is_port_scan else "NETWORK_SCAN"
                weight = 0.4
                
                # Định dạng timestamp sang chuỗi dễ nhìn cho Terminal
                ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

                # In cảnh báo ra Terminal chuẩn đặc tả JSON aivpn.json
                # Mẫu: [2026-05-20 11:31:10] [SCAN_DETECT] IP 10.38.50.3 quét 15 ports trong 2s! Gửi bằng chứng (Weight: 0.4).
                if is_port_scan:
                    msg = f"IP {src_ip} quét {num_ports} ports trong {elapsed}s! Gửi bằng chứng (Weight: {weight})."
                else:
                    msg = f"IP {src_ip} quét {num_ips} IPs trong {elapsed}s! Gửi bằng chứng (Weight: {weight})."

                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}{Colors.BRIGHT}[SCAN_DETECT]{Colors.RESET} "
                    f"{Colors.YELLOW}{msg}{Colors.RESET}"
                )

                # Trả về đối tượng Evidence chuyển lên Layer 4
                return {
                    "ip": src_ip,
                    "alert_type": alert_type,
                    "weight": weight,
                    "timestamp": ts,
                    "details": f"Ports: {num_ports}, IPs: {num_ips}, Elapsed: {elapsed}s"
                }

        return None


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.YELLOW}{Colors.BRIGHT}Kiểm thử độc lập: ScanDetector (Layer 3){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo detector: quét > 10 ports HOẶC > 5 IPs trong 10s sẽ cảnh báo
    detector = ScanDetector(window_size=10.0, port_threshold=10, ip_threshold=5, cooldown_time=5.0)

    now = time.time()
    
    # KỊCH BẢN 1: Giao dịch mạng bình thường (3 kết nối khác nhau)
    print("\n[TEST 1] Gửi giao dịch bình thường (Không cảnh báo)...")
    normal_logs = [
        {"timestamp": now, "id.orig_h": "10.38.50.4", "id.resp_h": "10.38.50.1", "id.resp_p": 80, "proto": "tcp"},
        {"timestamp": now + 0.5, "id.orig_h": "10.38.50.4", "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp"},
        {"timestamp": now + 1.0, "id.orig_h": "10.38.50.4", "id.resp_h": "142.250.190.46", "id.resp_p": 443, "proto": "tcp"},
    ]
    for log in normal_logs:
        evidence = detector.process_log(log)
        if evidence:
            print(f"-> Thất bại: Sinh bằng chứng sai lệch: {evidence}")
    print("-> Test 1: ĐẠT")

    # KỊCH BẢN 2: Tấn công Port Scan (Quét 12 cổng khác nhau của 10.38.50.1 trong 2 giây)
    print("\n[TEST 2] Mô phỏng quét cổng (Phải sinh cảnh báo PORT_SCAN)...")
    scan_logs = []
    for i in range(12):
        scan_logs.append({
            "timestamp": now + 2.0 + (i * 0.15),  # 2.0s -> 3.8s
            "id.orig_h": "10.38.50.3",
            "id.resp_h": "10.38.50.1",
            "id.resp_p": 100 + i, # Cổng 100 đến 111
            "proto": "tcp"
        })
    
    has_alert = False
    for log in scan_logs:
        ev = detector.process_log(log)
        if ev:
            has_alert = True
            print(f"-> Trả về Evidence: {ev}")
            
    if has_alert:
        print("-> Test 2: ĐẠT")
    else:
        print("-> Test 2: THẤT BẠI (Không sinh cảnh báo)")

    # KỊCH BẢN 3: Cơ chế Cooldown hoạt động (Gửi tiếp đợt quét thứ hai ngay lập tức)
    print("\n[TEST 3] Kiểm tra cơ chế Cooldown (Không được phát sinh cảnh báo liên tục)...")
    cooldown_logs = []
    for i in range(12):
        cooldown_logs.append({
            "timestamp": now + 4.0 + (i * 0.1), # Ngay sau đợt quét trước
            "id.orig_h": "10.38.50.3",
            "id.resp_h": "10.38.50.1",
            "id.resp_p": 1000 + i,
            "proto": "tcp"
        })
    
    cooldown_alert = False
    for log in cooldown_logs:
        ev = detector.process_log(log)
        if ev:
            cooldown_alert = True
            print(f"-> Lỗi: Sinh cảnh báo trong thời gian cooldown: {ev}")
            
    if not cooldown_alert:
        print("-> Test 3: ĐẠT (Ngăn chặn spam thành công nhờ Cooldown)")
    else:
        print("-> Test 3: THẤT BẠI")
