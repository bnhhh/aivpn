#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 3: Detection Engine (Static Port Scan Detector)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Senior Software Architect
Mô tả:
    - Phát hiện hành vi quét cổng (Port Scan) thời gian thực bằng cách theo dõi
      các cổng đích duy nhất được truy cập bởi một IP nguồn trong cửa sổ trượt 10 giây.
    - Hoàn toàn tuân thủ kiến trúc dựa trên Bằng chứng: Chỉ phát hiện và gửi Evidence,
      không chứa logic thực thi iptables hay in cảnh báo block IP.
    - Tích hợp cơ chế cooldown 10 giây để ngăn chặn hiện tượng spam hàng loạt bằng chứng
      cho cùng một đợt tấn công của một IP nguồn.
"""

import sys
import time
from typing import Dict, List, Tuple, Optional, Any

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Cố gắng import colorama để hiển thị log SOC sinh động
try:
    import colorama
    from colorama import Fore, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

class Colors:
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""


class ScanDetector:
    """
    Module phân tích phát hiện hành vi Quét Cổng (Port Scan).
    """
    def __init__(self, ports_threshold: int = 10, window_seconds: float = 10.0, cooldown_seconds: float = 10.0):
        self.ports_threshold = ports_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        
        # Lịch sử kết nối của từng IP: { ip_src: [(timestamp, port_dst), ...] }
        self.history: Dict[str, List[Tuple[float, int]]] = {}
        
        # Thời điểm gửi bằng chứng gần nhất của từng IP: { ip_src: timestamp }
        self.last_evidence_time: Dict[str, float] = {}

    def process_log(self, parsed_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Tiếp nhận kết nối mới và cập nhật trạng thái quét cổng của IP nguồn.
        Args:
            parsed_log: Dictionary thông tin kết nối từ Zeek conn.log.
        Returns:
            Dictionary chứa các thuộc tính để khởi tạo Evidence nếu phát hiện quét cổng,
            ngược lại trả về None.
        """
        ip_src = parsed_log.get("id.orig_h")
        port_dst = parsed_log.get("id.resp_p")
        ts = parsed_log.get("timestamp") or parsed_log.get("ts")
        
        if not ip_src or port_dst is None:
            return None
            
        try:
            port_dst = int(port_dst)
        except (ValueError, TypeError):
            return None

        if ts is None:
            ts = time.time()
        else:
            try:
                ts = float(ts)
            except (ValueError, TypeError):
                ts = time.time()

        # Khởi tạo lịch sử cho IP nguồn nếu chưa có
        if ip_src not in self.history:
            self.history[ip_src] = []

        # 1. Thêm kết nối hiện tại vào lịch sử
        self.history[ip_src].append((ts, port_dst))

        # 2. Dọn dẹp các bản ghi cũ nằm ngoài cửa sổ trượt (Slide Window)
        cutoff_time = ts - self.window_seconds
        self.history[ip_src] = [conn for conn in self.history[ip_src] if conn[0] >= cutoff_time]

        # 3. Đếm số lượng cổng đích duy nhất được truy cập trong cửa sổ trượt
        unique_ports = {conn[1] for conn in self.history[ip_src]}
        ports_count = len(unique_ports)

        # 4. Kiểm tra xem có vượt ngưỡng hay không
        if ports_count > self.ports_threshold:
            last_sent = self.last_evidence_time.get(ip_src, 0.0)
            
            # Kiểm tra cơ chế Cooldown để tránh spam bằng chứng
            if ts - last_sent >= self.cooldown_seconds:
                self.last_evidence_time[ip_src] = ts
                
                ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}{Colors.BRIGHT}[SCAN_DETECT]{Colors.RESET} "
                    f"IP {Colors.GREEN}{ip_src}{Colors.RESET} đã truy cập {Colors.BRIGHT}{ports_count}{Colors.RESET} ports duy nhất trong {self.window_seconds}s! "
                    f"Tạo bằng chứng quét cổng tĩnh."
                )
                
                # Trả về các thuộc tính cho Evidence để Main Coordinator tạo đối tượng Evidence
                return {
                    "ip": ip_src,
                    "module_name": "ScanDetector",
                    "confidence": 0.7,
                    "attack_type": "High_Connection_Rate",
                    "timestamp": ts
                }

        return None


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.YELLOW}{Colors.BRIGHT}Kiểm thử độc lập: ScanDetector (Layer 3){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo detector: Ngưỡng > 3 ports duy nhất trong 5s, cooldown 5s
    detector = ScanDetector(ports_threshold=3, window_seconds=5.0, cooldown_seconds=5.0)
    ip_test = "10.0.0.1"
    now = time.time()

    # Giả lập kết nối đến các port khác nhau
    for i in range(1, 6):
        log_entry = {
            "id.orig_h": ip_test,
            "id.resp_p": 80 + i,
            "timestamp": now + (i * 0.1)
        }
        evidence_data = detector.process_log(log_entry)
        if evidence_data:
            print(f"-> Phát hiện Port Scan thành công tại port {80 + i}! Evidence: {evidence_data}")
        else:
            print(f"Port {80 + i}: Đang tích lũy...")
            
    # Thử gửi tiếp kết nối trong thời gian cooldown (Không được kích hoạt tiếp bằng chứng)
    print("\n--- Gửi thêm log trong thời gian Cooldown (Không được phát cảnh báo mới) ---")
    log_cooldown = {
        "id.orig_h": ip_test,
        "id.resp_p": 999,
        "timestamp": now + 0.6
    }
    evidence_cooldown = detector.process_log(log_cooldown)
    if evidence_cooldown:
        print(f"-> [LỖI] Kích hoạt bằng chứng dù đang cooldown! Evidence: {evidence_cooldown}")
    else:
        print("-> [ĐẠT] Bỏ qua kích hoạt thành công (Cooldown hoạt động tốt).")
