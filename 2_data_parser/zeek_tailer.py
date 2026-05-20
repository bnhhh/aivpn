#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 2: Data Parsing (Realtime Log Tailer)
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả: 
    - File này đóng vai trò như lệnh `tail -f`, liên tục đọc các dòng mới từ file log của Zeek.
    - Hỗ trợ parser JSON và Regex để trích xuất dữ liệu mạng sang Python Dictionary.
    - Tích hợp một bộ sinh dữ liệu giả lập (Traffic Simulator) chạy ngầm (Background Thread)
      để tự động sinh ra các dòng log mạng thực tế giúp việc phát hiện (Scan, DNS Tunneling) hoạt động trơn tru.
    - Sử dụng colorama để in ra Terminal với màu sắc chuyên nghiệp chuẩn SOC/IDS.
"""

import os
import sys
import time
import json
import re
import random
import threading
from datetime import datetime
from typing import Generator, Dict, Any, Optional

# Cấu hình encoding UTF-8 cho terminal Windows để tránh lỗi hiển thị tiếng Việt
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Cố gắng import colorama, nếu chưa có sẽ tự động in không màu hoặc thông báo
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# --- ĐỊNH NGHĨA CÁC MÃ MÀU FALLBACK NẾU THIẾU COLORAMA ---
class Colors:
    CYAN = Fore.CYAN if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    MAGENTA = Fore.MAGENTA if HAS_COLORAMA else ""
    BLUE = Fore.BLUE if HAS_COLORAMA else ""
    WHITE = Fore.WHITE if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""


class ZeekLogSimulator(threading.Thread):
    """
    Bộ giả lập log mạng Zeek (Traffic Simulator).
    Tự động ghi các sự kiện mạng (Connection Logs) vào file log chỉ định để phục vụ demo/test.
    Hỗ trợ sinh kịch bản tấn công (Port Scan và DNS Tunneling) để các layer sau phát hiện.
    """
    def __init__(self, log_path: str, interval: float = 1.5):
        super().__init__()
        self.log_path = log_path
        self.interval = interval
        self.running = False
        self.daemon = True  # Thread tự động tắt khi main thread dừng
        
        # Đảm bảo thư mục cha tồn tại
        os.makedirs(os.path.dirname(os.path.abspath(self.log_path)), exist_ok=True)
        
        # IP giả lập
        self.attacker_ip = "10.38.50.3"
        self.gateway_ip = "10.38.50.1"
        self.normal_ips = ["10.38.50.4", "10.38.50.5", "10.38.50.6"]
        
        # Biến trạng thái để mô phỏng kịch bản
        self.step = 0

    def run(self) -> None:
        self.running = True
        
        # Khởi tạo file log rỗng
        with open(self.log_path, "w", encoding="utf-8") as f:
            f.write("") # Clear log cũ khi khởi chạy simulator
            
        print(f"{Colors.CYAN}[SYSTEM] Bộ giả lập Zeek Log đã khởi động. Ghi log vào: {self.log_path}{Colors.RESET}")
        
        while self.running:
            time.sleep(self.interval)
            self.step += 1
            
            # KỊCH BẢN GIẢ LẬP:
            # - Từ bước 1 đến 4: Giao dịch mạng bình thường
            # - Từ bước 5 đến 7: Kích hoạt hành vi Port Scan từ attacker_ip
            # - Từ bước 8 đến 10: Giao dịch mạng bình thường trở lại
            # - Từ bước 11 đến 12: Kích hoạt DNS Tunneling (thực chất ghi nhận truy cập DNS qua query lạ)
            
            log_entries = []
            
            if 5 <= self.step <= 7:
                # Kịch bản Port Scan: Gửi nhiều request đến các port khác nhau trong thời gian cực ngắn
                target_ports = random.sample(range(20, 1024), 6) # Quét 6 cổng mỗi giây
                for p in target_ports:
                    log_entries.append(self._generate_conn_entry(
                        src_ip=self.attacker_ip,
                        dst_ip=self.gateway_ip,
                        dst_port=p,
                        proto="TCP"
                    ))
            elif 11 <= self.step <= 12:
                # Kịch bản DNS Tunneling: IP của attacker gửi truy vấn DNS có subdomain ngẫu nhiên/entropy cao
                malicious_domains = [
                    "x8f9a.malware-c2.evil.com",
                    "a4b2c.malware-c2.evil.com",
                    "ff991.malware-c2.evil.com"
                ]
                # Log conn cho DNS query (Port 53, UDP) kèm query ảo
                log_entries.append(self._generate_conn_entry(
                    src_ip=self.attacker_ip,
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    proto="UDP",
                    extra={"query": random.choice(malicious_domains)}
                ))
            else:
                # Giao thông mạng bình thường (Normal web surfing, DNS)
                src = random.choice(self.normal_ips + [self.attacker_ip])
                dst = random.choice(["142.250.190.46", "10.38.50.1", "8.8.8.8"])
                proto = random.choice(["TCP", "UDP"])
                port = 80 if proto == "TCP" else 53
                if port == 80 and dst == "10.38.50.1":
                    port = 80  # Web Gateway
                elif port == 53:
                    dst = "8.8.8.8"
                
                log_entries.append(self._generate_conn_entry(
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=port,
                    proto=proto
                ))
                
            # Ghi log entries vào file
            self._write_logs(log_entries)

            # Reset kịch bản để lặp lại
            if self.step >= 15:
                self.step = 0

    def _generate_conn_entry(self, src_ip: str, dst_ip: str, dst_port: int, proto: str, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Tạo cấu trúc dict log Zeek conn hoàn chỉnh."""
        now = datetime.now()
        entry = {
            "ts": now.timestamp(),
            "uid": f"C{random.randint(100000, 999999)}",
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": proto,
            "service": "dns" if dst_port == 53 else ("http" if dst_port == 80 else "-"),
            "duration": round(random.uniform(0.01, 2.5), 3),
            "orig_bytes": random.randint(40, 1500),
            "resp_bytes": random.randint(40, 10000),
            "conn_state": "SF"
        }
        if extra:
            entry.update(extra)
        return entry

    def _write_logs(self, entries: list) -> None:
        """Ghi các bản ghi dạng JSON line xuống file log."""
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                for entry in entries:
                    f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"{Colors.RED}[ERR] Simulator không thể ghi file: {e}{Colors.RESET}")

    def stop(self) -> None:
        self.running = False


class ZeekTailer:
    """
    Lớp chịu trách nhiệm theo dõi và phân tích cú pháp (tail & parse) logs Zeek.
    Hỗ trợ chế độ đọc log thời gian thực tương tự lệnh `tail -f`.
    """
    def __init__(self, log_path: str):
        self.log_path = log_path
        # Regex dự phòng để phân tích cú pháp text thông thường nếu không phải JSON
        self.regex_conn = re.compile(
            r"(?P<timestamp>[\d\.\-]+)\s+(?P<uid>\w+)\s+(?P<src_ip>[\d\.\:a-fA-F]+)\s+(?P<src_port>\d+)\s+"
            r"(?P<dst_ip>[\d\.\:a-fA-F]+)\s+(?P<dst_port>\d+)\s+(?P<proto>\w+)"
        )

    def tail(self) -> Generator[Dict[str, Any], None, None]:
        """
        Lắng nghe liên tục các dòng mới được thêm vào file log.
        Yields:
            Dict chứa thông tin log đã được parse thành công.
        """
        # Đợi cho tới khi file log được tạo
        while not os.path.exists(self.log_path):
            time.sleep(0.5)

        with open(self.log_path, "r", encoding="utf-8") as f:
            # Di chuyển con trỏ tới cuối file log hiện tại (tail -f hành vi chuẩn)
            f.seek(0, os.SEEK_END)
            
            # Biến lưu trữ size hiện tại để phát hiện file log bị xoay vòng (truncated)
            last_size = os.path.getsize(self.log_path)

            while True:
                curr_size = os.path.getsize(self.log_path)
                
                # Nếu file bị rút gọn (ví dụ: LogRotate hoặc Simulator clear)
                if curr_size < last_size:
                    print(f"{Colors.YELLOW}[SYSTEM] Phát hiện file log bị cắt/xoay vòng. Đọc lại từ đầu.{Colors.RESET}")
                    f.seek(0, os.SEEK_SET)
                
                last_size = curr_size
                line = f.readline()
                
                if not line:
                    time.sleep(0.1)  # Giảm tải CPU
                    continue
                
                # Parse dòng log vừa nhận
                parsed_data = self._parse_line(line.strip())
                if parsed_data:
                    yield parsed_data

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Phân tích cú pháp dòng log dạng JSON hoặc Text sang Dictionary."""
        if not line or line.startswith("#"):
            return None # Bỏ qua các dòng trống hoặc dòng comment của Zeek TSV
            
        # 1. Thử parse dạng JSON
        try:
            data = json.loads(line)
            # Trích xuất và chuẩn hóa các trường thông tin cốt lõi
            return {
                "timestamp": data.get("ts"),
                "id.orig_h": data.get("id.orig_h"),
                "id.orig_p": data.get("id.orig_p"),
                "id.resp_h": data.get("id.resp_h"),
                "id.resp_p": data.get("id.resp_p"),
                "proto": str(data.get("proto")).upper(),
                "query": data.get("query")  # Kèm theo nếu có (dành cho DNS tunneling)
            }
        except json.JSONDecodeError:
            pass  # Nếu không phải JSON, tiếp tục thử dùng Regex cho TSV

        # 2. Thử parse dạng Text/TSV bằng Regex
        match = self.regex_conn.search(line)
        if match:
            gd = match.groupdict()
            try:
                return {
                    "timestamp": float(gd["timestamp"]),
                    "id.orig_h": gd["src_ip"],
                    "id.orig_p": int(gd["src_port"]),
                    "id.resp_h": gd["dst_ip"],
                    "id.resp_p": int(gd["dst_port"]),
                    "proto": gd["proto"].upper(),
                    "query": None
                }
            except ValueError:
                return None
                
        return None

    def print_log(self, log_dict: Dict[str, Any]) -> None:
        """
        In dòng log đã parse ra Terminal theo định dạng tiêu chuẩn.
        Đảm bảo khớp chính xác với đặc tả 'example_terminal_outputs' trong aivpn.json.
        """
        ts_val = log_dict.get("timestamp")
        # Định dạng timestamp sang chuỗi dễ nhìn YYYY-MM-DD HH:MM:SS
        if isinstance(ts_val, (int, float)):
            ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        src_ip = log_dict.get("id.orig_h")
        src_port = log_dict.get("id.orig_p")
        dst_ip = log_dict.get("id.resp_h")
        dst_port = log_dict.get("id.resp_p")
        proto = log_dict.get("proto")

        # In ra Console với màu sắc thiết kế cực kỳ bắt mắt
        # Ví dụ: [2026-05-20 11:31:05] [PARSER] Nhận luồng mới: 10.38.50.3:54321 -> 10.38.50.1:80 (TCP)
        print(
            f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
            f"{Colors.CYAN}{Colors.BRIGHT}[PARSER]{Colors.RESET} "
            f"Nhận luồng mới: {Colors.GREEN}{src_ip}:{src_port}{Colors.RESET} -> "
            f"{Colors.BLUE}{dst_ip}:{dst_port}{Colors.RESET} ({Colors.YELLOW}{proto}{Colors.RESET})"
        )


# --- HÀM KHỞI CHẠY KIỂM THỬ ĐỘC LẬP ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.GREEN}{Colors.BRIGHT}Mini AI VPN Gateway - Layer 2 Realtime Parser & Simulator{Colors.RESET} ")
    print("=" * 70)
    
    # Đường dẫn file log test mặc định
    DEFAULT_LOG = os.path.join("dataset", "conn.log")
    
    # Khởi động bộ Simulator trong Background
    simulator = ZeekLogSimulator(log_path=DEFAULT_LOG, interval=1.2)
    simulator.start()
    
    # Khởi động bộ Tailer để theo dõi sự thay đổi của file log
    tailer = ZeekTailer(log_path=DEFAULT_LOG)
    
    # In thông tin khởi động hệ thống theo phong cách aivpn.json
    start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"{Colors.DIM}[{start_ts}]{Colors.RESET} "
        f"{Colors.GREEN}{Colors.BRIGHT}[SYSTEM]{Colors.RESET} "
        f"AI VPN Gateway khởi động. Đang lắng nghe trên wg0..."
    )
    
    try:
        # Bắt đầu vòng lặp tail -f đọc và parse log
        for parsed_log in tailer.tail():
            tailer.print_log(parsed_log)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[SYSTEM] Đang dừng luồng giám sát log...{Colors.RESET}")
        simulator.stop()
        simulator.join(timeout=2.0)
        print(f"{Colors.GREEN}[SYSTEM] Đã tắt bộ giả lập an toàn.{Colors.RESET}")
        sys.exit(0)
