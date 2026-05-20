#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Main Application Coordinator
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - File khởi chạy chính (Main App).
    - Khởi tạo các thread, kết nối luồng dữ liệu từ Parser (Lớp 2) -> Detection Engine (Lớp 3) -> Scorer & Blocker (Lớp 4).
    - Vận hành đa luồng thời gian thực:
        + Luồng 1: Simulator tự động sinh log Zeek ảo ghi vào dataset/conn.log.
        + Luồng 2: Tailer đọc log, chuyển tiếp qua 3 bộ phát hiện (Port Scan, DNS suspicious, C2 Beaconing).
        + Luồng 3: Định kỳ áp dụng Time Decay để suy hao điểm rủi ro sau mỗi 10 giây.
"""

import os
import sys
import time
import threading
from datetime import datetime

# Cố gắng import colorama để hiển thị UI SOC/IDS chuyên nghiệp
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Đảm bảo in UTF-8 không gặp lỗi trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Import các Layer thành phần một cách động để tránh lỗi cú pháp Python với thư mục bắt đầu bằng số
import importlib

zeek_tailer = importlib.import_module("2_data_parser.zeek_tailer")
ZeekTailer = zeek_tailer.ZeekTailer
#ZeekLogSimulator = zeek_tailer.ZeekLogSimulator

scan_detector = importlib.import_module("3_detection_engine.scan_detector")
ScanDetector = scan_detector.ScanDetector

dns_detector = importlib.import_module("3_detection_engine.dns_detector")
DNSDetector = dns_detector.DNSDetector

markov_behavior = importlib.import_module("3_detection_engine.markov_behavior")
BehavioralDetector = markov_behavior.BehavioralDetector

scoring_engine = importlib.import_module("4_risk_manager.scoring_engine")
ScoringEngine = scoring_engine.ScoringEngine

firewall_blocker = importlib.import_module("4_risk_manager.firewall_blocker")
FirewallBlocker = firewall_blocker.FirewallBlocker


class Colors:
    CYAN = Fore.CYAN if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""


class AIVPN_Gateway:
    """
    Hệ thống Gateway điều khiển trung tâm (Mini AI VPN Gateway).
    Phối hợp hoạt động của Log Tailer, các bộ Detectors, Scorer và Firewall Blocker.
    """
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.running = False
        
        # Khởi tạo Lớp 2: Parser & Simulator
        #self.simulator = ZeekLogSimulator(log_path=self.log_path, interval=1.2)
        self.tailer = ZeekTailer(log_path=self.log_path)
        
        # Khởi tạo Lớp 3: Detection Engine
        self.scan_detector = ScanDetector(window_size=10.0, port_threshold=10, ip_threshold=5, cooldown_time=10.0)
        self.dns_detector = DNSDetector(entropy_threshold=3.6, length_threshold=30)
        self.beacon_detector = BehavioralDetector(history_limit=10, cv_threshold=0.10, min_interval=1.0, cooldown_time=10.0)
        
        # Khởi tạo Lớp 4: Risk Manager
        self.scorer = ScoringEngine(block_threshold=1.0, decay_factor=0.98, min_score=0.05)
        self.blocker = FirewallBlocker()
        
        # Các thread quản lý
        self.tailer_thread: Optional[threading.Thread] = None
        self.decay_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Khởi chạy toàn bộ hệ thống Mini AI VPN Gateway."""
        self.running = True
        
        # 1. Khởi chạy Simulator để liên tục ghi log kết nối ảo
        #self.simulator.start()
        
        # Đợi 1 giây để simulator khởi tạo file log
        #time.sleep(1.0)
        
        # 2. Khởi chạy luồng Tailer lắng nghe và phân tích log thời gian thực
        self.tailer_thread = threading.Thread(target=self._run_log_pipeline, daemon=True)
        self.tailer_thread.start()
        
        # 3. Khởi chạy luồng Định kỳ Suy hao Điểm rủi ro (Time Decay)
        self.decay_thread = threading.Thread(target=self._run_time_decay_loop, daemon=True)
        self.decay_thread.start()

        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{Colors.DIM}[{start_ts}]{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BRIGHT}[SYSTEM]{Colors.RESET} "
            f"Hệ thống Mini AI VPN Gateway đang hoạt động và giám sát kết nối..."
        )

    def _run_log_pipeline(self) -> None:
        """Đường ống tiếp nhận log và điều phối đến các Layer phân tích."""
        try:
            for parsed_log in self.tailer.tail():
                if not self.running:
                    break
                
                # In luồng kết nối nhận được ra terminal (đã định dạng màu sắc ở zeek_tailer)
                self.tailer.print_log(parsed_log)
                
                # Danh sách bằng chứng thu thập được từ dòng log hiện tại
                evidences = []
                
                # Gửi qua Scan Detector (Lớp 3)
                ev_scan = self.scan_detector.process_log(parsed_log)
                if ev_scan:
                    evidences.append(ev_scan)
                    
                # Gửi qua DNS Detector (Lớp 3)
                ev_dns = self.dns_detector.process_log(parsed_log)
                if ev_dns:
                    evidences.append(ev_dns)
                    
                # Gửi qua Beaconing Detector (Lớp 3)
                ev_beacon = self.beacon_detector.process_log(parsed_log)
                if ev_beacon:
                    evidences.append(ev_beacon)
                    
                # Cộng dồn điểm rủi ro và thực thi hành động ngăn chặn (Lớp 4)
                for ev in evidences:
                    ip = ev["ip"]
                    # 1. Cộng điểm rủi ro
                    self.scorer.add_evidence(ev)
                    
                    # 2. Kiểm tra trạng thái rủi ro, thực hiện chặn IP nếu vượt ngưỡng
                    if self.scorer.is_blocked(ip):
                        self.blocker.block_ip(ip)

        except Exception as e:
            print(f"{Colors.RED}[LỖI PIPELINE] Lỗi xảy ra khi xử lý luồng log: {e}{Colors.RESET}")

    def _run_time_decay_loop(self) -> None:
        """Luồng chạy ngầm thực hiện suy hao điểm rủi ro theo chu kỳ thời gian."""
        while self.running:
            # Chạy suy hao mỗi 60 giây để dễ demo (trong thực tế có thể là 60 giây)
            time.sleep(60.0)
            
            # Áp dụng công thức suy hao
            self.scorer.apply_decay()
            
            # Đồng bộ hóa Firewall Blocker với ScoringEngine
            # Nếu IP đã tụt điểm rủi ro xuống dưới ngưỡng block -> Tiến hành gỡ chặn (UNBLOCK)
            for blocked_ip in list(self.blocker.active_blocks):
                if not self.scorer.is_blocked(blocked_ip):
                    self.blocker.unblock_ip(blocked_ip)

    def stop(self) -> None:
        """Dừng hoạt động toàn bộ gateway an toàn."""
        print(f"\n{Colors.YELLOW}[SYSTEM] Đang dừng hệ thống Mini AI VPN Gateway...{Colors.RESET}")
        self.running = False
        
        # Dừng simulator
        #self.simulator.stop()
        #self.simulator.join(timeout=2.0)
        
        print(f"{Colors.GREEN}[SYSTEM] Đã tắt toàn bộ Gateway và các thread con an toàn.{Colors.RESET}")


# --- KHỞI CHẠY CHƯƠNG TRÌNH CHÍNH ---
if __name__ == "__main__":
    print("=" * 80)
    print(f" {Colors.GREEN}{Colors.BRIGHT}Mini AI VPN Gateway - Hành vi & Hệ thống Chặn Tự động{Colors.RESET} ")
    print("=" * 80)

    # Đường dẫn log
    #LOG_FILE = os.path.join("dataset", "conn.log")
    LOG_FILE = "/opt/zeek/logs/current/conn.log"
    
    # Khởi chạy hệ thống Gateway
    gateway = AIVPN_Gateway(log_path=LOG_FILE)
    gateway.start()
    
    try:
        # Giữ main thread chạy liên tục
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        gateway.stop()
        sys.exit(0)
