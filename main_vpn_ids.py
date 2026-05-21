#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Main Application Coordinator (Dynamic Upgrade)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Kỹ sư Python Backend cấp cao
Mô tả:
    - File khởi chạy chính (Main Coordinator).
    - Khởi tạo hệ thống Gateway bằng cách nạp cấu hình động từ `slips.yaml` (dùng PyYAML)
      và nạp danh sách loại trừ tin cậy từ `whitelist.conf` (thông qua WhitelistParser).
    - Phối hợp và vận hành đa luồng các Layer trong kiến trúc 4 lớp:
        + Đọc log thời gian thực bền bỉ, chống crash khi log rotation (Layer 2).
        + Kiểm tra whitelist sớm nhất có thể để bypass ngay lập tức, tiết kiệm RAM/CPU.
        + Chuyển tiếp luồng không whitelist qua các bộ phát hiện hành vi nguy hiểm (Layer 3).
        + Tính toán điểm rủi ro tập trung, tự động time decay và block IP qua iptables (Layer 4).
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Optional, Dict, Any

# Sử dụng PyYAML để nạp cấu hình linh hoạt từ slips.yaml
try:
    import yaml
except ImportError:
    print("[\033[31mERROR\033[0m] Thiếu thư viện PyYAML! Hãy cài đặt bằng lệnh: pip install pyyaml")
    sys.exit(1)

# Cố gắng import colorama để hiển thị UI SOC/IDS chuyên nghiệp và bắt mắt
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Đảm bảo in UTF-8 không gặp lỗi trên Windows PowerShell / Cmd
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


# --- ĐỊNH NGHĨA CÁC MÃ MÀU FALLBACK NẾU THIẾU COLORAMA ---
class Colors:
    CYAN = Fore.CYAN if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    MAGENTA = Fore.MAGENTA if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""
    BG_RED = Back.RED if HAS_COLORAMA else ""
    WHITE = Fore.WHITE if HAS_COLORAMA else ""


# --- IMPORT ĐỘNG CÁC LAYER THÀNH PHẦN (Tránh lỗi decimal literal do tên thư mục bắt đầu bằng số) ---
import importlib

# Layer 2: Log Tailer & Whitelist Parser
zeek_tailer = importlib.import_module("2_data_parser.zeek_tailer")
ZeekTailer = zeek_tailer.ZeekTailer

whitelist_parser = importlib.import_module("2_data_parser.whitelist_parser")
WhitelistParser = whitelist_parser.WhitelistParser

# Layer 3: Detection Engine (Scan, DNS, C2/Beacon)
scan_detector = importlib.import_module("3_detection_engine.scan_detector")
ScanDetector = scan_detector.ScanDetector

dns_detector = importlib.import_module("3_detection_engine.dns_detector")
DNSDetector = dns_detector.DNSDetector

markov_behavior = importlib.import_module("3_detection_engine.markov_behavior")
BehavioralDetector = markov_behavior.BehavioralDetector

# Layer 4: Risk Manager & Firewall Blocker
scoring_engine = importlib.import_module("4_risk_manager.scoring_engine")
ScoringEngine = scoring_engine.ScoringEngine

firewall_blocker = importlib.import_module("4_risk_manager.firewall_blocker")
FirewallBlocker = firewall_blocker.FirewallBlocker


class AIVPN_Gateway:
    """
    Hệ thống Gateway điều khiển trung tâm (Mini AI VPN Gateway).
    Quản lý luồng dữ liệu thời gian thực từ cấu hình slips.yaml và whitelist.conf.
    """
    def __init__(self, config_path: str = "config/slips.yaml", whitelist_path: str = "config/whitelist.conf"):
        self.config_path = config_path
        self.whitelist_path = whitelist_path
        self.running = False
        
        # 1. Nạp tệp cấu hình slips.yaml
        self.config = self._load_yaml_config()
        
        # 2. Nạp whitelist.conf
        print(f"{Colors.CYAN}[SYSTEM] Đang khởi tạo bộ lọc Whitelist từ: {self.whitelist_path}...{Colors.RESET}")
        self.whitelist = WhitelistParser(self.whitelist_path)
        
        # 3. Phân rã cấu hình gateway
        gateway_cfg = self.config.get("gateway", {})
        self.interface = gateway_cfg.get("interface", "wg0")
        log_dir = gateway_cfg.get("log_dir", "dataset")
        conn_log_name = gateway_cfg.get("conn_log_name", "conn.log")
        self.log_path = os.path.join(log_dir, conn_log_name)
        
        # 4. Khởi tạo Lớp 2: Log Tailer
        self.tailer = ZeekTailer(log_path=self.log_path)
        
        # 5. Khởi tạo Lớp 3: Detection Engine (Tiêm cấu hình từ YAML)
        det_cfg = self.config.get("detection", {})
        
        scan_cfg = det_cfg.get("scan", {})
        self.scan_detector = ScanDetector(
            window_size=float(scan_cfg.get("window_size", 10.0)),
            port_threshold=int(scan_cfg.get("port_threshold", 10)),
            ip_threshold=int(scan_cfg.get("ip_threshold", 5)),
            cooldown_time=float(scan_cfg.get("cooldown_time", 10.0))
        )
        
        dns_cfg = det_cfg.get("dns", {})
        self.dns_detector = DNSDetector(
            entropy_threshold=float(dns_cfg.get("entropy_threshold", 3.6)),
            length_threshold=int(dns_cfg.get("length_threshold", 30))
        )
        
        beacon_cfg = det_cfg.get("beacon", {})
        self.beacon_detector = BehavioralDetector(
            history_limit=int(beacon_cfg.get("history_limit", 10)),
            cv_threshold=float(beacon_cfg.get("cv_threshold", 0.10)),
            min_interval=float(beacon_cfg.get("min_interval", 1.0)),
            cooldown_time=float(beacon_cfg.get("cooldown_time", 10.0))
        )
        
        # 6. Khởi tạo Lớp 4: Risk Manager & Blocker (Tiêm cấu hình từ YAML)
        risk_cfg = self.config.get("risk_manager", {})
        self.scorer = ScoringEngine(
            block_threshold=float(risk_cfg.get("threat_threshold", 1.0)),
            decay_factor=float(risk_cfg.get("time_decay_factor", 0.95)),
            min_score=float(risk_cfg.get("min_score", 0.05))
        )
        self.blocker = FirewallBlocker(
            dry_run=bool(risk_cfg.get("dry_run", True))
        )
        
        # Threads quản lý nền
        self.tailer_thread: Optional[threading.Thread] = None
        self.decay_thread: Optional[threading.Thread] = None

    def _load_yaml_config(self) -> Dict[str, Any]:
        """Đọc và kiểm tra cấu trúc file cấu hình slips.yaml."""
        if not os.path.exists(self.config_path):
            print(f"{Colors.RED}[LỖI] Không tìm thấy file cấu hình tại {self.config_path}! Dừng hệ thống.{Colors.RESET}")
            sys.exit(1)
            
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                print(f"{Colors.GREEN}[SYSTEM] Nạp thành công file cấu hình slips.yaml!{Colors.RESET}")
                return config
        except Exception as e:
            print(f"{Colors.RED}[LỖI] Lỗi cú pháp/đọc file slips.yaml: {e}{Colors.RESET}")
            sys.exit(1)

    def start(self) -> None:
        """Khởi chạy toàn bộ hệ thống Mini AI VPN Gateway."""
        self.running = True
        
        # 1. Khởi chạy luồng Tailer lắng nghe và phân tích log thời gian thực
        self.tailer_thread = threading.Thread(target=self._run_log_pipeline, daemon=True)
        self.tailer_thread.start()
        
        # 2. Khởi chạy luồng Định kỳ Suy hao Điểm rủi ro (Time Decay)
        self.decay_thread = threading.Thread(target=self._run_time_decay_loop, daemon=True)
        self.decay_thread.start()

        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{Colors.DIM}[{start_ts}]{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BRIGHT}[SYSTEM]{Colors.RESET} "
            f"Hệ thống Mini AI VPN Gateway đang hoạt động trên interface {Colors.BRIGHT}{self.interface}{Colors.RESET}!"
        )
        print(f"{Colors.DIM}[SYSTEM] File log đang giám sát: {self.log_path}{Colors.RESET}\n")

    def _run_log_pipeline(self) -> None:
        """Đường ống tiếp nhận log và điều phối đến các Layer phân tích."""
        try:
            for parsed_log in self.tailer.tail():
                if not self.running:
                    break
                
                # Trích xuất các thực thể để kiểm tra Whitelist trước tiên
                ip_src = parsed_log.get("id.orig_h")
                ip_dst = parsed_log.get("id.resp_h")
                domain = parsed_log.get("query")
                
                # 1. Kiểm tra Whitelist kiểm soát ngay tại cổng ngõ vào
                if self.whitelist.is_whitelisted(ip_src=ip_src, ip_dst=ip_dst, domain=domain):
                    ts_val = parsed_log.get("timestamp")
                    if isinstance(ts_val, (int, float)):
                        ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Mô tả đối tượng được bypass để hiển thị trực quan
                    bypass_detail = f"SRC={ip_src}"
                    if ip_dst:
                        bypass_detail += f", DST={ip_dst}"
                    if domain:
                        bypass_detail += f", Domain={domain}"
                    
                    # Hiển thị log màu vàng chuẩn spec bypass
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.YELLOW}{Colors.BRIGHT}[WHITELIST]{Colors.RESET} "
                        f"{Colors.YELLOW}Bypass/Ignore luồng kết nối tin cậy: {bypass_detail}{Colors.RESET}"
                    )
                    continue  # Bỏ qua hoàn toàn, không phân tích, tiết kiệm CPU/RAM
                
                # In luồng kết nối hợp lệ chưa bị lọc ra terminal
                self.tailer.print_log(parsed_log)
                
                # Danh sách các bằng chứng nguy hại thu thập được từ dòng log hiện tại
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
                    # Cộng điểm rủi ro
                    self.scorer.add_evidence(ev)
                    
                    # Thực hiện chặn IP trên Firewall nếu điểm rủi ro vượt ngưỡng
                    if self.scorer.is_blocked(ip):
                        self.blocker.block_ip(ip)

        except Exception as e:
            print(f"{Colors.RED}[LỖI PIPELINE] Lỗi xảy ra khi xử lý luồng log: {e}{Colors.RESET}")

    def _run_time_decay_loop(self) -> None:
        """Luồng chạy ngầm thực hiện suy hao điểm rủi ro theo chu kỳ thời gian."""
        while self.running:
            # Chạy suy hao mỗi 30 giây để tối ưu kiểm thử (hoặc lấy từ config nếu cần thiết)
            time.sleep(30.0)
            
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
        print(f"{Colors.GREEN}[SYSTEM] Đã tắt toàn bộ Gateway và các thread con an toàn.{Colors.RESET}")


# --- KHỞI CHẠY CHƯƠNG TRÌNH CHÍNH ---
if __name__ == "__main__":
    print("=" * 80)
    print(f" {Colors.GREEN}{Colors.BRIGHT}Mini AI VPN Gateway - Tích Hợp Cấu Hình Slips & Whitelist{Colors.RESET} ")
    print("=" * 80)

    # Đăng ký các file cấu hình
    CONFIG_FILE = "config/slips.yaml"
    WHITELIST_FILE = "config/whitelist.conf"
    
    # Khởi chạy hệ thống Gateway
    gateway = AIVPN_Gateway(config_path=CONFIG_FILE, whitelist_path=WHITELIST_FILE)
    gateway.start()
    
    try:
        # Giữ main thread chạy liên tục
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        gateway.stop()
        sys.exit(0)
