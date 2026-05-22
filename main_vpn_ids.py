#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Main Application Coordinator (Deep Learning LSTM Upgrade)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Kỹ sư Python Backend cấp cao
Mô tả:
    - File khởi chạy chính (Main Coordinator) phiên bản Deep Learning.
    - Khởi tạo hệ thống Gateway bằng cách nạp cấu hình động từ `slips.yaml`
      và nạp danh sách loại trừ tin cậy từ `whitelist.conf`.
    - Phối hợp và vận hành luồng xử lý:
        + Đọc log thời gian thực bền bỉ, chống crash khi log rotation (Layer 2).
        + Kiểm tra whitelist sớm nhất có thể để bypass ngay lập tức.
        + Chuyển tiếp kết nối không whitelisted sang Log Discretizer để mã hóa chuỗi thời gian (Layer 2).
        + Sử dụng collections.deque(maxlen=20) để lưu trữ Rolling Window (Sliding Window FIFO) cho từng IP.
        + Giải quyết an toàn sự cố "Khởi động nguội" (Cold Start): Chỉ suy luận khi nạp đủ 20 ký tự.
        + Dự đoán rủi ro bằng mạng LSTM thông qua ScoringEngine V2 (Layer 4).
        + Thực thi chặn IP độc hại qua FirewallBlocker (iptables) (Layer 4).
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


# --- IMPORT ĐỘNG CÁC LAYER THÀNH PHẦN ---
import importlib

# Layer 2: Log Tailer & Whitelist Parser & Log Discretizer
zeek_tailer = importlib.import_module("2_data_parser.zeek_tailer")
ZeekTailer = zeek_tailer.ZeekTailer

whitelist_parser = importlib.import_module("2_data_parser.whitelist_parser")
WhitelistParser = whitelist_parser.WhitelistParser

log_discretizer = importlib.import_module("2_data_parser.log_discretizer")
LogDiscretizer = log_discretizer.LogDiscretizer

# Layer 4: AI Risk Manager & Firewall Blocker
scoring_engine_v2 = importlib.import_module("4_risk_manager.scoring_engine_v2")
ScoringEngine = scoring_engine_v2.ScoringEngine

firewall_blocker = importlib.import_module("4_risk_manager.firewall_blocker")
FirewallBlocker = firewall_blocker.FirewallBlocker


class AIVPN_Gateway:
    """
    Hệ thống Gateway điều khiển trung tâm (Mini AI VPN Gateway) - Phiên bản LSTM AI.
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
        
        # 4. Khởi tạo Lớp 2: Log Tailer & Log Discretizer (LSTM Sliding Buffer maxlen=20)
        self.tailer = ZeekTailer(log_path=self.log_path)
        self.discretizer = LogDiscretizer(max_len=20)
        
        # 5. Khởi tạo Lớp 4: Risk Manager (LSTM Model) & Blocker (Tiêm cấu hình từ YAML)
        risk_cfg = self.config.get("risk_manager", {})
        threat_threshold = float(risk_cfg.get("threat_threshold", 0.8))
        # Nếu cấu hình slips.yaml có threat_threshold bằng 1.0 (cấu hình cũ), ta chuyển về 0.8 để mô hình LSTM phát hiện Beacon hiệu quả hơn
        if threat_threshold >= 1.0:
            threat_threshold = 0.8
            
        model_path = risk_cfg.get("model_path", "lstm_model.tflite")
        
        self.scorer = ScoringEngine(
            model_path=model_path,
            threat_threshold=threat_threshold
        )
        self.blocker = FirewallBlocker(
            dry_run=bool(risk_cfg.get("dry_run", True))
        )
        
        # Thread quản lý nền
        self.tailer_thread: Optional[threading.Thread] = None

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
        
        # Khởi chạy luồng Tailer lắng nghe và phân tích log thời gian thực
        self.tailer_thread = threading.Thread(target=self._run_log_pipeline, daemon=True)
        self.tailer_thread.start()

        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{Colors.DIM}[{start_ts}]{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BRIGHT}[SYSTEM]{Colors.RESET} "
            f"Hệ thống Mini AI VPN Gateway LSTM đang hoạt động trên interface {Colors.BRIGHT}{self.interface}{Colors.RESET}!"
        )
        print(f"{Colors.DIM}[SYSTEM] File log đang giám sát: {self.log_path}{Colors.RESET}")
        print(f"{Colors.DIM}[SYSTEM] Ngưỡng rủi ro AI (Threat Threshold): {self.scorer.threat_threshold * 100:.1f}%{Colors.RESET}\n")

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
                
                if not ip_src:
                    continue

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
                
                # In luồng kết nối hợp lệ chưa bị lọc ra terminal bằng ZeekTailer
                self.tailer.print_log(parsed_log)
                
                # 2. Đẩy log kết nối vào Log Discretizer để mã hóa ký tự và lưu buffer trượt maxlen=20
                char, window, is_ready, current_len = self.discretizer.process_log(parsed_log)
                if not char:
                    continue

                ts_val = parsed_log.get("timestamp")
                if isinstance(ts_val, (int, float)):
                    ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")
                else:
                    ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # In log phân tích Discretizer (màu vàng) cho gói tin hiện tại
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}[DISCRETIZER]{Colors.RESET} "
                    f"Mã hóa kết nối IP {Colors.GREEN}{ip_src}{Colors.RESET} -> Ký tự: '{Colors.BRIGHT}{Colors.MAGENTA}{char}{Colors.RESET}'"
                )

                # 3. Kiểm tra bảo vệ Cold Start (Graceful Wait)
                if not is_ready:
                    # Tuyệt đối không đưa vào AI suy luận khi chưa đủ 20 ký tự
                    # Chỉ in log lưu trữ thu thập dữ liệu (màu vàng)
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.YELLOW}[COLD_START]{Colors.RESET} "
                        f"IP {Colors.GREEN}{ip_src}{Colors.RESET} đang thu thập dữ liệu chuỗi: "
                        f"{Colors.YELLOW}{current_len}/20{Colors.RESET} ký tự. {Colors.DIM}[Buffer: {''.join(window)}]{Colors.RESET}"
                    )
                    continue

                # 4. Đẩy chuỗi 20 ký tự qua AI Scoring Engine V2 để dự đoán xác suất độc hại
                prob, is_malicious = self.scorer.evaluate_sequence(ip_src, window, ts_val)
                
                # 5. Nếu phát hiện nguy hại vượt ngưỡng -> Thực thi Firewall Block qua iptables
                if is_malicious:
                    self.blocker.block_ip(ip_src)

        except Exception as e:
            print(f"{Colors.RED}[LỖI PIPELINE] Lỗi xảy ra khi xử lý luồng log: {e}{Colors.RESET}")

    def stop(self) -> None:
        """Dừng hoạt động toàn bộ gateway an toàn."""
        print(f"\n{Colors.YELLOW}[SYSTEM] Đang dừng hệ thống Mini AI VPN Gateway...{Colors.RESET}")
        self.running = False
        print(f"{Colors.GREEN}[SYSTEM] Đã tắt toàn bộ Gateway và các thread con an toàn.{Colors.RESET}")


# --- KHỞI CHẠY CHƯƠNG TRÌNH CHÍNH ---
if __name__ == "__main__":
    print("=" * 80)
    print(f" {Colors.GREEN}{Colors.BRIGHT}Mini AI VPN Gateway - Tích Hợp Mô Hình Deep Learning LSTM{Colors.RESET} ")
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
