#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Main Application Coordinator (Evidence-based & Producer-Consumer Upgrade)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Kỹ sư Python Backend cấp cao
Mô tả:
    - File khởi chạy chính (Main Coordinator) phiên bản Kiến trúc dựa trên Bằng chứng.
    - Áp dụng mô hình thiết kế bất đồng bộ Producer-Consumer thông qua queue.Queue:
        + Luồng Producer (Reader): Đọc log Zeek, kiểm tra Whitelist, cập nhật discretizer
          và chạy quét cổng tĩnh siêu nhanh, sau đó đẩy dữ liệu cần suy luận AI vào Queue.
        + Luồng Consumer (Worker): Nhận dữ liệu từ Queue, thực hiện suy luận Deep Learning LSTM
          và tương tác với EvidenceManager để phán quyết chặn IP.
        + Giải quyết triệt để vấn đề Blocking I/O khi lưu lượng log mạng tăng cao.
    - Quản lý tập trung bằng chứng và thực thi Luật kép tại lớp Bồi thẩm đoàn.
"""

import os
import sys
import time
import queue
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

# Layer 3: Static Port Scan Detector & DNS Detector
scan_detector = importlib.import_module("3_detection_engine.scan_detector")
ScanDetector = scan_detector.ScanDetector

dns_detector = importlib.import_module("3_detection_engine.dns_detector")
DNSDetector = dns_detector.DNSDetector

# Layer 4: AI Risk Manager & Evidence Manager
scoring_engine_v2 = importlib.import_module("4_risk_manager.scoring_engine_v2")
ScoringEngine = scoring_engine_v2.ScoringEngine

evidence_manager = importlib.import_module("4_risk_manager.evidence_manager")
EvidenceManager = evidence_manager.EvidenceManager
Evidence = evidence_manager.Evidence


class AIVPN_Gateway:
    """
    Hệ thống Gateway điều khiển trung tâm (Mini AI VPN Gateway) - Phiên bản Kiến trúc dựa trên Bằng chứng.
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
        
        # 5. Khởi tạo Lớp 3: Static Port Scan Detector & DNS Detector
        self.scan_detector = ScanDetector(
            ports_threshold=10, 
            window_seconds=10.0, 
            cooldown_seconds=10.0
        )
        self.dns_detector = DNSDetector(
            entropy_threshold=4.2,
            subdomain_len_threshold=45
        )
        
        # 6. Khởi tạo Lớp 4: LSTM Scoring Engine & Evidence Manager (Bồi thẩm đoàn)
        risk_cfg = self.config.get("risk_manager", {})
        threat_threshold = float(risk_cfg.get("threat_threshold", 0.8))
        if threat_threshold >= 1.0:
            threat_threshold = 0.8
            
        model_path = risk_cfg.get("model_path", "lstm_model.tflite")
        
        self.scorer = ScoringEngine(
            model_path=model_path,
            threat_threshold=threat_threshold
        )
        
        # Bồi thẩm đoàn nắm giữ Firewall Blocker
        self.evidence_manager = EvidenceManager(
            dry_run=bool(risk_cfg.get("dry_run", True)),
            ttl_seconds=300.0 # Bằng chứng có hiệu lực trong 5 phút
        )
        
        # 7. Khởi tạo Hàng đợi Thread-Safe và các Thread nền
        self.log_queue = queue.Queue(maxsize=1000)
        self.tailer_thread: Optional[threading.Thread] = None
        self.worker_thread: Optional[threading.Thread] = None

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
        
        # A. Khởi chạy luồng Worker xử lý suy luận AI và phán quyết bằng chứng trước (Consumer)
        self.worker_thread = threading.Thread(target=self._process_queue_worker, daemon=True)
        self.worker_thread.start()
        
        # B. Khởi chạy luồng Tailer lắng nghe và phân tích log thời gian thực (Producer)
        self.tailer_thread = threading.Thread(target=self._run_log_pipeline, daemon=True)
        self.tailer_thread.start()

        start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{Colors.DIM}[{start_ts}]{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BRIGHT}[SYSTEM]{Colors.RESET} "
            f"Hệ thống Mini AI VPN Gateway LSTM đang hoạt động trên interface {Colors.BRIGHT}{self.interface}{Colors.RESET}!"
        )
        print(f"{Colors.DIM}[SYSTEM] File log đang giám sát: {self.log_path}{Colors.RESET}")
        print(f"{Colors.DIM}[SYSTEM] Chế độ thiết kế: Kiến trúc dựa trên Bằng chứng & Bất đồng bộ (Queue){Colors.RESET}")
        print(f"{Colors.DIM}[SYSTEM] Ngưỡng rủi ro AI (Threat Threshold): {self.scorer.threat_threshold * 100:.1f}% | Nguong chan dong thuan: 1.50{Colors.RESET}\n")

    def _run_log_pipeline(self) -> None:
        """Đường ống tiếp nhận log (Producer): Đọc log, chạy whitelist, discretizer và quét cổng nhanh."""
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
                    ts_val = parsed_log.get("timestamp") or parsed_log.get("ts") or time.time()
                    ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")
                    
                    bypass_detail = f"SRC={ip_src}"
                    if ip_dst:
                        bypass_detail += f", DST={ip_dst}"
                    if domain:
                        bypass_detail += f", Domain={domain}"
                    
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.YELLOW}{Colors.BRIGHT}[WHITELIST]{Colors.RESET} "
                        f"{Colors.YELLOW}Bypass/Ignore luồng kết nối tin cậy: {bypass_detail}{Colors.RESET}"
                    )
                    continue
                
                # In luồng kết nối hợp lệ chưa bị lọc ra terminal
                self.tailer.print_log(parsed_log)
                
                # 2. Xử lý Quét Cổng Tĩnh siêu nhanh (Non-blocking computation)
                scan_evidence_data = self.scan_detector.process_log(parsed_log)
                if scan_evidence_data:
                    # Đóng gói và đẩy vào queue để Worker xử lý đồng nhất nhằm tránh tranh chấp đa luồng
                    queue_item = {
                        "type": "EVIDENCE",
                        "data": scan_evidence_data
                    }
                    try:
                        self.log_queue.put_nowait(queue_item)
                    except queue.Full:
                        pass
                
                # 2.5. Xử lý DNS Detector (Non-blocking computation)
                if domain:
                    dns_evidence_data = self.dns_detector.process_domain(ip_src, domain)
                    if dns_evidence_data:
                        queue_item = {
                            "type": "EVIDENCE",
                            "data": dns_evidence_data
                        }
                        try:
                            self.log_queue.put_nowait(queue_item)
                        except queue.Full:
                            pass
                
                # 3. Đẩy log kết nối vào Log Discretizer để mã hóa ký tự và lưu buffer trượt
                # Bỏ qua các cổng rác của Windows (NetBIOS, LLMNR, SSDP, mDNS, DHCP, DNS)
                # để tránh làm sai lệch chuỗi nhịp điệu phân tích của LSTM C2 Scorer (vì chúng cũng gửi định kỳ)
                resp_port = parsed_log.get("id.resp_p")
                try:
                    resp_port = int(resp_port) if resp_port is not None else 0
                except (ValueError, TypeError):
                    resp_port = 0

                noisy_ports = {53, 67, 68, 137, 138, 139, 1900, 5353, 5355}
                if resp_port in noisy_ports:
                    continue

                # Bỏ qua nếu IP nguồn này đang thực hiện quét nhiều cổng (Port Scan) trong cửa sổ 10s
                # nhằm loại bỏ lưu lượng quét cổng tốc độ cao gây nhiễu cho chuỗi trượt nhịp điệu của LSTM
                history_conns = self.scan_detector.history.get(ip_src, [])
                if history_conns:
                    unique_ports = {conn[1] for conn in history_conns}
                    if len(unique_ports) > 2:
                        # RẤT QUAN TRỌNG: Xóa sạch bộ đệm LSTM của IP này nếu phát hiện nó đang quét cổng!
                        # Ngăn chặn việc trộn lẫn lưu lượng Port Scan vào LSTM gây ra báo động nhầm "C2 Beaconing".
                        keys_to_clear = [k for k in self.discretizer.buffers.keys() if k.startswith(f"{ip_src}>")]
                        for k in keys_to_clear:
                            self.discretizer.buffers[k].clear()
                        continue

                char, window, is_ready, current_len, flow_key = self.discretizer.process_log(parsed_log)
                if not char:
                    continue

                ts_val = parsed_log.get("timestamp") or parsed_log.get("ts") or time.time()
                ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")

                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}[DISCRETIZER]{Colors.RESET} "
                    f"Mã hóa kết nối {Colors.GREEN}{flow_key}{Colors.RESET} -> Ký tự: '{Colors.BRIGHT}{Colors.MAGENTA}{char}{Colors.RESET}'"
                )

                # 4. Kiểm tra bảo vệ Cold Start (Graceful Wait)
                if not is_ready:
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.YELLOW}[COLD_START]{Colors.RESET} "
                        f"Luồng {Colors.GREEN}{flow_key}{Colors.RESET} đang thu thập dữ liệu: "
                        f"{Colors.YELLOW}{current_len}/20{Colors.RESET} ký tự. {Colors.DIM}[Buffer: {''.join(window)}]{Colors.RESET}"
                    )
                    continue

                # 5. Đóng gói dữ liệu chuỗi nạp đủ 20 ký tự đẩy vào hàng đợi suy luận AI (Non-blocking I/O)
                # Chuyển window sang list thông thường để tránh dữ liệu rolling biến đổi trong hàng đợi
                queue_item = {
                    "type": "AI_INFERENCE",
                    "ip": ip_src,
                    "window": list(window),
                    "timestamp": ts_val
                }
                
                try:
                    self.log_queue.put_nowait(queue_item)
                except queue.Full:
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.RED}[SYSTEM_WARNING] Hàng đợi phân tích đầy! Bỏ qua phân tích AI cho IP {ip_src}{Colors.RESET}"
                    )

        except Exception as e:
            print(f"{Colors.RED}[LỖI PIPELINE] Lỗi xảy ra khi xử lý luồng log: {e}{Colors.RESET}")

    def _process_queue_worker(self) -> None:
        """Bộ thu nhận hàng đợi (Consumer): Thực thi tính toán AI và nạp bằng chứng cho lop phan quyet."""
        while self.running:
            try:
                # Lấy tác vụ từ queue với timeout 0.5s để thread có thể thoát khi self.running = False
                try:
                    item = self.log_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                
                item_type = item.get("type")
                
                if item_type == "AI_INFERENCE":
                    ip = item.get("ip")
                    window = item.get("window")
                    timestamp = item.get("timestamp")
                    
                    # Gọi Scoring Engine suy luận AI LSTM (Tốn thời gian CPU nhưng chạy ở luồng Worker riêng biệt)
                    prob, is_malicious = self.scorer.evaluate_sequence(ip, window, timestamp)
                    
                    # Luật LSTM Phủ Quyết khẩn cấp hoặc gửi bằng chứng nghi ngờ
                    if prob >= 0.80:
                        evidence = Evidence(
                            ip=ip,
                            module_name="LSTM",
                            confidence=prob,
                            attack_type="Suspicious_Rhythm",
                            timestamp=timestamp
                        )
                        self.evidence_manager.add_evidence(evidence)
                        
                elif item_type == "EVIDENCE":
                    data = item.get("data")
                    # Chuyển đổi dữ liệu thô sang đối tượng Evidence
                    evidence = Evidence(
                        ip=data["ip"],
                        module_name=data["module_name"],
                        confidence=data["confidence"],
                        attack_type=data["attack_type"],
                        timestamp=data["timestamp"]
                    )
                    self.evidence_manager.add_evidence(evidence)
                
                # Báo cáo hoàn tất tác vụ
                self.log_queue.task_done()
                
            except Exception as e:
                print(f"{Colors.RED}[WORKER_ERROR] Lỗi trong tiến trình Worker: {e}{Colors.RESET}")
                time.sleep(0.1)

    def stop(self) -> None:
        """Dừng hoạt động toàn bộ gateway an toàn."""
        print(f"\n{Colors.YELLOW}[SYSTEM] Đang dừng hệ thống Mini AI VPN Gateway...{Colors.RESET}")
        self.running = False
        print(f"{Colors.GREEN}[SYSTEM] Đã tắt toàn bộ Gateway và các thread con an toàn.{Colors.RESET}")


# --- KHỞI CHẠY CHƯƠNG TRÌNH CHÍNH ---
if __name__ == "__main__":
    print("=" * 80)
    print(f" {Colors.GREEN}{Colors.BRIGHT}Mini AI VPN Gateway - Tích Hợp Kiến Trúc Bằng Chứng Bất Đồng Bộ{Colors.RESET} ")
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
