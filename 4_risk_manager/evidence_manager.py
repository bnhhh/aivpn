#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 4: Evidence Manager (Evidence-based Architecture)
Tác giả: Senior Software Architect & Cybersecurity Specialist
Mô tả:
    - Quản lý và tích lũy các Bằng chứng (Evidence) phát hiện được từ các module Lớp 3.
    - Áp dụng cơ chế Time-To-Live (TTL = 5 phút) để tự động đào thải các bằng chứng lỗi thời.
    - Triển khai **Cơ chế Luật kép (Dual-Rule System)** tối tân để đưa ra phán quyết chặn IP:
        + Luật 1 (Đồng thuận - Consensus): Tổng điểm bằng chứng (Confidence) tích lũy >= 1.5.
        + Luật 2 (Phủ quyết - Critical Bypass): Có bất kỳ bằng chứng đơn lẻ nào có Confidence >= 0.85.
    - Thực thi gọi FirewallBlocker để áp luật chặn tường lửa iptables.
"""

import sys
import time
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime

# Import động FirewallBlocker do tên thư mục 4_risk_manager bắt đầu bằng số
import importlib
firewall_blocker = importlib.import_module("4_risk_manager.firewall_blocker")
FirewallBlocker = firewall_blocker.FirewallBlocker

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Cố gắng import colorama để hiển thị log SOC sinh động
try:
    import colorama
    from colorama import Fore, Back, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

class Colors:
    CYAN = Fore.CYAN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""
    BG_RED = Back.RED if HAS_COLORAMA else ""
    WHITE = Fore.WHITE if HAS_COLORAMA else ""


class Evidence:
    """
    Vật thể Bằng chứng (Evidence) được sinh ra từ các module phát hiện (Hunters).
    """
    def __init__(self, ip: str, module_name: str, confidence: float, attack_type: str, timestamp: Optional[float] = None):
        self.ip = ip
        self.module_name = module_name
        self.confidence = float(confidence)
        self.attack_type = attack_type
        self.timestamp = timestamp if timestamp is not None else time.time()

    def __repr__(self) -> str:
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
        return f"<Evidence {self.module_name} for {self.ip} | Conf: {self.confidence:.2f} | {self.attack_type} | {ts_str}>"


class EvidenceManager:
    """
    Bồi thẩm đoàn (Jury) - Quản lý, phân tích tổng hợp bằng chứng và đưa ra quyết định thực thi chặn IP.
    """
    def __init__(self, dry_run: bool = False, ttl_seconds: float = 300.0):
        self.ttl_seconds = ttl_seconds
        
        # Khởi tạo Firewall Blocker làm công cụ thực thi chặn IP
        self.blocker = FirewallBlocker(dry_run=dry_run)
        
        # Profile của từng IP nguồn:
        # { ip: { "evidences": [Evidence, ...], "blocked": False, "verdict": None, "total_score": 0.0 } }
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def add_evidence(self, evidence: Evidence) -> None:
        """
        Tiếp nhận bằng chứng mới cho một địa chỉ IP và đánh giá lại Profile của IP đó.
        """
        ip = evidence.ip
        if ip not in self.profiles:
            self.profiles[ip] = {
                "evidences": [],
                "blocked": False,
                "verdict": None,
                "total_score": 0.0
            }
            
        self.profiles[ip]["evidences"].append(evidence)
        
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(evidence.timestamp))
        print(
            f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
            f"{Colors.CYAN}{Colors.BRIGHT}[EVIDENCE]{Colors.RESET} "
            f"Bồi thẩm đoàn nhận bằng chứng từ [{Colors.BRIGHT}{evidence.module_name}{Colors.RESET}]: "
            f"IP={Colors.GREEN}{evidence.ip}{Colors.RESET}, Conf={Colors.YELLOW}{evidence.confidence:.2f}{Colors.RESET}, Tấn công={Colors.DIM}{evidence.attack_type}{Colors.RESET}"
        )
        
        # Đánh giá lại hồ sơ IP để kiểm tra xem có đưa ra phán quyết Block hay không
        self.evaluate_profile(ip)

    def evaluate_profile(self, ip: str) -> None:
        """
        Đánh giá hồ sơ bằng chứng của một IP, áp dụng TTL dọn dẹp bằng chứng cũ và kiểm thử hệ luật kép.
        """
        if ip not in self.profiles:
            return
            
        profile = self.profiles[ip]
        now = time.time()
        
        # 1. Áp dụng TTL (5 phút) loại bỏ các bằng chứng lỗi thời
        profile["evidences"] = [
            ev for ev in profile["evidences"]
            if now - ev.timestamp <= self.ttl_seconds
        ]
        
        # Nếu không còn bằng chứng nào và chưa bị block, ta có thể xóa profile để tiết kiệm RAM
        if not profile["evidences"] and not profile["blocked"]:
            del self.profiles[ip]
            return
            
        # 2. Cộng dồn tổng điểm rủi ro từ các bằng chứng còn hiệu lực
        total_score = sum(ev.confidence for ev in profile["evidences"])
        profile["total_score"] = round(total_score, 4)
        
        # Tránh tính toán lại nếu IP đã bị chặn cứng trước đó
        if profile["blocked"]:
            return

        # 3. Kiểm tra xem có tồn tại bằng chứng khẩn cấp (Critical Bypass) hay không
        critical_evidence = None
        for ev in profile["evidences"]:
            if ev.confidence >= 0.85:
                critical_evidence = ev
                break
                
        has_critical = critical_evidence is not None
        has_consensus = total_score >= 1.5
        
        # 4. Thực thi phán quyết nếu thỏa mãn Luật kép (Dual-Rule System)
        if has_consensus or has_critical:
            verdict = ""
            rule_applied = ""
            
            # Phân loại và định danh mã độc theo dấu vết các bằng chứng
            if has_critical:
                rule_applied = "QUYỀN PHỦ QUYẾT KHẨN CẤP (Confidence >= 0.85)"
                if critical_evidence.module_name == "LSTM":
                    verdict = "Critical C2 Beaconing (Deep Learning)"
                elif critical_evidence.module_name == "ScanDetector":
                    verdict = "Critical Port Scan Attack"
                else:
                    verdict = f"Critical Attack ({critical_evidence.attack_type})"
            else:
                rule_applied = "ĐỒNG THUẬN CỘNG DỒN (Tổng điểm >= 1.5)"
                modules = {ev.module_name for ev in profile["evidences"]}
                if "LSTM" in modules and "ScanDetector" in modules:
                    verdict = "Botnet/C2 (LSTM Beaconing + Port Scan)"
                elif "ScanDetector" in modules:
                    verdict = "Nmap Port Scan (High Volume)"
                elif "LSTM" in modules:
                    verdict = "C2 Beaconing (Suspicious Rhythm)"
                else:
                    verdict = "Combined Suspicious Network Activity"
            
            # Áp dụng lệnh khóa tường lửa
            profile["blocked"] = True
            profile["verdict"] = verdict
            
            ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"\n{Colors.DIM}[{ts_str}]{Colors.RESET} "
                f"{Colors.RED}{Colors.BRIGHT}[JURY_VERDICT]{Colors.RESET} "
                f"{Colors.BG_RED}{Colors.WHITE}{Colors.BRIGHT} PHÁN QUYẾT BỒI THẨM ĐOÀN {Colors.RESET}\n"
                f"  -> IP Bị Kết Án   : {Colors.BRIGHT}{Colors.YELLOW}{ip}{Colors.RESET}\n"
                f"  -> Tội danh định danh: {Colors.BRIGHT}{Colors.RED}{verdict}{Colors.RESET}\n"
                f"  -> Tổng điểm tích lũy: {Colors.BRIGHT}{Colors.CYAN}{total_score:.2f}{Colors.RESET} / 1.50\n"
                f"  -> Quy tắc áp dụng: {Colors.DIM}{rule_applied}{Colors.RESET}\n"
                f"  {Colors.RED}[>>> TIẾN HÀNH KHÓA KHẨN CẤP VÀ TỐNG XUẤT IP KHỎI VPN GATEWAY <<<]{Colors.RESET}"
            )
            
            # Thực thi chặn IP qua iptables
            self.blocker.block_ip(ip)
            print("-" * 80 + "\n")


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.CYAN}{Colors.BRIGHT}Kiểm thử độc lập: EvidenceManager (Dual-Rule System){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo Manager (dry_run=True)
    manager = EvidenceManager(dry_run=True)
    ip_compromised = "192.168.100.5"
    ip_critical = "192.168.100.9"

    # --- TEST 1: Luật đồng thuận (Consensus - Tổng điểm >= 1.5) ---
    print("\n=== [TEST 1] THỰC THI LUẬT ĐỒNG THUẬN (Cộng dồn các hành vi nhỏ) ===")
    
    # 1. Thêm bằng chứng Port Scan nhẹ (Confidence = 0.7)
    ev1 = Evidence(ip=ip_compromised, module_name="ScanDetector", confidence=0.7, attack_type="High_Connection_Rate")
    manager.add_evidence(ev1)
    
    # Hệ thống không được chặn vì tổng điểm mới = 0.7 < 1.5 và confidence < 0.85
    assert not manager.profiles[ip_compromised]["blocked"], "Lỗi: Đã block IP sớm!"
    print("-> Bước 1 ĐẠT: Chỉ có Scan (0.7) -> An toàn (Chưa chặn).")

    # 2. Gửi thêm bằng chứng LSTM nghi ngờ trung bình (Confidence = 0.5)
    ev2 = Evidence(ip=ip_compromised, module_name="LSTM", confidence=0.5, attack_type="Suspicious_Rhythm")
    manager.add_evidence(ev2)
    
    # Tổng điểm = 0.7 + 0.5 = 1.2 < 1.5 -> Không chặn
    assert not manager.profiles[ip_compromised]["blocked"], "Lỗi: Đã block IP sớm tại bước 2!"
    print("-> Bước 2 ĐẠT: Tổng điểm 1.2 -> An toàn (Chưa chặn).")

    # 3. Gửi thêm một bằng chứng nữa từ module DNS (Confidence = 0.4)
    ev3 = Evidence(ip=ip_compromised, module_name="DNS_Detector", confidence=0.4, attack_type="DNS_Tunneling")
    manager.add_evidence(ev3)
    
    # Tổng điểm = 0.7 + 0.5 + 0.4 = 1.6 >= 1.5 -> KÍCH HOẠT CHẶN QUA ĐỒNG THUẬN!
    assert manager.profiles[ip_compromised]["blocked"], "Lỗi: Không chặn IP khi tổng điểm >= 1.5!"
    print("-> Bước 3 ĐẠT: Tổng điểm 1.6 >= 1.5 -> ĐÃ CHẶN THÀNH CÔNG (Luật Đồng Thuận).")

    # --- TEST 2: Luật phủ quyết (Critical Bypass - confidence >= 0.85) ---
    print("\n=== [TEST 2] THỰC THI LUẬT PHỦ QUYẾT (Critical Bypass từ AI LSTM) ===")
    
    # Gửi một bằng chứng duy nhất từ AI LSTM với độ chính xác Beaconing cực cao (Confidence = 0.96)
    ev_crit = Evidence(ip=ip_critical, module_name="LSTM", confidence=0.96, attack_type="Suspicious_Rhythm")
    manager.add_evidence(ev_crit)
    
    # Chỉ có 1 bằng chứng, tổng điểm = 0.96 < 1.5. Nhưng confidence = 0.96 >= 0.85 -> PHẢI CHẶN LẬP TỨC!
    assert manager.profiles[ip_critical]["blocked"], "Lỗi: Không chặn IP khi có bằng chứng khẩn cấp >= 0.85!"
    assert manager.profiles[ip_critical]["verdict"] == "Critical C2 Beaconing (Deep Learning)", "Lỗi: Định danh sai tội danh!"
    print("-> Test 2 ĐẠT: Đã chặn khẩn cấp IP thành công với bằng chứng AI = 0.96 (Luật Phủ Quyết).")
