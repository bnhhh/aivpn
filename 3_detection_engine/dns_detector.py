#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 3: Detection Engine (DNS DGA & Tunneling Detector)
Tác giả: Chuyên gia An toàn Thông tin & Senior Cybersecurity Engineer
Mô tả:
    - Phát hiện hành vi DNS Tunneling và mã độc sử dụng thuật toán sinh tên miền động (DGA - Domain Generation Algorithm).
    - Sử dụng thuật toán toán học Shannon Entropy để tính toán mức độ hỗn loạn thông tin của chuỗi tên miền.
    - Thực hiện bóc tách subdomain thông minh (không phụ thuộc thư viện ngoài) để kiểm tra độ dài chuỗi rò rỉ dữ liệu.
    - Hoàn toàn tuân thủ kiến trúc dựa trên Bằng chứng: Chỉ trả về Dictionary thông tin Evidence,
      không chứa logic chặn hay gọi trực tiếp iptables.
"""

import sys
import time
import math
from collections import Counter
from typing import Dict, Optional, Any

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
    CYAN = Fore.CYAN if HAS_COLORAMA else ""


def calculate_entropy(domain_string: str) -> float:
    """
    Tính toán Shannon Entropy của chuỗi tên miền để đo lường độ hỗn loạn thông tin.
    Công thức toán học Shannon Entropy:
        H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)
    Trong đó:
        - P(x_i) là xác suất xuất hiện của ký tự x_i trong chuỗi tên miền.
        - Tên miền DGA sinh ngẫu nhiên (ví dụ: 'x8f9a2z9p1m.evil.com') sẽ có entropy rất cao (thường > 4.0),
          trong khi tên miền thông thường tiếng Anh/Việt (ví dụ: 'google.com', 'wikipedia.org') có entropy thấp (thường < 3.5).
    """
    if not domain_string:
        return 0.0
        
    total_len = len(domain_string)
    # Đếm tần suất xuất hiện của từng ký tự trong chuỗi
    char_counts = Counter(domain_string)
    
    # Tính entropy theo công thức Shannon
    entropy = 0.0
    for count in char_counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)
        
    return round(entropy, 4)


class DNSDetector:
    """
    Module phân tích lưu lượng tên miền (DNS Traffic Analysis Hunter).
    """
    def __init__(self, entropy_threshold: float = 4.2, subdomain_len_threshold: int = 45, cooldown_seconds: float = 10.0):
        self.entropy_threshold = entropy_threshold
        self.subdomain_len_threshold = subdomain_len_threshold
        self.cooldown_seconds = cooldown_seconds
        
        # Thời điểm gửi bằng chứng gần nhất của từng IP theo loại tấn công: { "ip_attackType": timestamp }
        self.last_evidence_time: Dict[str, float] = {}

    def extract_subdomain(self, domain: str) -> str:
        """
        Bóc tách subdomain thông minh từ tên miền đầy đủ (FQDN).
        Ví dụ:
            - 'en.wikipedia.org' -> 'en'
            - 'a.b.c.malware-dns.com' -> 'a.b.c'
            - 'google.com' -> '' (Không có subdomain)
        """
        if not domain:
            return ""
            
        parts = domain.split('.')
        # Nếu chỉ có domain name và TLD (ví dụ google.com), không có subdomain
        if len(parts) <= 2:
            return ""
            
        # Subdomain là phần còn lại khi loại bỏ 2 phần cuối (Domain name + TLD)
        return ".".join(parts[:-2])

    def process_domain(self, ip_src: str, domain: str) -> Optional[Dict[str, Any]]:
        """
        Phân tích tên miền truy vấn từ log và kiểm thử các quy tắc an toàn.
        Args:
            ip_src: Địa chỉ IP nguồn thực hiện truy vấn DNS.
            domain: Tên miền đầy đủ truy vấn (ví dụ: 'x8f9a.malware.com').
        Returns:
            Dictionary chứa các thuộc tính Evidence nếu phát hiện bất thường, ngược lại trả về None.
        """
        if not ip_src or not domain:
            return None
            
        ts = time.time()
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        
        # 1. Trích xuất subdomain để kiểm tra DNS Tunneling (Rò rỉ thông tin qua TXT/CNAME query)
        subdomain = self.extract_subdomain(domain)
        subdomain_len = len(subdomain)
        
        # --- LUẬT 2: Phát hiện DNS Tunneling (Độ dài subdomain lớn) ---
        if subdomain_len > self.subdomain_len_threshold:
            attack_type = "DNS_Tunneling"
            cache_key = f"{ip_src}_{attack_type}"
            last_sent = self.last_evidence_time.get(cache_key, 0.0)
            if ts - last_sent >= self.cooldown_seconds:
                self.last_evidence_time[cache_key] = ts
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}{Colors.BRIGHT}[DNS_DETECT]{Colors.RESET} "
                    f"IP {Colors.GREEN}{ip_src}{Colors.RESET} truy vấn tên miền có Subdomain quá dài ({Colors.BRIGHT}{subdomain_len}{Colors.RESET} ký tự): '{Colors.CYAN}{domain}{Colors.RESET}'!"
                )
                return {
                    "ip": ip_src,
                    "module_name": "DNS_Detector",
                    "confidence": 0.90, # Ngưỡng cực kỳ cao
                    "attack_type": attack_type,
                    "timestamp": ts
                }
            return None
            
        # --- LUẬT 1: Phát hiện DGA (Shannon Entropy cao) ---
        entropy = calculate_entropy(domain)
        if entropy >= self.entropy_threshold:
            attack_type = "DGA_Malware"
            cache_key = f"{ip_src}_{attack_type}"
            last_sent = self.last_evidence_time.get(cache_key, 0.0)
            if ts - last_sent >= self.cooldown_seconds:
                self.last_evidence_time[cache_key] = ts
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}{Colors.BRIGHT}[DNS_DETECT]{Colors.RESET} "
                    f"IP {Colors.GREEN}{ip_src}{Colors.RESET} truy vấn tên miền có mức độ hỗn loạn cao (Entropy = {Colors.BRIGHT}{entropy:.4f}{Colors.RESET}): '{Colors.CYAN}{domain}{Colors.RESET}'!"
                )
                return {
                    "ip": ip_src,
                    "module_name": "DNS_Detector",
                    "confidence": 0.85, # Đạt ngưỡng phủ quyết khẩn cấp (Critical Bypass)
                    "attack_type": attack_type,
                    "timestamp": ts
                }
            return None
        elif 3.6 <= entropy < self.entropy_threshold:
            attack_type = "Suspicious_Domain"
            cache_key = f"{ip_src}_{attack_type}"
            last_sent = self.last_evidence_time.get(cache_key, 0.0)
            if ts - last_sent >= self.cooldown_seconds:
                self.last_evidence_time[cache_key] = ts
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.YELLOW}{Colors.BRIGHT}[DNS_DETECT]{Colors.RESET} "
                    f"IP {Colors.GREEN}{ip_src}{Colors.RESET} truy vấn tên miền mờ ám (Entropy = {Colors.BRIGHT}{entropy:.4f}{Colors.RESET}): '{Colors.CYAN}{domain}{Colors.RESET}'!"
                )
                return {
                    "ip": ip_src,
                    "module_name": "DNS_Detector",
                    "confidence": 0.70, # Dưới ngưỡng phủ quyết, chờ Đồng Thuận
                    "attack_type": attack_type,
                    "timestamp": ts
                }
            return None

        return None


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.CYAN}{Colors.BRIGHT}Kiểm thử độc lập: DNSDetector (Layer 3){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo detector
    detector = DNSDetector()
    ip_test = "10.38.50.3"

    # 1. Thử nghiệm tính toán Shannon Entropy
    print("\n--- [TEST 1] Đánh giá Shannon Entropy của các tên miền ---")
    domains = [
        "google.com",
        "wikipedia.org",
        "en.wikipedia.org",
        "x8f9a2z9p1m.evil.com", # DGA điển hình
        "qweasdzxcrtyfghvbnuio.malware-dns.net" # DGA dài
    ]
    for d in domains:
        ent = calculate_entropy(d)
        print(f"  -> Domain: {d:<40} | Entropy: {ent:.4f}")
        
    # 2. Thử nghiệm bóc tách subdomain
    print("\n--- [TEST 2] Trích xuất Subdomain ---")
    sub_tests = [
        ("google.com", ""),
        ("en.wikipedia.org", "en"),
        ("a.b.c.malware.com", "a.b.c")
    ]
    for orig, expected in sub_tests:
        extracted = detector.extract_subdomain(orig)
        print(f"  -> FQDN: {orig:<30} | Subdomain: '{extracted}' | Khớp? {extracted == expected}")

    # 3. Phân tích truy vấn bình thường
    print("\n--- [TEST 3] Phân tích tên miền Bình thường ---")
    normal_ev = detector.process_domain(ip_test, "en.wikipedia.org")
    print(f"  -> Kết quả: {normal_ev} (Thành công - Không có bằng chứng)")

    # 4. Phân tích tên miền DGA (Entropy cao)
    print("\n--- [TEST 4] Phân tích tên miền DGA ---")
    dga_ev = detector.process_domain(ip_test, "x8f9a2z9p1m.evil.com")
    print(f"  -> Kết quả: {dga_ev} (Thành công - Tạo bằng chứng DGA)")
    assert dga_ev is not None and dga_ev["attack_type"] == "DGA_Malware", "Lỗi: Không phát hiện DGA!"

    # 5. Phân tích DNS Tunneling (Subdomain dài)
    print("\n--- [TEST 5] Phân tích DNS Tunneling ---")
    # Subdomain dài 54 ký tự
    tunnel_domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a.tunnel.evil.com"
    tunnel_ev = detector.process_domain(ip_test, tunnel_domain)
    print(f"  -> Kết quả: {tunnel_ev} (Thành công - Tạo bằng chứng Tunneling)")
    assert tunnel_ev is not None and tunnel_ev["attack_type"] == "DNS_Tunneling", "Lỗi: Không phát hiện DNS Tunneling!"
