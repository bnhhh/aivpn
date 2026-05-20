#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 3: Detection Engine (DNS Detector)
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Phân tích tên miền truy vấn (DNS queries) để phát hiện hành vi DNS Tunneling và tên miền DGA.
    - Áp dụng thuật toán tính toán Shannon Entropy đo lường độ ngẫu nhiên của chuỗi domain.
    - Nhận biết các dấu hiệu đóng gói dữ liệu dựa trên độ dài của domain (> 30 ký tự).
    - Đối chiếu từ khóa nguy hại ('malware', 'exfil', 'c2', 'tunnel', 'evil') và TLDs đáng ngờ (.xyz, .top, .ru).
"""

import sys
import time
import math
from datetime import datetime
from typing import Dict, Optional, Any

# Cố gắng import colorama để phục vụ giao diện terminal chuẩn SOC/IDS
try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Đảm bảo UTF-8 hoạt động mượt mà trên môi trường Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

class Colors:
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""


class DNSDetector:
    """
    Bộ phân tích hành vi DNS truy cập để tìm kiếm dấu hiệu C2/Tunneling/DGA.
    """
    def __init__(self, entropy_threshold: float = 3.6, length_threshold: int = 30):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        
        # Danh sách từ khóa độc hại/đáng ngờ thường gặp trong C2/Exfiltration
        self.suspicious_keywords = ["malware", "exfil", "tunnel", "c2", "evil", "dnsleak", "payload"]
        
        # Danh sách TLDs (tên miền cấp cao nhất) có độ tin cậy thấp, thường dùng cho DGA/Spam
        self.suspicious_tlds = [".xyz", ".top", ".tk", ".ru", ".cc", ".biz", ".live"]

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """
        Tính toán Shannon Entropy của một chuỗi văn bản.
        Entropy đo lường mức độ ngẫu nhiên của các ký tự (Domain DGA có entropy rất cao).
        Công thức: H = - sum(P(x) * log2(P(x)))
        """
        if not text:
            return 0.0
            
        length = len(text)
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
            
        entropy = 0.0
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return round(entropy, 3)

    def process_log(self, log_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Phân tích log DNS để tìm kiếm dấu hiệu rò rỉ hoặc C2 Tunneling.
        Args:
            log_dict: Dict chứa thông tin log mạng (yêu cầu trường 'query').
        Returns:
            Evidence Dict nếu phát hiện vi phạm, ngược lại trả về None.
        """
        query = log_dict.get("query")
        src_ip = log_dict.get("id.orig_h")
        ts = log_dict.get("timestamp")

        # Bỏ qua các log không chứa truy vấn DNS hoặc thiếu IP nguồn
        if not query or not src_ip:
            return None

        if ts is None:
            ts = time.time()
        else:
            try:
                ts = float(ts)
            except (ValueError, TypeError):
                ts = time.time()

        query_lower = query.lower()
        
        # --- CÁC TIÊU CHÍ ĐÁNH GIÁ AN TOÀN ---
        
        # 1. Kiểm tra Entropy của domain (đo độ ngẫu nhiên DGA)
        # Loại bỏ TLDs phổ biến để tránh làm giảm độ chính xác của Entropy
        domain_parts = query_lower.split(".")
        main_subdomain = domain_parts[0] if domain_parts else query_lower
        entropy_val = self.calculate_entropy(main_subdomain)
        is_high_entropy = entropy_val > self.entropy_threshold

        # 2. Kiểm tra độ dài truy vấn (Đặc trưng của DNS Tunneling đóng gói payload)
        is_too_long = len(query_lower) > self.length_threshold

        # 3. Kiểm tra từ khóa đáng ngờ
        has_suspicious_keyword = any(kw in query_lower for kw in self.suspicious_keywords)

        # 4. Kiểm tra TLDs độ tin cậy thấp
        has_suspicious_tld = any(query_lower.endswith(tld) for tld in self.suspicious_tlds)

        # Kích hoạt cảnh báo nếu thỏa mãn bất kỳ tiêu chí rủi ro nào
        if is_high_entropy or is_too_long or has_suspicious_keyword or has_suspicious_tld:
            weight = 0.6
            ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            
            # Lý do cảnh báo
            reasons = []
            if is_high_entropy: reasons.append(f"High Entropy ({entropy_val})")
            if is_too_long: reasons.append(f"Too Long ({len(query)} chars)")
            if has_suspicious_keyword: reasons.append("Suspicious Keyword")
            if has_suspicious_tld: reasons.append("Untrusted TLD")

            reason_str = ", ".join(reasons)
            
            # In cảnh báo ra Terminal chuẩn đặc tả JSON aivpn.json
            # Mẫu: [2026-05-20 11:31:15] [DNS_DETECT] IP 10.38.50.3 truy vấn domain lạ: x8f9a.malware-c2.evil.com! Gửi bằng chứng (Weight: 0.6).
            print(
                f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                f"{Colors.YELLOW}{Colors.BRIGHT}[DNS_DETECT]{Colors.RESET} "
                f"IP {src_ip} truy vấn domain lạ: {Colors.RED}{query}{Colors.RESET}! "
                f"Gửi bằng chứng (Weight: {weight}). {Colors.DIM}[Reason: {reason_str}]{Colors.RESET}"
            )

            # Trả về đối tượng Evidence để Scorer xử lý
            return {
                "ip": src_ip,
                "alert_type": "DNS_SUSPICIOUS",
                "weight": weight,
                "timestamp": ts,
                "details": f"Query: {query}, Reason: {reason_str}"
            }

        return None


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.YELLOW}{Colors.BRIGHT}Kiểm thử độc lập: DNSDetector (Layer 3){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo DNS Detector
    detector = DNSDetector(entropy_threshold=3.6, length_threshold=30)
    now = time.time()

    # KỊCH BẢN 1: Tên miền hợp lệ phổ biến (Không sinh cảnh báo)
    print("\n[TEST 1] Phân tích tên miền thông thường (Không cảnh báo)...")
    safe_domains = [
        {"timestamp": now, "id.orig_h": "10.38.50.4", "query": "google.com"},
        {"timestamp": now, "id.orig_h": "10.38.50.5", "query": "wikipedia.org"},
        {"timestamp": now, "id.orig_h": "10.38.50.6", "query": "vietnamnet.vn"}
    ]
    for log in safe_domains:
        ev = detector.process_log(log)
        if ev:
            print(f"-> Thất bại: Cảnh báo nhầm domain sạch: {ev}")
    print("-> Test 1: ĐẠT")

    # KỊCH BẢN 2: Tên miền chứa từ khóa nguy hiểm
    print("\n[TEST 2] Tên miền chứa từ khóa đáng ngờ (Phải cảnh báo)...")
    keyword_log = {"timestamp": now, "id.orig_h": "10.38.50.3", "query": "support-malware-update.com"}
    ev = detector.process_log(keyword_log)
    if ev and ev["alert_type"] == "DNS_SUSPICIOUS":
        print(f"-> Trả về Evidence: {ev}")
        print("-> Test 2: ĐẠT")
    else:
        print("-> Test 2: THẤT BẠI")

    # KỊCH BẢN 3: Tên miền DGA độ ngẫu nhiên cao (Entropy cao)
    print("\n[TEST 3] Tên miền ngẫu nhiên DGA (Phải cảnh báo)...")
    dga_log = {"timestamp": now, "id.orig_h": "10.38.50.3", "query": "x8f9a.malware-c2.evil.com"}
    ev = detector.process_log(dga_log)
    if ev and ev["alert_type"] == "DNS_SUSPICIOUS":
        print(f"-> Trả về Evidence: {ev}")
        print("-> Test 3: ĐẠT")
    else:
        print("-> Test 3: THẤT BẠI")

    # KỊCH BẢN 4: Truy vấn quá dài (Đóng gói Payload)
    print("\n[TEST 4] Tên miền có độ dài cực lớn (Phải cảnh báo)...")
    long_log = {
        "timestamp": now,
        "id.orig_h": "10.38.50.3",
        "query": "superlongsubdomainwithencodedpayloadsdataforc2tunneling.evil.xyz"
    }
    ev = detector.process_log(long_log)
    if ev and ev["alert_type"] == "DNS_SUSPICIOUS":
        print(f"-> Trả về Evidence: {ev}")
        print("-> Test 4: ĐẠT")
    else:
        print("-> Test 4: THẤT BẠI")
