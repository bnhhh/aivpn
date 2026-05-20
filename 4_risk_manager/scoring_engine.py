#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 4: Risk Manager & Scoring
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Quản lý điểm rủi ro tập trung cho toàn bộ các IP kết nối qua VPN.
    - Hàm add_evidence: Cộng dồn trọng số (weight) từ các bộ phát hiện Lớp 3.
    - Hàm apply_decay: Suy hao điểm rủi ro theo thời gian (Time Decay) để tránh khóa nhầm IP vĩnh viễn.
    - In các cảnh báo trực quan bằng Colorama theo các mức độ: Thường (Xanh), Cảnh báo (Vàng), Block (Đỏ).
"""

import sys
import time
from datetime import datetime
from typing import Dict, Optional, Any

# Cố gắng import colorama để hiển thị UI màu sắc chất lượng cao
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Cấu hình encoding UTF-8 cho Windows để tránh lỗi Unicode tiếng Việt khi xuất ra console
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class Colors:
    CYAN = Fore.CYAN if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RED = Fore.RED if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""
    BG_RED = Back.RED if HAS_COLORAMA else ""
    WHITE = Fore.WHITE if HAS_COLORAMA else ""


class ScoringEngine:
    """
    Hệ thống tính điểm rủi ro và quản lý danh sách chặn (Blocked IPs) dựa trên hành vi.
    """
    def __init__(self, block_threshold: float = 1.0, decay_factor: float = 0.95, min_score: float = 0.05):
        self.block_threshold = block_threshold  # Ngưỡng kích hoạt lệnh chặn (mặc định 1.0)
        self.decay_factor = decay_factor        # Hệ số suy hao rủi ro (0.95 ~ giảm 5% mỗi chu kỳ)
        self.min_score = min_score              # Điểm tối thiểu, nếu thấp hơn sẽ reset về 0.0 để dọn dẹp cache
        
        # Lưu trữ điểm số rủi ro hiện tại của các IP: { ip: score }
        self.threat_scores: Dict[str, float] = {}
        
        # Lưu trạng thái đã bị chặn của IP để tránh lặp lại lệnh chặn liên tục: { ip: True/False }
        self.blocked_ips: Dict[str, bool] = {}

    def add_evidence(self, evidence: Dict[str, Any]) -> float:
        """
        Cộng dồn điểm rủi ro khi nhận được Evidence (Bằng chứng vi phạm) từ Lớp 3.
        Công thức: RiskScore(t) = RiskScore(t-1) + Evidence_Weight
        """
        ip = evidence.get("ip")
        weight = evidence.get("weight", 0.0)
        ts = evidence.get("timestamp", time.time())
        alert_type = evidence.get("alert_type", "UNKNOWN")

        if not ip:
            return 0.0

        # Khởi tạo điểm số ban đầu nếu IP xuất hiện lần đầu
        old_score = self.threat_scores.get(ip, 0.0)
        new_score = old_score + weight
        
        # Cập nhật điểm số trong bộ nhớ
        self.threat_scores[ip] = round(new_score, 3)

        # Tạo chuỗi thời gian hiển thị
        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

        # In thông tin cập nhật điểm số chuẩn đặc tả JSON aivpn.json
        # Ví dụ: [2026-05-20 11:31:10] [SCORER] Threat Score IP 10.38.50.3 cập nhật: 0.0 -> 0.4
        print(
            f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
            f"{Colors.CYAN}{Colors.BRIGHT}[SCORER]{Colors.RESET} "
            f"Threat Score IP {Colors.GREEN}{ip}{Colors.RESET} cập nhật: "
            f"{Colors.YELLOW}{old_score:.1f} -> {new_score:.1f}{Colors.RESET} ({alert_type})"
        )

        # Kiểm tra nếu vượt ngưỡng Block hành động (Score >= 1.0)
        if new_score >= self.block_threshold:
            # Chỉ in lệnh BLOCK nếu IP chưa ở trạng thái chặn trước đó
            if not self.blocked_ips.get(ip, False):
                self.blocked_ips[ip] = True
                
                # In thông báo CRITICAL yêu cầu Block chuẩn spec
                # Ví dụ: [2026-05-20 11:31:15] [SCORER] Threat Score IP 10.38.50.3 vượt ngưỡng: 1.0! [>>> YÊU CẦU BLOCK <<<]
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.RED}{Colors.BRIGHT}[SCORER]{Colors.RESET} "
                    f"{Colors.RED}Threat Score IP {Colors.BRIGHT}{ip}{Colors.RESET}{Colors.RED} vượt ngưỡng: "
                    f"{Colors.BRIGHT}{new_score:.1f}! {Colors.BG_RED}{Colors.WHITE}{Colors.BRIGHT}[>>> YÊU CẦU BLOCK <<<]{Colors.RESET}"
                )
        
        return self.threat_scores[ip]

    def apply_decay(self, current_ts: Optional[float] = None) -> None:
        """
        Thuật toán Time Decay (Suy hao theo thời gian).
        Giảm điểm rủi ro định kỳ để ân xá cho các IP đã cải tà quy chính (không có hành vi xấu mới).
        Công thức: RiskScore(new) = RiskScore(old) * Decay_Factor
        """
        if current_ts is None:
            current_ts = time.time()

        ts_str = datetime.fromtimestamp(current_ts).strftime("%Y-%m-%d %H:%M:%S")
        ips_to_delete = []

        # Áp dụng suy hao rủi ro cho từng IP
        for ip, old_score in self.threat_scores.items():
            if old_score <= 0.0:
                continue

            # Áp dụng công thức suy hao
            new_score = round(old_score * self.decay_factor, 3)

            # Nếu điểm số tụt xuống mức cực nhỏ, đưa về 0 để giải phóng bộ nhớ
            if new_score < self.min_score:
                new_score = 0.0
                ips_to_delete.append(ip)
            else:
                self.threat_scores[ip] = new_score

            # Kiểm tra nếu IP được gỡ Block (Score tụt xuống dưới ngưỡng chặn)
            if old_score >= self.block_threshold and new_score < self.block_threshold:
                if self.blocked_ips.get(ip, False):
                    self.blocked_ips[ip] = False
                    print(
                        f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                        f"{Colors.GREEN}{Colors.BRIGHT}[SCORER]{Colors.RESET} "
                        f"{Colors.GREEN}Giải phóng chặn (UNBLOCK) cho IP {ip} (Điểm giảm xuống {new_score:.2f}){Colors.RESET}"
                    )

            # In nhật ký suy hao theo thời gian chuẩn aivpn.json
            # Ví dụ: [2026-05-20 11:32:00] [SCORER] [TIME DECAY] IP 10.38.50.4 không có dấu hiệu mới. Threat Score: 0.3 -> 0.28
            print(
                f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                f"{Colors.CYAN}{Colors.BRIGHT}[SCORER]{Colors.RESET} "
                f"{Colors.DIM}[TIME DECAY]{Colors.RESET} "
                f"IP {Colors.GREEN}{ip}{Colors.RESET} không có dấu hiệu mới. Threat Score: "
                f"{Colors.YELLOW}{old_score:.2f} -> {new_score:.2f}{Colors.RESET}"
            )

        # Thực hiện dọn dẹp các IP có điểm rủi ro bằng 0 ra khỏi RAM
        for ip in ips_to_delete:
            del self.threat_scores[ip]
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]

    def get_score(self, ip: str) -> float:
        """Lấy điểm số hiện tại của một IP."""
        return self.threat_scores.get(ip, 0.0)

    def is_blocked(self, ip: str) -> bool:
        """Kiểm tra xem một IP có đang nằm trong danh sách chặn hay không."""
        return self.blocked_ips.get(ip, False)


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.CYAN}{Colors.BRIGHT}Kiểm thử độc lập: ScoringEngine (Layer 4){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo Scorer
    scorer = ScoringEngine(block_threshold=1.0, decay_factor=0.95, min_score=0.05)
    now = time.time()

    # KỊCH BẢN 1: Tích lũy bằng chứng PORT_SCAN
    print("\n[TEST 1] Thêm bằng chứng PORT_SCAN (Trọng số 0.4)...")
    evidence_1 = {"ip": "10.38.50.3", "alert_type": "PORT_SCAN", "weight": 0.4, "timestamp": now}
    score = scorer.add_evidence(evidence_1)
    print(f"-> Điểm hiện tại: {score}")
    if score == 0.4:
        print("-> Test 1: ĐẠT")
    else:
        print("-> Test 1: THẤT BẠI")

    # KỊCH BẢN 2: Tích lũy thêm bằng chứng DNS_SUSPICIOUS và kích hoạt BLOCK IP
    print("\n[TEST 2] Thêm tiếp bằng chứng DNS_SUSPICIOUS (Trọng số 0.6) để kích hoạt BLOCK...")
    evidence_2 = {"ip": "10.38.50.3", "alert_type": "DNS_SUSPICIOUS", "weight": 0.6, "timestamp": now + 5.0}
    score = scorer.add_evidence(evidence_2)
    print(f"-> Điểm hiện tại: {score}")
    is_blocked = scorer.is_blocked("10.38.50.3")
    print(f"-> IP 10.38.50.3 bị chặn? {is_blocked}")
    if score == 1.0 and is_blocked:
        print("-> Test 2: ĐẠT")
    else:
        print("-> Test 2: THẤT BẠI")

    # KỊCH BẢN 3: Áp dụng thuật toán Time Decay (Suy hao theo thời gian)
    print("\n[TEST 3] Áp dụng Time Decay (Suy hao 5%)...")
    # Giả lập IP 10.38.50.4 có điểm 0.3 trước khi suy hao
    scorer.threat_scores["10.38.50.4"] = 0.30
    print("--- Chạy Decay lần 1 ---")
    scorer.apply_decay(current_ts=now + 60.0)
    
    # 10.38.50.3: 1.0 * 0.95 = 0.95 (Sẽ tự động UNBLOCK vì xuống dưới 1.0)
    # 10.38.50.4: 0.3 * 0.95 = 0.285 (Hiển thị làm tròn thành 0.28)
    
    score_3 = scorer.get_score("10.38.50.3")
    score_4 = scorer.get_score("10.38.50.4")
    blocked_3 = scorer.is_blocked("10.38.50.3")
    
    print(f"-> IP 10.38.50.3 Score: {score_3}, Bị chặn? {blocked_3}")
    print(f"-> IP 10.38.50.4 Score: {score_4}")
    
    if score_3 == 0.95 and not blocked_3 and score_4 == 0.285:
        print("-> Test 3: ĐẠT")
    else:
        print("-> Test 3: THẤT BẠI")
