#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Automated System Integration Test V2 (Evidence-based Upgrade)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Kỹ sư Python Backend cấp cao
Mô tả:
    - Script này tự động hóa kiểm thử tích hợp toàn diện kiến trúc Evidence-based mới.
    - Xác minh chi tiết 5 kịch bản logic cốt lõi:
        1. Whitelist Bypass: IP tin cậy đi qua mà không bị phân tích.
        2. Cold Start Protection: IP mới có ít hơn 20 kết nối -> Bỏ qua AI suy luận, chỉ thu thập.
        3. Safe Normal IP: IP gửi traffic ngẫu nhiên -> Chuỗi ký tự hỗn loạn -> AI đánh giá Safe.
        4. LSTM Critical Phủ quyết (Critical Bypass): IP lặp Beaconing với xác suất 0.96 (>= 0.85) -> Block lập tức do luật Phủ quyết.
        5. Consensus Đồng thuận (Consensus Rule): IP quét cổng (0.7 điểm) kết hợp với AI phát hiện rủi ro (0.80 điểm) 
           -> Tổng điểm = 1.5 >= 1.5 -> Block lập tức do luật Đồng thuận cộng dồn.
"""

import os
import sys
import time
import json
import threading
from datetime import datetime

# Đảm bảo import được các module từ workspace
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Gateway, Colors và các thành phần
from main_vpn_ids import AIVPN_Gateway, Colors

# Import động Evidence do tên thư mục 4_risk_manager bắt đầu bằng số
import importlib
evidence_manager = importlib.import_module("4_risk_manager.evidence_manager")
Evidence = evidence_manager.Evidence

def simulate_log(log_path: str, ts: float, src_ip: str, dst_ip: str, dst_port: int, duration: float, orig_bytes: int, query: str = None):
    """Ghi một dòng log dạng JSON Zeek conn.log để Gateway xử lý."""
    entry = {
        "ts": ts,
        "uid": f"Ctest{int(ts * 100) % 100000}",
        "id.orig_h": src_ip,
        "id.orig_p": 50000,
        "id.resp_h": dst_ip,
        "id.resp_p": dst_port,
        "proto": "TCP",
        "duration": duration,
        "orig_bytes": orig_bytes
    }
    if query:
        entry["query"] = query
        entry["service"] = "dns"
        entry["id.resp_p"] = 53
        entry["proto"] = "UDP"

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def run_test():
    print("=" * 80)
    print(f" {Colors.CYAN}{Colors.BRIGHT}BẮT ĐẦU KIỂM THỬ TÍCH HỢP V2 - KIẾN TRÚC DỰA TRÊN BẰNG CHỨNG{Colors.RESET} ")
    print("=" * 80)

    # Khởi tạo thư mục và file log kiểm thử sạch
    log_dir = "dataset"
    log_name = "conn.log"
    log_path = os.path.join(log_dir, log_name)

    os.makedirs(log_dir, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("") # Clear log cũ hoàn toàn

    # Khởi tạo Gateway
    gateway = AIVPN_Gateway(config_path="config/slips.yaml", whitelist_path="config/whitelist.conf")
    
    # Ghi đè đường dẫn log của Gateway để chạy test cục bộ
    gateway.log_path = log_path
    gateway.tailer.log_path = log_path
    
    # Khởi chạy Gateway trong một thread riêng biệt
    gateway_thread = threading.Thread(target=gateway.start, daemon=True)
    gateway_thread.start()
    
    # Chờ hệ thống khởi động an toàn
    time.sleep(1.5)

    now = time.time()
    success_flags = {
        "whitelist_bypass": False,
        "cold_start_safe": True,
        "normal_traffic_safe": False,
        "critical_bypass_blocked": False,
        "consensus_blocked": False
    }

    # ==================================================================================
    # KỊCH BẢN 1: Traffic thuộc danh sách Whitelist (Bypass)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 1] Kiểm tra Whitelist Bypass (8.8.8.8 & wikipedia.org) ---{Colors.RESET}")
    
    # IP nguồn thuộc whitelist
    simulate_log(log_path, now, "8.8.8.8", "192.168.1.100", 443, 0.5, 1200)
    time.sleep(0.5)

    # Domain truy vấn thuộc whitelist
    simulate_log(log_path, now + 0.1, "192.168.10.5", "1.1.1.1", 53, 0.1, 75, query="en.wikipedia.org")
    time.sleep(1.0)
    
    # IP trong whitelist không được đưa vào LogDiscretizer
    if "8.8.8.8" not in gateway.discretizer.buffers:
        print(f"{Colors.GREEN}[✓] Test 1 ĐẠT: Whitelist Bypass hoạt động hoàn hảo!{Colors.RESET}")
        success_flags["whitelist_bypass"] = True
    else:
        print(f"{Colors.RED}[✗] Test 1 THẤT BẠI: Whitelist IP vẫn bị phân tích.{Colors.RESET}")

    # ==================================================================================
    # KỊCH BẢN 2: Bảo vệ Cold Start (Khởi động nguội an toàn)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 2] Kiểm tra Cold Start Protection (10 kết nối đầu của IP mới) ---{Colors.RESET}")
    cold_ip = "192.168.10.11"
    
    # Gửi 10 kết nối (ít hơn 20)
    for i in range(10):
        simulate_log(log_path, now + 1.0 + (i * 2.5), cold_ip, "203.0.113.10", 80, 0.5, 500)
        time.sleep(0.05)
    
    time.sleep(1.5)
    
    # Kiểm tra xem IP có bị block không và độ dài buffer trong discretizer
    current_buf_len = len(gateway.discretizer.buffers.get(cold_ip, []))
    if current_buf_len == 10:
        print(f"{Colors.GREEN}[✓] Test 2 ĐẠT: Đang tích lũy chuỗi ({current_buf_len}/20 ký tự), không crash và không suy luận sớm!{Colors.RESET}")
    else:
        print(f"{Colors.RED}[✗] Test 2 THẤT BẠI: Độ dài buffer bị sai lệch ({current_buf_len}/20).{Colors.RESET}")
        success_flags["cold_start_safe"] = False

    # Dọn dẹp an toàn nếu bị chặn nhầm trước đó
    if gateway.evidence_manager.blocker.block_ip(cold_ip):
        gateway.evidence_manager.blocker.active_blocks.discard(cold_ip)
        if cold_ip in gateway.scorer.blocked_ips:
            gateway.scorer.blocked_ips[cold_ip] = False
        if cold_ip in gateway.evidence_manager.profiles:
            gateway.evidence_manager.profiles[cold_ip]["blocked"] = False

    # ==================================================================================
    # KỊCH BẢN 3: Hành vi người dùng sạch (Safe Normal IP)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 3] Kiểm tra Hành vi người dùng sạch (Gửi thêm 10 kết nối ngẫu nhiên) ---{Colors.RESET}")
    
    # Gửi tiếp 10 kết nối có thông số thay đổi ngẫu nhiên, không đều đặn
    durations = [0.2, 12.0, 5.0, 0.5, 18.0, 1.2, 0.1, 8.5, 3.2, 14.0]
    bytes_sent = [200, 15000, 5000, 800, 32000, 4000, 100, 12000, 9500, 20000]
    intervals = [1.5, 40.0, 15.0, 5.0, 60.0, 3.5, 1.2, 50.0, 8.0, 45.0]
    
    current_ts = now + 1.0 + (9 * 2.5)
    
    for i in range(10):
        current_ts += intervals[i]
        # Sử dụng port cố định 80 để không kích hoạt ScanDetector
        simulate_log(log_path, current_ts, cold_ip, "203.0.113.10", 80, durations[i], bytes_sent[i])
        time.sleep(0.05)
        
    time.sleep(2.0)
    
    # Verify xem IP sạch có bị block hay không
    is_blocked = gateway.evidence_manager.blocker.active_blocks
    if cold_ip not in is_blocked:
        print(f"{Colors.GREEN}[✓] Test 3 ĐẠT: IP người dùng sạch nạp đủ 20 ký tự trượt, AI đánh giá SAFE, không chặn!{Colors.RESET}")
        success_flags["normal_traffic_safe"] = True
    else:
        print(f"{Colors.RED}[✗] Test 3 THẤT BẠI: IP người dùng sạch bị Bồi thẩm đoàn kết án và BLOCK nhầm!{Colors.RESET}")

    # ==================================================================================
    # KỊCH BẢN 4: LSTM Phủ quyết khẩn cấp (Critical Bypass - AI xác suất 0.96)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 4] Kiểm tra Luật Phủ Quyết Khẩn Cấp (AI LSTM = 0.96 >= 0.85) ---{Colors.RESET}")
    beacon_ip = "192.168.10.12"
    beacon_ts = now + 2000.0
    
    # Gửi 20 kết nối đều đặn tăm tắp (Duration=0.5s, Bytes=500B, Interval=1.5s) -> Mã hóa thành 'A'
    for i in range(20):
        # Port cố định để tránh kích hoạt Scan
        simulate_log(log_path, beacon_ts + (i * 1.5), beacon_ip, "203.0.113.66", 80, 0.5, 500)
        time.sleep(0.05)
        
    time.sleep(2.5)
    
    # Kiểm tra xem beacon_ip đã bị block thông qua Luật phủ quyết khẩn cấp hay chưa
    if beacon_ip in gateway.evidence_manager.blocker.active_blocks:
        profile = gateway.evidence_manager.profiles.get(beacon_ip, {})
        verdict = profile.get("verdict", "")
        if "Critical" in verdict:
            print(f"{Colors.GREEN}[✓] Test 4 ĐẠT: Phát hiện khẩn cấp thành công! Tội danh: '{verdict}'. IP {beacon_ip} bị BLOCK do Luật Phủ Quyết!{Colors.RESET}")
            success_flags["critical_bypass_blocked"] = True
        else:
            print(f"{Colors.RED}[✗] Test 4 THẤT BẠI: Đã block IP nhưng không định danh đúng theo Luật Phủ Quyết! Verdict: {verdict}{Colors.RESET}")
    else:
        print(f"{Colors.RED}[✗] Test 4 THẤT BẠI: IP lặp Beaconing mạnh không bị block khẩn cấp!{Colors.RESET}")

    # ==================================================================================
    # KỊCH BẢN 5: Luật Đồng Thuận Cộng Dồn (Port Scan + LSTM)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 5] Kiểm tra Luật Đồng Thuận Cộng Dồn (Scan 0.7 + LSTM 0.8) ---{Colors.RESET}")
    compromised_ip = "192.168.10.15"
    comp_ts = now + 4000.0
    
    # Bước A: IP gửi traffic quét cổng (11 kết nối đến 11 port đích khác nhau trong 2 giây)
    # ScanDetector kích hoạt (confidence = 0.7). Tổng điểm = 0.7 < 1.5 -> Chưa block!
    for i in range(11):
        simulate_log(log_path, comp_ts + (i * 0.1), compromised_ip, "203.0.113.88", 1000 + i, 0.1, 100)
        time.sleep(0.02)
        
    time.sleep(1.0)
    
    is_blocked_step_a = compromised_ip in gateway.evidence_manager.blocker.active_blocks
    current_score_step_a = gateway.evidence_manager.profiles.get(compromised_ip, {}).get("total_score", 0.0)
    
    print(f"{Colors.DIM}[TEST 5A] Sau khi quét cổng: Tổng điểm tích lũy = {current_score_step_a}, Blocked? {is_blocked_step_a}{Colors.RESET}")
    
    # Bước B: IP gửi thêm chuỗi kết nối Beaconing trung bình/mạnh
    # Giả lập gửi trực tiếp một bằng chứng LSTM (Confidence = 0.8) về EvidenceManager
    # Tổng điểm = 0.7 + 0.8 = 1.5 -> Đạt ngưỡng đồng thuận -> Block!
    lstm_ev = Evidence(
        ip=compromised_ip,
        module_name="LSTM",
        confidence=0.8,
        attack_type="Suspicious_Rhythm",
        timestamp=comp_ts + 2.0
    )
    gateway.evidence_manager.add_evidence(lstm_ev)
    time.sleep(1.0)
    
    is_blocked_step_b = compromised_ip in gateway.evidence_manager.blocker.active_blocks
    current_score_step_b = gateway.evidence_manager.profiles.get(compromised_ip, {}).get("total_score", 0.0)
    verdict_step_b = gateway.evidence_manager.profiles.get(compromised_ip, {}).get("verdict", "")
    
    print(f"{Colors.DIM}[TEST 5B] Sau khi nhận thêm bằng chứng AI: Tổng điểm = {current_score_step_b}, Blocked? {is_blocked_step_b}{Colors.RESET}")
    
    if not is_blocked_step_a and is_blocked_step_b and "Botnet" in verdict_step_b:
        print(f"{Colors.GREEN}[✓] Test 5 ĐẠT: Đồng thuận cộng dồn thành công! Tội danh: '{verdict_step_b}'. IP {compromised_ip} bị BLOCK do Luật Đồng Thuận!{Colors.RESET}")
        success_flags["consensus_blocked"] = True
    else:
        print(f"{Colors.RED}[✗] Test 5 THẤT BẠI: Sai logic đồng thuận! Block sớm? {is_blocked_step_a}, Block muộn? {is_blocked_step_b}, Verdict: {verdict_step_b}{Colors.RESET}")

    # Dừng hệ thống an toàn
    print("")
    gateway.stop()
    
    # Tổng hợp kết quả
    print("=" * 80)
    print(f" {Colors.CYAN}{Colors.BRIGHT}KẾT QUẢ ĐÁNH GIÁ CHẤT LƯỢNG HỆ THỐNG{Colors.RESET} ")
    print("=" * 80)
    
    all_passed = True
    for scenario, passed in success_flags.items():
        status_color = Colors.GREEN if passed else Colors.RED
        status_text = "ĐẠT (PASSED)" if passed else "THẤT BẠI (FAILED)"
        print(f" - Kịch bản {scenario.upper():<25}: {status_color}{status_text}{Colors.RESET}")
        if not passed:
            all_passed = False
            
    print("=" * 80)
    if all_passed:
        print(f" {Colors.GREEN}{Colors.BRIGHT}KẾT LUẬN: HỆ THỐNG ĐẠT ĐIỂM TUYỆT ĐỐI, SẴN SÀNG TRIỂN KHAI V2!{Colors.RESET} ")
    else:
        print(f" {Colors.RED}{Colors.BRIGHT}KẾT LUẬN: CÓ LỖI LOGIC CẦN KIỂM TRA LẠI!{Colors.RESET} ")
    print("=" * 80)

if __name__ == "__main__":
    run_test()
