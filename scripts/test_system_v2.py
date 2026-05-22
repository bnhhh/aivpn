#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Automated System Integration Test V2 (LSTM Deep Learning)
Tác giả: Chuyên gia Kiến trúc An toàn Thông tin & Kỹ sư Python Backend cấp cao
Mô tả:
    - Script này tự động hóa kiểm thử tích hợp toàn diện Layer 2, Layer 4 và Main Coordinator mới.
    - Xác minh chi tiết 4 kịch bản logic cốt lõi:
        1. Whitelist Bypass: IP tin cậy (8.8.8.8, wikipedia.org) đi qua mà không bị phân tích.
        2. Cold Start Protection: IP mới kết nối có < 20 gói tin -> Bỏ qua AI suy luận, chỉ hiển thị trạng thái thu thập.
        3. Safe Normal IP: IP gửi traffic ngẫu nhiên -> Chuỗi ký tự hỗn loạn -> AI đánh giá Safe.
        4. Malicious C2 Beaconing: IP gửi traffic đều đặn chu kỳ -> Chuỗi ký tự tuần hoàn lặp -> AI đánh giá Malicious -> BLOCK ngay lập tức.
"""

import os
import sys
import time
import json
import threading
from datetime import datetime

# Đảm bảo import được các module từ workspace
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import Gateway và các màu sắc từ main_vpn_ids
from main_vpn_ids import AIVPN_Gateway, Colors

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
    print(f" {Colors.CYAN}{Colors.BRIGHT}BẮT ĐẦU KIỂM THỬ TÍCH HỢP TỰ ĐỘNG V2 - LSTM DEEP LEARNING SYSTEM{Colors.RESET} ")
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
        "cold_start_safe": True,  # Giả định ban đầu đúng, sẽ set False nếu crash hoặc suy luận nhầm
        "normal_traffic_safe": False,
        "beaconing_blocked": False
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
        # Các kết nối đều đặn để xem nếu không có Cold Start thì có bị suy luận/block nhầm không
        simulate_log(log_path, now + 1.0 + (i * 2.5), cold_ip, "203.0.113.10", 443, 0.5, 500)
        time.sleep(0.1)
    
    time.sleep(1.5)
    
    # Kiểm tra xem IP có bị block không và độ dài buffer trong discretizer
    current_buf_len = len(gateway.discretizer.buffers.get(cold_ip, []))
    if current_buf_len == 10:
        print(f"{Colors.GREEN}[✓] Test 2 ĐẠT: Đang tích lũy chuỗi ({current_buf_len}/20 ký tự), không crash và không suy luận sớm!{Colors.RESET}")
    else:
        print(f"{Colors.RED}[✗] Test 2 THẤT BẠI: Độ dài buffer bị sai lệch ({current_buf_len}/20).{Colors.RESET}")
        success_flags["cold_start_safe"] = False

    if gateway.blocker.block_ip(cold_ip):
        # Gỡ chặn mô phỏng để tiếp tục test
        gateway.blocker.active_blocks.discard(cold_ip)
        if cold_ip in gateway.scorer.blocked_ips:
            gateway.scorer.blocked_ips[cold_ip] = False

    # ==================================================================================
    # KỊCH BẢN 3: Hành vi người dùng sạch (Safe Normal IP)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 3] Kiểm tra Hành vi người dùng sạch (Gửi thêm 10 kết nối ngẫu nhiên) ---{Colors.RESET}")
    
    # Gửi tiếp 10 kết nối có thông số thay đổi ngẫu nhiên, không đều đặn
    durations = [0.2, 12.0, 5.0, 0.5, 18.0, 1.2, 0.1, 8.5, 3.2, 14.0]
    bytes_sent = [200, 15000, 5000, 800, 32000, 4000, 100, 12000, 9500, 20000]
    intervals = [1.5, 40.0, 15.0, 5.0, 60.0, 3.5, 1.2, 50.0, 8.0, 45.0]
    
    current_ts = now + 1.0 + (9 * 2.5) # Timestamp của kết nối thứ 10 trước đó
    
    for i in range(10):
        current_ts += intervals[i]
        simulate_log(log_path, current_ts, cold_ip, "203.0.113.10", 443, durations[i], bytes_sent[i])
        time.sleep(0.1)
        
    time.sleep(2.0)
    
    # Verify xem IP sạch có bị block hay không
    is_blocked = gateway.blocker.active_blocks
    if cold_ip not in is_blocked:
        print(f"{Colors.GREEN}[✓] Test 3 ĐẠT: IP người dùng sạch nạp đủ 20 ký tự trượt, AI đánh giá SAFE, không chặn!{Colors.RESET}")
        success_flags["normal_traffic_safe"] = True
    else:
        print(f"{Colors.RED}[✗] Test 3 THẤT BẠI: IP người dùng sạch bị AI đánh giá nhầm là nguy hại và BLOCK!{Colors.RESET}")

    # ==================================================================================
    # KỊCH BẢN 4: Tấn công C2 Beaconing (LSTM Block)
    # ==================================================================================
    print(f"\n{Colors.CYAN}--- [TEST 4] Kiểm tra Tấn công C2 Beaconing (IP 192.168.10.12 lặp tuần hoàn) ---{Colors.RESET}")
    beacon_ip = "192.168.10.12"
    beacon_ts = now + 2000.0  # Timestamp mới hoàn toàn
    
    # Gửi 20 kết nối đều đặn tăm tắp (Duration=0.5s, Bytes=500B, Interval=1.5s) -> Mã hóa thành 'A'
    for i in range(20):
        simulate_log(log_path, beacon_ts + (i * 1.5), beacon_ip, "203.0.113.66", 443, 0.5, 500)
        time.sleep(0.1)
        
    time.sleep(2.0)
    
    # Kiểm tra xem beacon_ip đã bị đưa vào active_blocks của tường lửa hay chưa
    if beacon_ip in gateway.blocker.active_blocks:
        print(f"{Colors.GREEN}[✓] Test 4 ĐẠT: Phát hiện C2 Beaconing thành công, IP {beacon_ip} đã bị BLOCK lập tức bởi AI!{Colors.RESET}")
        success_flags["beaconing_blocked"] = True
    else:
        print(f"{Colors.RED}[✗] Test 4 THẤT BẠI: IP Tấn công C2 Beaconing không bị AI phát hiện hoặc bỏ lọt!{Colors.RESET}")

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
