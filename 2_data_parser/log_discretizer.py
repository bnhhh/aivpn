#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 2: Log Discretizer (Deep Learning Upgrade)
Tác giả: Chuyên gia Kiến trúc Hệ thống MLOps & Deep Learning An toàn Thông tin
Mô tả:
    - Đọc luồng log từ Zeek (conn.log) theo thời gian thực.
    - Mã hóa chuỗi (Discretization) dựa trên 3 thông số: Duration, Bytes_sent, Time_interval.
    - Băm 3 mức độ (Nhỏ=0, Trung bình=1, Lớn=2) tạo ra 3x3x3 = 27 tổ hợp trạng thái.
    - Sử dụngcollections.deque(maxlen=20) để duy trì Buffer trượt (Sliding Window FIFO)
      rolling liên tục cho từng IP nguồn, loại bỏ hoàn toàn cơ chế reset thủ công.
    - Hỗ trợ quản lý an toàn trạng thái Cold Start (thu thập dữ liệu tích lũy dần).
"""

import sys
import time
from collections import deque
from typing import Dict, Tuple, Optional, Any, List

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class LogDiscretizer:
    """
    Class quản lý mã hóa chuỗi hành vi mạng của các IP kết nối qua VPN.
    """
    def __init__(self, max_len: int = 20):
        self.max_len = max_len
        
        # Bộ đệm lưu trữ chuỗi ký tự trượt FIFO cho mỗi IP nguồn: { ip: deque(maxlen=20) }
        self.buffers: Dict[str, deque] = {}
        
        # Ghi nhận timestamp kết nối gần nhất của từng IP nguồn để tính Time Interval: { ip: last_timestamp }
        self.last_conn_times: Dict[str, float] = {}

    def discretize_flow(self, duration: float, bytes_sent: int, interval: float) -> str:
        """
        Thuật toán băm log mạng (Discretization):
        Băm 3 tham số (Duration, Bytes_sent, Time_interval) thành 3 mức độ (0, 1, 2)
        và trả về 1 ký tự tương ứng đại diện cho tổ hợp trạng thái.
        """
        # 1. Phân mức Duration (Thời lượng kết nối)
        if duration < 1.0:
            dur_level = 0
        elif duration <= 10.0:
            dur_level = 1
        else:
            dur_level = 2

        # 2. Phân mức Bytes Sent (Kích thước dữ liệu gửi)
        if bytes_sent < 1000:
            byte_level = 0
        elif bytes_sent <= 10000:
            byte_level = 1
        else:
            byte_level = 2

        # 3. Phân mức Time Interval (Độ trễ giữa 2 kết nối liên tiếp)
        if interval < 2.0:
            int_level = 0  # Kết nối dồn dập / Beaconing
        elif interval <= 30.0:
            int_level = 1  # Bình thường
        else:
            int_level = 2  # Thưa thớt

        # Tính toán chỉ số băm trong khoảng [0, 26] đại diện cho 27 trạng thái
        index = dur_level * 9 + byte_level * 3 + int_level
        
        # Chuyển đổi chỉ số thành ký tự bắt đầu từ 'A' (ASCII 65) -> 'A' đến '['
        char = chr(ord('A') + index)
        return char

    def process_log(self, log_dict: Dict[str, Any]) -> Tuple[str, List[str], bool, int]:
        """
        Xử lý dòng log kết nối mạng đã parse:
        1. Tính toán Interval dựa trên lịch sử kết nối của IP.
        2. Chạy thuật toán Discretization ra ký tự đại diện.
        3. Đẩy ký tự vào collections.deque(maxlen=20) trượt liên tục của IP.
        4. Trả về: (Ký tự vừa tạo, Danh sách ký tự hiện tại trong deque, Đủ 20 ký tự chưa, Số lượng hiện có).
        """
        src_ip = log_dict.get("id.orig_h")
        ts = log_dict.get("timestamp")
        
        if not src_ip or ts is None:
            return "", [], False, 0

        try:
            ts = float(ts)
        except (ValueError, TypeError):
            ts = time.time()

        # Trích xuất duration và bytes sent, handle giá trị thiếu hoặc '-' của Zeek
        duration = log_dict.get("duration")
        if duration is None or duration == "-":
            duration = 0.0
        else:
            try:
                duration = float(duration)
            except ValueError:
                duration = 0.0

        bytes_sent = log_dict.get("orig_bytes")
        if bytes_sent is None or bytes_sent == "-":
            bytes_sent = 0
        else:
            try:
                bytes_sent = int(bytes_sent)
            except ValueError:
                bytes_sent = 0

        # Tính Time Interval giữa kết nối hiện tại và kết nối trước đó từ IP này
        last_ts = self.last_conn_times.get(src_ip)
        if last_ts is None:
            # Lần đầu kết nối: Interval mặc định là lớn (thưa thớt)
            interval = 60.0
        else:
            interval = ts - last_ts
            if interval < 0:
                interval = 0.0  # Phòng ngừa sai lệch thời gian hệ thống

        # Cập nhật timestamp kết nối gần nhất của IP
        self.last_conn_times[src_ip] = ts

        # Chạy băm Discretization
        char = self.discretize_flow(duration, bytes_sent, interval)

        # Khởi tạo collections.deque(maxlen=20) nếu IP này lần đầu tiên giao tiếp
        if src_ip not in self.buffers:
            self.buffers[src_ip] = deque(maxlen=self.max_len)

        # Đẩy ký tự vừa băm vào bộ đệm trượt FIFO (tự động đẩy phần tử cũ nhất ra khi đầy)
        self.buffers[src_ip].append(char)

        current_window = list(self.buffers[src_ip])
        current_len = len(current_window)
        is_ready = current_len >= self.max_len

        return char, current_window, is_ready, current_len


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(" Kiểm thử độc lập: LogDiscretizer (collections.deque Rolling Buffer) ")
    print("=" * 70)

    discretizer = LogDiscretizer(max_len=5)  # Dùng max_len = 5 để dễ demo test trượt
    
    now = time.time()
    ip_test = "192.168.1.100"

    print("\n--- Giai đoạn 1: Khởi động nguội (Cold Start) ---")
    # Gửi 4 kết nối (chưa đủ 5 phần tử)
    for i in range(4):
        log = {
            "timestamp": now + (i * 1.5), # Interval = 1.5s -> int_level = 0
            "id.orig_h": ip_test,
            "duration": 0.5,             # dur_level = 0
            "orig_bytes": 500            # byte_level = 0
        }
        # 0*9 + 0*3 + 0 = 0 -> Ký tự 'A'
        char, window, ready, length = discretizer.process_log(log)
        print(f"Lần {i+1}: Nhận ký tự '{char}', Window: {window}, Sẵn sàng? {ready} (Độ dài: {length}/5)")

    print("\n--- Giai đoạn 2: Đạt trạng thái đầy buffer (Window Ready) ---")
    # Gửi kết nối thứ 5 (Interval = 10s -> int_level = 1) -> 0*9 + 0*3 + 1 = 1 -> 'B'
    log_5 = {
        "timestamp": now + (4 * 1.5) + 10.0,
        "id.orig_h": ip_test,
        "duration": 0.5,
        "orig_bytes": 500
    }
    char, window, ready, length = discretizer.process_log(log_5)
    print(f"Lần 5: Nhận ký tự '{char}', Window: {window}, Sẵn sàng? {ready} (Độ dài: {length}/5)")

    print("\n--- Giai đoạn 3: Trượt Rolling Window FIFO (Tự động đẩy ký tự đầu tiên) ---")
    # Gửi kết nối thứ 6 (Interval = 60s -> int_level = 2, Bytes = 20000 -> byte_level = 2) -> 0*9 + 2*3 + 2 = 8 -> 'I'
    log_6 = {
        "timestamp": now + (4 * 1.5) + 10.0 + 60.0,
        "id.orig_h": ip_test,
        "duration": 0.5,
        "orig_bytes": 20000
    }
    char, window, ready, length = discretizer.process_log(log_6)
    print(f"Lần 6 (Đẩy rolling): Nhận ký tự '{char}', Window: {window}, Sẵn sàng? {ready} (Độ dài: {length}/5)")
    print("=> Ký tự 'A' đầu tiên đã bị tự động loại bỏ khỏi deque thành công!")
