import time
import random
from datetime import datetime

LOG_FILE = "aivpn_alert.log"

# Các dòng log kỹ thuật cấp thấp (sẽ bị Backend Filter loại bỏ)
NOISE_LOGS = [
    "[PARSER] Nhận luồng mới: 10.38.50.2:59723 -> 10.38.50.1:21 (TCP)",
    "[DISCRETIZER] Mã hóa kết nối IP 10.38.50.2 -> Ký tự: 'C'",
    "[COLD_START] IP 10.38.50.2 đang thu thập dữ liệu chuỗi: 1/20 ký tự.",
    "[PARSER] Nhận luồng mới: 10.38.50.6:443 -> 8.8.8.8:53 (UDP)"
]

# Các dòng log có giá trị thực thi (Sẽ được đẩy lên Frontend)
EVIDENCE_LOGS = [
    "[EVIDENCE] Bằng chứng từ [ScanDetector]: IP=10.38.50.2, Conf=0.70, Tấn công=High_Connection_Rate",
    "[EVIDENCE] Bằng chứng từ [DNSDetector]: IP=10.38.50.4, Conf=0.85, Tấn công=DGA_Malware",
    "[EVIDENCE] Bằng chứng từ [LSTM]: IP=10.38.50.5, Conf=0.82, Tấn công=Suspicious_Rhythm"
]

WHITELIST_LOGS = [
    "[WHITELIST] Bypass/Ignore luồng kết nối tin cậy: SRC=8.8.8.8",
    "[WHITELIST] Bypass/Ignore luồng kết nối tin cậy: SRC=1.1.1.1, Domain=cloudflare.com"
]

BLOCK_LOGS = [
    "[ALERT] Cảnh báo ĐỎ! IP 10.38.50.4 vi phạm Luật Phủ quyết Khẩn cấp!",
    "[BLOCK] FirewallBlocker (L4) -> iptables DROP IP 10.38.50.4",
    "[ALERT] Hệ thống nhận thấy IP 10.38.50.2 vi phạm Luật Đồng thuận (Tổng điểm 1.52)!",
    "[BLOCK] FirewallBlocker (L4) -> iptables DROP IP 10.38.50.2",
    "[BLOCK] FirewallBlocker (L4) -> iptables DROP IP 10.38.50.5"
]

def generate_logs():
    print(f"[*] Đang khởi tạo luồng log giả lập vào file: {LOG_FILE}...")
    print("[*] Nhấn Ctrl+C để dừng.")
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        try:
            while True:
                # Trọng số xác suất sinh log
                roll = random.randint(1, 100)
                
                if roll <= 50:
                    # 50% là rác kỹ thuật
                    line = random.choice(NOISE_LOGS)
                elif roll <= 75:
                    # 25% là Bằng chứng
                    line = random.choice(EVIDENCE_LOGS)
                elif roll <= 90:
                    # 15% là Whitelist
                    line = random.choice(WHITELIST_LOGS)
                else:
                    # 10% là Alert/Block
                    line = random.choice(BLOCK_LOGS)
                    
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_line = f"[{ts}] {line}\n"
                
                f.write(log_line)
                f.flush()
                print(log_line.strip())
                
                # Tốc độ sinh log ngẫu nhiên (nhanh chậm thất thường giống thật)
                time.sleep(random.uniform(0.1, 1.5))
        except KeyboardInterrupt:
            print("\n[*] Đã dừng giả lập log.")

if __name__ == "__main__":
    generate_logs()
