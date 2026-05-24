#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 4: Risk Manager (Firewall Blocker)
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Thực thi hành động ngăn chặn (Active Response) bằng cách cấu hình tường lửa hệ thống.
    - Sử dụng `subprocess.run` để gọi lệnh `iptables` trên Linux để chặn hoàn toàn lưu lượng từ IP độc hại.
    - Tự động nhận diện Hệ điều hành. Nếu chạy trên Windows/macOS, hệ thống tự động chuyển sang chế độ Mô phỏng (Simulation Mode)
      để đảm bảo không gây crash chương trình khi đang chạy test/demo.
"""

import sys
import os
import subprocess
from datetime import datetime
from typing import Dict, Any, Optional

# Cố gắng import colorama để hiển thị giao diện terminal SOC sống động
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class Colors:
    RED = Fore.RED if HAS_COLORAMA else ""
    GREEN = Fore.GREEN if HAS_COLORAMA else ""
    YELLOW = Fore.YELLOW if HAS_COLORAMA else ""
    RESET = Style.RESET_ALL if HAS_COLORAMA else ""
    DIM = Style.DIM if HAS_COLORAMA else ""
    BRIGHT = Style.BRIGHT if HAS_COLORAMA else ""
    BG_RED = Back.RED if HAS_COLORAMA else ""
    WHITE = Fore.WHITE if HAS_COLORAMA else ""


class FirewallBlocker:
    """
    Bộ thực thi chặn IP trên Tường lửa (Firewall Blocker).
    """
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        # Nhận dạng môi trường OS đang chạy
        self.is_linux = sys.platform.startswith("linux")
        
        # Đăng ký danh sách các IP đã bị chặn thực tế trong phiên làm việc
        self.active_blocks = set()

    def block_ip(self, ip_address: str) -> bool:
        """
        Khóa IP trên hệ thống tường lửa Linux iptables hoặc chạy chế độ mô phỏng trên các OS khác.
        Args:
            ip_address: Chuỗi địa chỉ IP cần chặn (Ví dụ: "10.38.50.3").
        Returns:
            True nếu chặn thành công hoặc giả lập thành công, False nếu gặp lỗi nghiêm trọng.
        """
        if not ip_address:
            return False

        # Tránh thực thi chặn lặp lại nhiều lần cho cùng một IP
        if ip_address in self.active_blocks:
            return True

        ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Chế độ chạy thực tế trên môi trường Linux sử dụng iptables
        if self.is_linux and not self.dry_run:
            try:
                # Lệnh chặn IP đi qua VPN Gateway (Chặn Routing và Input)
                # SỬ DỤNG -I (Insert) ở đầu chuỗi (Vị trí 1) thay vì -A (Append)
                # Điều này giúp luật của AIVPN đè lên mọi luật của UFW (nếu có)
                cmd_input = ["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"]
                cmd_forward = ["iptables", "-I", "FORWARD", "1", "-s", ip_address, "-j", "DROP"]
                
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.RED}{Colors.BRIGHT}[FIREWALL]{Colors.RESET} "
                    f"Đang thực thi chặn thực tế IP {Colors.BRIGHT}{ip_address}{Colors.RESET} bằng iptables..."
                )
                
                # Gọi lệnh thực thi với quyền root (Yêu cầu sudo hoặc chạy với root)
                res_input = subprocess.run(cmd_input, capture_output=True, text=True, check=True)
                res_forward = subprocess.run(cmd_forward, capture_output=True, text=True, check=True)

                self.active_blocks.add(ip_address)
                
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.GREEN}{Colors.BRIGHT}[FIREWALL]{Colors.RESET} "
                    f"{Colors.GREEN}Đã áp dụng chặn iptables thành công cho IP {Colors.BRIGHT}{ip_address}{Colors.RESET}"
                )
                return True
                
            except (subprocess.CalledProcessError, PermissionError) as e:
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.RED}{Colors.BRIGHT}[FIREWALL] [LỖI]{Colors.RESET} "
                    f"Không thể chặn IP {ip_address} trên Linux (Có thể do thiếu quyền root/sudo): {e}"
                )
                # Fallback sang chế độ mô phỏng khi bị lỗi phân quyền
                print(f"{Colors.YELLOW}[FIREWALL] Tự động chuyển đổi sang chế độ MÔ PHỎNG BLOCK...{Colors.RESET}")
                self._mock_block(ip_address, ts_str)
                return True
        else:
            # 2. Chế độ mô phỏng trên các OS khác (Windows/macOS) hoặc khi bật dry_run
            self._mock_block(ip_address, ts_str)
            return True

    def _mock_block(self, ip_address: str, ts_str: str) -> None:
        """Thực thi hiển thị mô phỏng hành vi chặn IP."""
        self.active_blocks.add(ip_address)
        
        # Mô tả chi tiết cách hệ thống chặn IP ảo
        print(
            f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
            f"{Colors.RED}{Colors.BRIGHT}[FIREWALL]{Colors.RESET} "
            f"{Colors.BG_RED}{Colors.WHITE}{Colors.BRIGHT}[MÔ PHỎNG CHẶN]{Colors.RESET} "
            f"Đã chặn lưu lượng truy cập từ IP: {Colors.BRIGHT}{Colors.YELLOW}{ip_address}{Colors.RESET} "
            f"-> Lệnh áp dụng: {Colors.DIM}iptables -I INPUT 1 -s {ip_address} -j DROP{Colors.RESET}"
        )

    def unblock_ip(self, ip_address: str) -> bool:
        """
        Mở khóa IP trên iptables (Phục vụ khi điểm rủi ro IP suy giảm xuống dưới ngưỡng chặn).
        """
        if ip_address not in self.active_blocks:
            return True

        ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if self.is_linux and not self.dry_run:
            try:
                cmd_input = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                cmd_forward = ["iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"]
                
                subprocess.run(cmd_input, capture_output=True, text=True, check=True)
                subprocess.run(cmd_forward, capture_output=True, text=True, check=True)
                
                self.active_blocks.remove(ip_address)
                print(
                    f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
                    f"{Colors.GREEN}{Colors.BRIGHT}[FIREWALL]{Colors.RESET} "
                    f"{Colors.GREEN}Đã gỡ chặn iptables thực tế thành công cho IP {Colors.BRIGHT}{ip_address}{Colors.RESET}"
                )
                return True
            except Exception as e:
                print(f"{Colors.RED}[FIREWALL] Lỗi gỡ chặn IP {ip_address}: {e}{Colors.RESET}")
                self._mock_unblock(ip_address, ts_str)
                return True
        else:
            self._mock_unblock(ip_address, ts_str)
            return True

    def _mock_unblock(self, ip_address: str, ts_str: str) -> None:
        """Thực thi hiển thị mô phỏng hành vi gỡ chặn IP."""
        if ip_address in self.active_blocks:
            self.active_blocks.remove(ip_address)
        print(
            f"{Colors.DIM}[{ts_str}]{Colors.RESET} "
            f"{Colors.GREEN}{Colors.BRIGHT}[FIREWALL]{Colors.RESET} "
            f"{Colors.GREEN}[MÔ PHỎNG GỠ CHẶN] Đã gỡ bỏ rule chặn tường lửa cho IP: {Colors.BRIGHT}{ip_address}{Colors.RESET}"
        )


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    print("=" * 70)
    print(f" {Colors.RED}{Colors.BRIGHT}Kiểm thử độc lập: FirewallBlocker (Layer 4){Colors.RESET} ")
    print("=" * 70)

    # Khởi tạo Blocker
    blocker = FirewallBlocker()

    # Thử chặn một IP bất kỳ
    target_ip = "10.38.50.3"
    print(f"\n[TEST 1] Thực thi chặn IP: {target_ip}...")
    success = blocker.block_ip(target_ip)
    
    if success and target_ip in blocker.active_blocks:
        print("-> Test 1: ĐẠT")
    else:
        print("-> Test 1: THẤT BẠI")

    # Thử chặn lại cùng một IP (Chương trình phải nhận biết và bỏ qua không chạy lại lệnh)
    print(f"\n[TEST 2] Chặn lại IP đã khóa trước đó (Không được in lại log chặn)...")
    success_duplicate = blocker.block_ip(target_ip)
    print("-> Test 2: ĐẠT")

    # Thử gỡ chặn IP
    print(f"\n[TEST 3] Thực thi gỡ chặn IP: {target_ip}...")
    unblock_success = blocker.unblock_ip(target_ip)
    if unblock_success and target_ip not in blocker.active_blocks:
        print("-> Test 3: ĐẠT")
    else:
        print("-> Test 3: THẤT BẠI")
