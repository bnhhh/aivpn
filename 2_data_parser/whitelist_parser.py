#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - Layer 2: Whitelist Parser
Tác giả: Chuyên gia Kỹ sư An toàn Thông tin & Python Backend
Mô tả:
    - Phân tích tệp cấu hình `whitelist.conf` để nạp danh sách an toàn bao gồm IP đơn, dải CIDR, và Domain.
    - Cung cấp hàm `is_whitelisted` kiểm tra nhanh luồng mạng kết nối để bỏ qua phân tích (Bypass/Ignore).
    - Sử dụng thư viện `ipaddress` của Python để xử lý dải mạng chuẩn xác và bảo mật.
"""

import os
import sys
import ipaddress
from typing import Set, List, Optional

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


class WhitelistParser:
    """
    Parser quản lý danh sách Whitelist cho hệ thống IDS.
    """
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.ips: Set[str] = set()
        self.networks: List[ipaddress.IPv4Network] = []
        self.domains: Set[str] = set()
        self.wildcard_domains: List[str] = []
        
        self.load_whitelist()

    def load_whitelist(self) -> None:
        """
        Nạp cấu hình từ file whitelist.conf.
        """
        if not os.path.exists(self.filepath):
            print(f"[\033[33mWARNING\033[0m] Không tìm thấy file whitelist tại {self.filepath}. Hoạt động không whitelist.")
            return

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                for line in f:
                    # Loại bỏ phần comment inline ở cuối dòng
                    if "#" in line:
                        line = line.split("#", 1)[0]
                    line = line.strip()
                    # Bỏ qua dòng trống hoặc dòng comment
                    if not line:
                        continue
                    
                    # 1. Thử parse dạng dải mạng CIDR (Có chứa dấu '/')
                    if "/" in line:
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            self.networks.append(network)
                        except ValueError:
                            # Nếu lỗi, có thể là domain có dấu gạch chéo
                            self.domains.add(line.lower())
                        continue

                    # 2. Thử parse dạng IP đơn lẻ
                    try:
                        ipaddress.ip_address(line)
                        self.ips.add(line)
                        continue
                    except ValueError:
                        pass

                    # 3. Mặc định coi là Domain
                    domain = line.lower()
                    if domain.startswith("*."):
                        # Lưu phần đuôi của wildcard (vd: .google.com)
                        self.wildcard_domains.append(domain[1:])
                    else:
                        self.domains.add(domain)
                        
            print(f"[\033[32mSYSTEM\033[0m] Đã nạp thành công whitelist.conf: {len(self.ips)} IPs, "
                  f"{len(self.networks)} Networks, {len(self.domains) + len(self.wildcard_domains)} Domains.")
        except Exception as e:
            print(f"[\033[31mERROR\033[0m] Lỗi khi nạp file whitelist: {e}")

    def is_whitelisted(self, ip_src: Optional[str] = None, ip_dst: Optional[str] = None, domain: Optional[str] = None) -> bool:
        """
        Kiểm tra xem kết nối hiện tại có thuộc whitelist không.
        Kiểm tra IP nguồn, IP đích và Domain truy vấn.
        """
        # 1. Kiểm tra so khớp IP nguồn / IP đích
        for ip in (ip_src, ip_dst):
            if not ip:
                continue
            
            # Khớp IP đơn lẻ
            if ip in self.ips:
                return True
                
            # Khớp dải mạng CIDR
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net in self.networks:
                    if ip_obj in net:
                        return True
            except ValueError:
                pass

        # 2. Kiểm tra so khớp Domain
        if domain:
            domain_lower = domain.lower()
            # Khớp domain chính xác
            if domain_lower in self.domains:
                return True
                
            # Khớp wildcard domain (vd: *.google.com)
            for wild in self.wildcard_domains:
                if domain_lower.endswith(wild) or domain_lower == wild[1:]:
                    return True

        return False


# --- KHỐI CHẠY KIỂM THỬ ĐỘC LẬP (UNIT TEST) ---
if __name__ == "__main__":
    # Tạo tệp tin whitelist mẫu để test
    test_conf = "test_whitelist.conf"
    with open(test_conf, "w", encoding="utf-8") as f:
        f.write("# File test whitelist\n")
        f.write("8.8.8.8\n")
        f.write("10.38.50.0/24\n")
        f.write("google.com\n")
        f.write("*.wikipedia.org\n")

    print("=" * 70)
    print(" Kiểm thử độc lập: WhitelistParser (Layer 2) ")
    print("=" * 70)

    parser = WhitelistParser(test_conf)

    # Test 1: Khớp IP đơn
    print("Test 1: IP 8.8.8.8 có whitelist? ->", parser.is_whitelisted(ip_src="8.8.8.8"))
    
    # Test 2: Khớp dải CIDR
    print("Test 2: IP 10.38.50.5 có whitelist? ->", parser.is_whitelisted(ip_src="10.38.50.5"))
    print("Test 3: IP 192.168.1.1 có whitelist? ->", parser.is_whitelisted(ip_src="192.168.1.1"))

    # Test 4: Khớp Domain chính xác
    print("Test 4: Domain 'google.com' có whitelist? ->", parser.is_whitelisted(domain="google.com"))

    # Test 5: Khớp Wildcard Domain
    print("Test 5: Domain 'en.wikipedia.org' có whitelist? ->", parser.is_whitelisted(domain="en.wikipedia.org"))
    print("Test 6: Domain 'evil.com' có whitelist? ->", parser.is_whitelisted(domain="evil.com"))

    # Dọn dẹp file test
    if os.path.exists(test_conf):
        os.remove(test_conf)
