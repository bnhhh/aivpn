@echo off
chcp 65001 >nul
title C2 Beaconing Simulator (APT Stealth)
color 0C

echo =======================================================
echo     [AIVPN] CHUONG TRINH GIA LAP MA DOC C2 BEACONING
echo =======================================================
echo Kich ban: Ma doc lien tuc goi ve may chu dieu khien (C2)
echo Chu ky: Trung binh 10 giay/lan
echo Jitter: Ngau nhien tu 8 den 12 giay de qua mat Heuristic
echo =======================================================
echo.

set /p target_ip="Nhap IP cua Server (Vi du: 10.38.50.1 hoac 8.8.8.8): "

:loop
echo [!] Dang gui tin hieu Beacon ngam (Stealth Ping) den %target_ip%...
:: Gui 1 goi tin duy nhat de mo phong lenh C2
ping %target_ip% -n 1 -w 1000 >nul

:: Su dung PowerShell de tao Jitter ngau nhien tu 8 den 12 giay
powershell -Command "$sleep_time = Get-Random -Minimum 8 -Maximum 13; Write-Host \"[+] Beacon da gui. Ngu dong $sleep_time giay de xoa dau vet...\"; Start-Sleep -Seconds $sleep_time"

echo.
goto loop
