@echo off
set /p TARGET_IP="Nhap IP cua may chu AIVPN (Mac dinh: 10.38.50.1): "
if "%TARGET_IP%"=="" set TARGET_IP=10.38.50.1

set /a count=0

echo.
:loop
set /a count+=1
set /a jitter=%RANDOM% %% 3

echo [%time%] [BEACON #%count%] Gui tin hieu C2 ==^> http://%TARGET_IP%/update?seq=%count%
curl -s -o nul -m 1 "http://%TARGET_IP%/update?seq=%count%"

timeout /t 2 /nobreak >nul
if %jitter% GTR 1 timeout /t 1 /nobreak >nul

goto loop