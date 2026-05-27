@echo off
set /p TARGET_IP="Nhap IP cua may chu AIVPN (Mac dinh: 10.38.50.1): "
if "%TARGET_IP%"=="" set TARGET_IP=10.38.50.1

powershell -ExecutionPolicy Bypass -Command "& { $target = '%TARGET_IP%'; for ($p=100; $p -le 200; $p++) { Write-Host ('  [-] Gui goi tin TCP SYN ==^> ' + $target + ':' + $p) -ForegroundColor Yellow; $tcp = New-Object System.Net.Sockets.TcpClient; $ia = $tcp.BeginConnect($target, $p, $null, $null); $wait = $ia.AsyncWaitHandle.WaitOne(100); if ($wait) { try { $tcp.EndConnect($ia) } catch {} }; $tcp.Close(); Start-Sleep -Milliseconds 300 } }"