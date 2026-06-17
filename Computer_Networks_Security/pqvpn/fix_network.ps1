# fix_network.ps1
# Her iki PC'de de YONETICI olarak PowerShell'de calistirin:
#   Right-click PowerShell -> "Run as Administrator"
#   cd "C:\Users\MUSTAFA\Desktop\CENG FİLES\3.SINIF\bahar\network\pqvpn"
#   .\fix_network.ps1

# UTF-8 encoding duzeltmesi (bozuk karakter sorununu cozar)
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "   PQ-VPN Windows Firewall Duzeltme Scripti" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# 1. ICMP (Ping) Izni
Write-Host "[1/4] ICMP (ping) trafigine izin veriliyor..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="PQ-VPN Allow ICMPv4 In" `
    protocol=icmpv4:8,any `
    dir=in `
    action=allow | Out-Null
Write-Host "      [OK] ICMP (ping) acildi." -ForegroundColor Green

# 2. TCP 4444 (Kyber Handshake)
Write-Host "[2/4] TCP 4444 portu (Kyber el sikismasi) aciliyor..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="PQ-VPN Kyber Handshake TCP 4444" `
    dir=in `
    action=allow `
    protocol=TCP `
    localport=4444 | Out-Null
Write-Host "      [OK] TCP 4444 acildi." -ForegroundColor Green

# 3. UDP 5555 (Sifreli Tunel)
Write-Host "[3/4] UDP 5555 portu (sifreli VPN tuneli) aciliyor..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="PQ-VPN Encrypted Tunnel UDP 5555" `
    dir=in `
    action=allow `
    protocol=UDP `
    localport=5555 | Out-Null
Write-Host "      [OK] UDP 5555 acildi." -ForegroundColor Green

# 4. Windows IP Adresini Goster
Write-Host "[4/4] Bu bilgisayarin LAN IP adresi:" -ForegroundColor Yellow
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
       Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*" } |
       Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "      >>> IP Adresiniz: $ip <<<" -ForegroundColor Cyan
Write-Host "      >>> Bu IP'yi karsi bilgisayarda kullanin! <<<" -ForegroundColor Cyan

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "  HAZIR! Simdi WSL2'den test edin:" -ForegroundColor Green
Write-Host "  wsl ping $ip" -ForegroundColor White
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
