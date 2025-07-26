# ================================
# @author 0x6768 <xxyang233@foxmail.com>
# @license Apache License 2.0
# @github https://github.com/0x6768/pwsh-profile
# =++++++++++++++++++++++++++++++=
# Note
# This script needs to be run in the PROFILE to achieve the best results.
# For more information, see https://learn.microsoft.com/powershell/scripting/learn/shell/creating-profiles?view=powershell-5.1
# ================================

# You Powershell, why are you so like bash
# This is the author idle nothing is written, please don't care, but he is really useful!

# Clear screen on startup
Clear-Host
# Define some variables that don't work
$osName = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
$buildLabEx = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name BuildLabEx).BuildLabEx
$architecture = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Architecture
switch ($architecture) {
    0 { $cpuArch = "x86" }
    1 { $cpuArch = "MIPS" }
    2 { $cpuArch = "Alpha" }
    3 { $cpuArch = "PowerPC" }
    5 { $cpuArch = "ARM" }
    6 { $cpuArch = "Itanium" }
    9 { $cpuArch = "x86_64" }
    12 { $cpuArch = "ARM64" }
    default { $cpuArch = "Unknown" }
}
# Ubuntu-style welcome message
Write-Host "Welcome to $osName ($buildLabEx $cpuArch)`n"
Write-Host "   *  Documentation:`thttps://learn.microsoft.com/windows/"
Write-Host "   *  Management:`thttps://endpoint.microsoft.com/"
Write-Host "   *  Support:`t`thttps://support.microsoft.com/`n`n"
# Clean up temporary variables
Remove-Variable osName, buildLabEx, architecture, cpuArch -ErrorAction SilentlyContinue
# Kali-style Prompt
function prompt{
    $userHost = "$env:USERNAME@$env:COMPUTERNAME"
    $currentPath = "$(Get-Location)"
    
    # First line
    Write-Host "┌──(" -NoNewLine -ForegroundColor Blue
    Write-Host "$userHost" -NoNewLine -ForegroundColor Red
    Write-Host ")-[" -NoNewLine -ForegroundColor Blue
    Write-Host "$currentPath" -NoNewLine -ForegroundColor White
    Write-Host "]" -ForegroundColor Blue

    # Second line
    Write-Host -NoNewLine "└─" -ForegroundColor Blue
    Write-Host -NoNewLine "#" -ForegroundColor Red

    return " "
}

# Reload environment variables (especially PATH)
function global:Reload-Environment {
    param(
        [switch]$NoOutput,
        [switch]$v
    )
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')

    # Merge and deduplicate PATH entries
    $newPath = ($machinePath, $userPath -split ';' | Where-Object { $_ -and $_ -ne '' } | Select-Object -Unique) -join ';'
    $env:Path = $newPath

    if ($v) {
        Write-Host "[Verbose]" -ForegroundColor Cyan
        Write-Host "System path: $machinePath" -ForegroundColor DarkGray
        Write-Host "User Path: $userPath" -ForegroundColor DarkGray
        Write-Host "Post-merger: $newPath" -ForegroundColor Yellow
    }

    if (-not $NoOutput) {
        Write-Host "[√] Environment reloaded! (Unique entries: $($newPath.Split(';').Count))" -ForegroundColor Green
    }
}

# Aliases for Linux-like experience
function global:apt { winget @args }
function global:ppip {
    # 检查是否是 install/i 命令
    if ($args[0] -eq "install" -or $args[0] -eq "i" -or  $args[0] -eq "add") {
        $newArgs = @("pip", "install") + $args[1..($args.Length - 1)] + "--extra-index-url", "https://pypi.tuna.tsinghua.edu.cn/simple" + "--system"
        # 执行 uv 命令
        uv @newArgs
    }
    else {
        # 其他命令直接透传
        uv pip @args
    }
}
function global:sapt { scoop @args }
function web-test {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Url,
        [int]$Port
    )
        if (-not $Url) {
        Write-Host @"
web-test - HTTP/HTTPS & TCP 网络测试工具

用法:
  web-test <URL> [端口]

示例:
  web-test http://example.com          # 测试 HTTP (默认端口 80)
  web-test https://example.com         # 测试 HTTPS (默认端口 443)
  web-test http://localhost:8080       # 测试自定义端口
  web-test http://example.com 8080     # 显式指定端口

输出信息:
  [+] TCP Latency (Avg): XX ms         # TCP 平均延迟
  [-] TCP Ping Failed (Port XX unreachable)  # TCP 连接失败
  [-] Testing HTTP/HTTPS...            # 开始 HTTP 测试
  [!] Skipping HTTP test (TCP failed)  # TCP 失败时跳过 HTTP 测试
"@
        return
    }


    # 提取主机名
    if ($Url -match '^(?:https?:\/\/)?([^\/:]+)') {
        $hostname = $matches[1]
    } else {
        Write-Host "[X] Invalid URL format!" -ForegroundColor Red
        return
    }

    # 自动判断端口
    if ($Url -match '^(?:https?:\/\/)?[^\/:]+:(\d+)') {
    $Port = [int]$matches[1]  # 如果 URL 带端口，直接使用
    } elseif (-not $Port) {
        $Port = if ($Url -match '^https:\/\/') { 443 } else { 80 }  # 否则用默认端口
    }
    # 1. 获取 tcping 输出
    $tcpingOutput = tcping $hostname $Port

    # 2. 检查是否全部失败（关键！）
    $isFailed = ($tcpingOutput -match "0 successful") -or ($tcpingOutput -match "Was unable to connect")

    if ($isFailed) {
        # 从 tcping 输出提取实际测试的端口（避免误报）
        $probedPort = ($tcpingOutput -match "Probing .*?(\d+)/tcp")[0] -replace '.*?(\d+)/tcp.*', '$1'
        Write-Host "[X] TCP Ping Failed (Port $probedPort unreachable)" -ForegroundColor Red
        $averageRtt = "Timeout"
    } else {
        # 3. 暴力提取平均延迟（最后一行）
        $averageLine = ($tcpingOutput | Select-Object -Last 1)
        $averageRtt = ($averageLine -split 'Average = ')[1] -replace 'ms.*' -replace ',', ''
        Write-Host "[+] TCP Latency (Avg): $averageRtt ms" -ForegroundColor Green
    }

    # 4. 测试 HTTP/HTTPS 性能
    Write-Host "`n[-] Testing HTTP/HTTPS..." -ForegroundColor Cyan
    if ($averageRtt -eq "Timeout") {
        Write-Host "[!]  Skipping HTTP test (TCP failed)" -ForegroundColor Yellow
    } else {
        curl.exe -s -o NUL -w "TCP Latency: $averageRtt ms`nDNS Lookup: %{time_namelookup}s`nConnect Time: %{time_connect}s`nSSL Handshake: %{time_appconnect}s`nTTFB: %{time_starttransfer}s`nTotal Time: %{time_total}s`n" $Url
    }
}
Set-Alias -Name reenv -Value Reload-Environment
