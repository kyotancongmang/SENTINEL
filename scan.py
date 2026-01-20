#!/usr/bin/env python3
"""
scanner.py
Updated for Recursive YARA Loading & Offline URL Scanning
"""

import os
import sys
import argparse
import base64
import hashlib
import json
import subprocess
import math
import re
from pathlib import Path

import requests
import magic 
import filetype 


try:
    import yara # type: ignore
except ImportError:
    yara = None
try:
    import lief # type: ignore
except ImportError:
    lief = None

# --- API KEYS ---
VT_API_KEY =  "1a639a4f8db95c22c4f16005fdce5df9466cc6c98923a90f4fcd249f0d98249d"
GSB_API_KEY = "AIzaSyD21QgC7AV8LcfeDkc1U9gE6KoGs5VDqnkn"

# --- GLOBAL VARIABLES ---
# Biến này dùng để lưu rules đã compile, tránh compile lại nhiều lần
COMPILED_RULES = None

# --- HELPER FUNCTIONS ---

def calculate_entropy(data):
    """Tính độ hỗn loạn dữ liệu (Entropy)"""
    if not data:
        return 0
    entropy = 0
    if isinstance(data, str):
        data = data.encode('utf-8')
    for x in range(256):
        p_x = float(data.count(x.to_bytes(1, 'little'))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def detect_file_type(path: str):
    try:
        m = magic.from_file(path, mime=True)
        return m
    except Exception:
        try:
            kind = filetype.guess(path)
            if kind:
                return kind.mime
        except Exception:
            return "application/octet-stream"
    return "application/octet-stream"

# --- YARA ENGINE (CORE) ---

def load_yara_rules(rules_path: str = "yara_rules/"):
    global COMPILED_RULES
    if COMPILED_RULES is not None:
        return COMPILED_RULES
    
    if yara is None:
        return None

    rules_files = {}
    print(f"[*] Đang nạp cơ sở dữ liệu YARA từ: {rules_path}...")
    
    if os.path.isdir(rules_path):
        for root, dirs, files in os.walk(rules_path):
            for f in files:
                # 1. Chỉ lấy file .yar hoặc .yara
                if f.endswith(".yara") or f.endswith(".yar"):
                    
                    # 2. LOẠI BỎ TRIỆT ĐỂ FILE INDEX
                    # Các file này thường gây lỗi 'can't open include file'
                    fname_lower = f.lower()
                    if "index" in fname_lower:
                        continue

                    full_path = os.path.join(root, f)
                    
                    # Tạo namespace unique để tránh xung đột
                    namespace = f"{os.path.basename(root)}_{f}"
                    clean_namespace = "".join(c if c.isalnum() else "_" for c in namespace)
                    
                    if clean_namespace in rules_files:
                        clean_namespace += f"_{len(rules_files)}"
                        
                    rules_files[clean_namespace] = full_path

    if not rules_files:
        print("[!] Không tìm thấy quy tắc YARA nào.")
        return None

    # THỬ NGHIỆM TỪNG FILE ĐỂ LOẠI BỎ FILE LỖI CÚ PHÁP (Robust Loading)
    valid_rules = {}
    print(f"[*] Đang kiểm tra {len(rules_files)} tệp quy tắc...")
    
    for ns, path in rules_files.items():
        try:
            # Thử compile từng file lẻ để kiểm tra lỗi cú pháp
            yara.compile(filepath=path)
            valid_rules[ns] = path
        except Exception:
            # Nếu file lỗi (syntax, include lỗi...), bỏ qua nó
            continue

    if not valid_rules:
        return None

    try:
        COMPILED_RULES = yara.compile(filepaths=valid_rules)
        print(f"[*] Đã nạp thành công {len(valid_rules)} quy tắc YARA.")
        return COMPILED_RULES
    except Exception as e:
        print(f"[Error] Lỗi nạp YARA tổng thể: {e}")
        return None

def yara_scan_file(path: str) -> dict:
    rules = load_yara_rules()
    if rules is None:
        if yara is None: return {"error": "yara-python not installed"}
        return {"info": "no rules found or compile error"}
    
    try:
        # Sử dụng fast=True để tránh lỗi 'too many matches' và tăng tốc độ
        # timeout=60 để đảm bảo không bị treo nếu gặp file cực lớn
        matches = rules.match(path, fast=True, timeout=60)
        return {"matches": [m.rule for m in matches]}
    except yara.TimeoutError:
        return {"error": "YARA scan timed out"}
    except Exception as e:
        return {"error": str(e)}

def yara_scan_string(text_data: str) -> dict:
    """Quét một chuỗi ký tự (URL) bằng YARA Rules"""
    rules = load_yara_rules()
    if rules is None:
        return {"info": "no rules found"}
    
    try:
        matches = rules.match(data=text_data)
        return {"matches": [m.rule for m in matches]}
    except Exception as e:
        return {"error": str(e)}

# --- OFFLINE HEURISTICS FOR URL ---

def offline_url_heuristic(url: str) -> list:
    """Phân tích URL bằng Regex và Logic để tìm điểm nghi ngờ mà không cần mạng"""
    flags = []
    
    # 1. Kiểm tra xem có dùng IP Address không
    ip_pattern = r"http[s]?://(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, url):
        flags.append("Heuristic: URL uses raw IP address (Suspicious)")
        
    # 2. Kiểm tra độ dài bất thường
    if len(url) > 150:
        flags.append("Heuristic: URL is unusually long")
        
    # 3. Kiểm tra user-info trong URL (vd: http://user:pass@site.com)
    if "@" in url:
        flags.append("Heuristic: URL contains credentials (@ symbol)")
        
    # 4. Kiểm tra nhiều subdomain lồng nhau
    domain_part = url.split("/")[2] if "//" in url else url
    if domain_part.count(".") > 4:
        flags.append("Heuristic: Excessive subdomains")
        
    # 5. Các đuôi mở rộng nguy hiểm thực thi
    dangerous_exts = [".exe", ".scr", ".bat", ".vbs", ".apk"]
    if any(url.endswith(ext) for ext in dangerous_exts):
        flags.append("Heuristic: Direct link to executable file")

    return flags

# --- ONLINE APIs ---

def google_safe_browsing_lookup(url: str) -> dict:
    if not GSB_API_KEY or "YOUR_" in GSB_API_KEY:
        return {"error": "NO_API_KEY"}
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GSB_API_KEY
    payload = {
        "client": {"clientId": "your-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(endpoint, json=payload, timeout=5)
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}", "body": r.text}
        return r.json()
    except Exception as e:
        return {"error": str(e)}

VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def vt_file_report_by_hash(sha256_hex: str) -> dict:
    if not VT_API_KEY or "YOUR_" in VT_API_KEY:
        return {"error": "NO_API_KEY"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256_hex}"
    try:
        r = requests.get(url, headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def vt_url_report(url_to_check: str) -> dict:
    if not VT_API_KEY or "YOUR_" in VT_API_KEY:
        return {"error": "NO_API_KEY"}
    encoded = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    get_url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    try:
        r = requests.get(get_url, headers=VT_HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        
        post_url = "https://www.virustotal.com/api/v3/urls"
        r2 = requests.post(post_url, headers=VT_HEADERS, data={"url": url_to_check}, timeout=10)
        if r2.status_code in (200,201):
            return r2.json()
        return {"error": f"HTTP {r.status_code}/{r2.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

# --- OFFLINE SCANNERS ---

def clam_scan_file(path: str) -> dict:
    try:
        proc = subprocess.run(["clamscan", "--no-summary", path], capture_output=True, text=True, timeout=60)
        out = proc.stdout + proc.stderr
        return {"raw": out, "returncode": proc.returncode}
    except FileNotFoundError:
        return {"error": "clamscan not installed"}
    except Exception as e:
        return {"error": str(e)}

def inspect_binary_with_lief(path: str) -> dict:
    if lief is None:
        return {"error": "lief not installed"}
    try:
        binary = lief.parse(path)
        if not binary: return {"error": "Not a binary file"}
        info = {
            "format": binary.format.name if hasattr(binary, "format") else "unknown",
            "entrypoint": getattr(binary, "entrypoint", None),
            "sections": [s.name for s in getattr(binary, "sections", [])],
        }
        return {"lief": info}
    except Exception as e:
        return {"error": str(e)}

# --- MAIN LOGIC FUNCTIONS ---

def scan_file_main(path: str, offline_mode: bool = False):
    out = {"path": path}
    out["sha256"] = sha256_of_file(path)
    out["mime"] = detect_file_type(path)
    
    # 1. Scanners (Chạy cả Offline & Online)
    out["clamav"] = clam_scan_file(path)
    out["yara"] = yara_scan_file(path) # Đã hỗ trợ submodules
    
    try:
        with open(path, "rb") as f:
            out["entropy"] = calculate_entropy(f.read())
    except:
        out["entropy"] = 0

    if any(x in out["mime"] for x in ["application/x-dosexec", "application/x-executable"]) or path.endswith((".exe", ".dll", ".dylib")):
        out["lief"] = inspect_binary_with_lief(path)

    # 2. Online Logic
    if not offline_mode:
        out["vt"] = vt_file_report_by_hash(out["sha256"])
    else:
        out["vt"] = {"error": "Skipped (Offline Mode)"}

    # 3. Phân tích kết quả (Aggregating Results)
    clean_list = []      
    malicious_list = [] 

    # -- YARA Analysis --
    yara_matches = out.get("yara", {}).get("matches", [])
    if yara_matches:
        for m in yara_matches: malicious_list.append(f"YARA Rule: {m}")
    else:
        if "error" in out.get("yara", {}): clean_list.append("YARA: Error/Not Installed")
        else: clean_list.append("YARA: Clean")

    # -- ClamAV Analysis --
    clam_raw = str(out["clamav"].get("raw", ""))
    clam_danger = "FOUND" in clam_raw
    if clam_danger: malicious_list.append("ClamAV: Infected")
    elif "not installed" in str(out["clamav"].get("error", "")): clean_list.append("ClamAV: Not Installed")
    else: clean_list.append("ClamAV: Clean")

    # -- Entropy Analysis --
    ENTROPY_THRESHOLD = 7.5
    entropy = out.get("entropy", 0)
    entropy_danger = entropy > ENTROPY_THRESHOLD
    if entropy_danger:
        malicious_list.append(f"Heuristic: High Entropy ({entropy:.2f}) - Packed/Encrypted")
    else:
        clean_list.append(f"Entropy: Normal ({entropy:.2f})")

    # -- VirusTotal Analysis --
    vt_malicious = 0
    if not offline_mode and "data" in out.get("vt", {}):
        try:
            attr = out["vt"]["data"]["attributes"]
            vt_malicious = attr["last_analysis_stats"]["malicious"]
            results = attr.get("last_analysis_results", {})
            for engine, res in results.items():
                if res.get("result") and res.get("result").lower() != "clean":
                    malicious_list.append(f"VT ({engine}): {res.get('result')}")
        except: pass
    elif offline_mode:
        clean_list.append("VirusTotal: Offline Skipped")

    is_danger = (vt_malicious > 0) or clam_danger or (len(yara_matches) > 0) or entropy_danger

    return {
        "is_danger": is_danger,
        "filename": os.path.basename(path),
        "details": {
            "Mode": "OFFLINE" if offline_mode else "ONLINE",
            "MIME": out["mime"],
            "Entropy": f"{entropy:.2f}"
        },
        "clean_list": clean_list,
        "malicious_list": malicious_list
    }

def scan_url_main(url: str, offline_mode: bool = False):
    clean_list = []
    malicious_list = []
    vt_malicious = 0
    gsb_danger = False

    # 1. OFFLINE CHECKS (Luôn chạy)
    
    # A. Heuristic Regex (Kiểm tra nhanh)
    heuristic_flags = offline_url_heuristic(url)
    if heuristic_flags:
        for flag in heuristic_flags:
            malicious_list.append(flag)
    else:
        clean_list.append("Heuristic: No suspicious pattern")

    # B. YARA String Scan (Kiểm tra xem URL có match blacklist nào trong rules không)
    # Lưu ý: Rules YARA thường cho file, nhưng một số bộ rules có check pattern string.
    yara_res = yara_scan_string(url)
    yara_matches = yara_res.get("matches", [])
    if yara_matches:
        for m in yara_matches: malicious_list.append(f"YARA URL: {m}")
    else:
        clean_list.append("YARA URL: Clean")

    # 2. ONLINE CHECKS
    if not offline_mode:
        # VirusTotal
        vt_res = vt_url_report(url)
        if "data" in vt_res:
            try:
                attr = vt_res["data"]["attributes"]
                vt_malicious = attr["last_analysis_stats"]["malicious"]
                if vt_malicious > 0:
                     malicious_list.append(f"VirusTotal: {vt_malicious} engines detected")
                else:
                    clean_list.append("VirusTotal: Clean")
            except: pass
        
        # Google Safe Browsing
        gsb_res = google_safe_browsing_lookup(url)
        if "matches" in gsb_res:
            gsb_danger = True
            malicious_list.append("Google Safe Browsing: MALICIOUS")
        elif "error" not in gsb_res:
             clean_list.append("Google Safe Browsing: Clean")
    else:
        clean_list.append("Online APIs: Skipped (Offline Mode)")

    is_danger = (vt_malicious > 0) or gsb_danger or (len(malicious_list) > 0)

    return {
        "is_danger": is_danger,
        "target": url,
        "details": {
            "Mode": "OFFLINE" if offline_mode else "ONLINE",
            "Heuristic Flags": len(heuristic_flags)
        },
        "clean_list": clean_list,
        "malicious_list": malicious_list
    }

# --- CLI ENTRY POINT ---
def main():
    parser = argparse.ArgumentParser(description="Advanced Malware Scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", "-f", help="Path to file")
    group.add_argument("--url", "-u", help="URL to scan")
    parser.add_argument("--offline", action="store_true", help="Enable Offline Mode")
    parser.add_argument("--out", "-o", help="Output JSON file")
    args = parser.parse_args()

    if args.file:
        if not os.path.exists(args.file):
            print("File not found"); sys.exit(2)
        res = scan_file_main(args.file, offline_mode=args.offline)
    else:
        # Giờ đây URL scan cũng hỗ trợ tham số offline_mode
        res = scan_url_main(args.url, offline_mode=args.offline)

    print(json.dumps(res, indent=2, ensure_ascii=False))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()