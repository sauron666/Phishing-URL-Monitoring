import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import aiohttp
import asyncio
import json
import csv
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import threading
import time
import os
import re
import sqlite3
import logging
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse
from PIL import Image, ImageTk
import validators
from concurrent.futures import ThreadPoolExecutor
import psutil

# Configuration file
CONFIG_FILE = "config.json"

class PhishingURLChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing URL Monitoring")
        self.root.geometry("1200x800")
        
        # Load configuration
        self.config = self.load_config()
        self.api_keys = self.config.get("api_keys", {})
        self.smtp_config = self.config.get("smtp_config", {})
        self.check_interval = self.config.get("check_interval", 3600)
        self.cache_ttl = self.config.get("cache_ttl", 24 * 3600)
        self.batch_size = self.config.get("batch_size", 10)
        self.inactive_threshold = self.config.get("inactive_threshold", 7)  # Days to keep inactive URLs
        self.risk_colors = self.config.get("risk_colors", {
            "High": "#ffcccc",
            "Medium": "#ffffcc",
            "Low": "#ccffcc",
            "Inactive": "#e6e6e6"
        })
        
        # Variables
        self.urls = []
        self.history_file = "phishing_url_history.csv"
        self.db_file = "phishing_urls.db"
        self.log_file = "phishing_monitor.log"
        self.auto_check_running = False
        self.auto_remove_inactive = False
        self.email_notifications_enabled = False
        self.db_pool = ThreadPoolExecutor(max_workers=1)
        self.url_queue = queue.Queue()
        
        # Setup logging
        self.setup_logging()
        
        # Initialize database
        self.init_db()
        
        # GUI Elements
        self.setup_ui()
        
        # Load initial history
        self.load_history()

    def load_config(self):
        """Load configuration from JSON file with validation"""
        default_config = {
            "api_keys": {
                "virustotal": "",
                "urlscan": ""
            },
            "smtp_config": {
                "host": "",
                "port": 465,
                "user": "",
                "password": "",
                "recipient": "",
                "from_name": "Phishing Monitor"
            },
            "check_interval": 7200,
            "cache_ttl": 86400,
            "batch_size": 10,
            "inactive_threshold": 7,
            "risk_colors": {
                "High": "#ffcccc",
                "Medium": "#ffffcc",
                "Low": "#ccffcc",
                "Inactive": "#e6e6e6"
            }
        }
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # Validate SMTP config
                    if not all(k in config.get("smtp_config", {}) for k in ["host", "port", "user", "password", "recipient"]):
                        messagebox.showwarning("Config Warning", "SMTP configuration is incomplete. Email notifications will be disabled.")
                        config["smtp_config"] = default_config["smtp_config"]
                    return {**default_config, **config}
            return default_config
        except Exception as e:
            self.log_error(f"Failed to load config: {str(e)}")
            return default_config

    def setup_logging(self):
        """Setup structured JSON logging with rotation"""
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler(self.log_file, maxBytes=10*1024*1024, backupCount=5)
        formatter = logging.Formatter('{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        self.log_info("Application started")

    def init_db(self):
        """Initialize SQLite database with migration for external_checks_timestamp"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS urls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE,
                        status TEXT,
                        last_checked TEXT,
                        first_detected TEXT,
                        risk_level TEXT,
                        redirect_chain TEXT,
                        external_checks TEXT,
                        external_checks_timestamp TEXT,
                        comments TEXT
                    )
                ''')
                cursor.execute("PRAGMA table_info(urls)")
                columns = [col[1] for col in cursor.fetchall()]
                if 'external_checks_timestamp' not in columns:
                    cursor.execute('ALTER TABLE urls ADD COLUMN external_checks_timestamp TEXT')
                    self.log_info("Migrated database: Added external_checks_timestamp column")
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON urls (url)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_checked ON urls (last_checked)')
                conn.commit()
        except Exception as e:
            self.log_error(f"Database initialization error: {str(e)}")

    def setup_ui(self):
        """Setup the GUI with status bar and progress bar"""
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Input Frame
        input_frame = ttk.LabelFrame(main_frame, text="Check URLs", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Enter URL(s) or text:").grid(row=0, column=0, sticky=tk.W)
        self.url_entry = ttk.Entry(input_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, sticky=tk.EW)
        
        ttk.Button(input_frame, text="Add URL", command=self.check_single_url).grid(row=0, column=2, padx=5)
        ttk.Button(input_frame, text="Load List", command=self.import_urls).grid(row=0, column=3, padx=5)
        ttk.Button(input_frame, text="Extract URLs", command=self.extract_urls_from_text).grid(row=0, column=4, padx=5)
        
        # Analysis Frame
        analysis_frame = ttk.LabelFrame(main_frame, text="Analysis Tools", padding="10")
        analysis_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(analysis_frame, text="Trace Redirects", command=self.trace_selected_redirects).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Check VirusTotal", command=self.check_virustotal).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Check URLScan", command=self.check_urlscan).pack(side=tk.LEFT, padx=5)
        ttk.Button(analysis_frame, text="Analyze Risk", command=self.analyze_risk_selected).pack(side=tk.LEFT, padx=5)
        
        # History Frame
        history_frame = ttk.LabelFrame(main_frame, text="URL History", padding="10")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.tree = ttk.Treeview(history_frame, columns=("URL", "Status", "Risk", "Last Checked", "First Detected", "Comments"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.column("URL", width=300)
        self.tree.column("Status", width=80)
        self.tree.column("Risk", width=80)
        self.tree.column("Last Checked", width=150)
        self.tree.column("First Detected", width=150)
        self.tree.column("Comments", width=200)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details Frame
        details_frame = ttk.LabelFrame(main_frame, text="URL Details", padding="10")
        details_frame.pack(fill=tk.X, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, height=8, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Action Buttons Frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(action_frame, text="Re-check Selected", command=self.recheck_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Re-check All", command=self.recheck_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Delete Selected", command=self.delete_selected_urls).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Remove Inactive", command=self.remove_inactive_urls).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Auto-check Toggle", command=self.toggle_auto_check).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Auto-remove Toggle", command=self.toggle_auto_remove).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Email Notify Toggle", command=self.toggle_email_notifications).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export CSV", command=lambda: self.export_history("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export JSON", command=lambda: self.export_history("json")).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Add Comment", command=self.add_comment).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Report to CERT", command=self.report_to_cert).pack(side=tk.LEFT, padx=5)
        
        self.tree.bind("<<TreeviewSelect>>", self.show_url_details)

    def log_info(self, message):
        """Log info with performance metrics"""
        memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        logging.info(json.dumps({"message": message, "memory_mb": memory}))

    def log_error(self, message):
        """Log error with performance metrics"""
        memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        logging.error(json.dumps({"message": message, "memory_mb": memory}))

    async def check_url_async(self, url, session, retries=3, backoff_factor=1):
        """Asynchronously check if URL is active with retry logic"""
        for attempt in range(retries):
            try:
                parsed = urlparse(url)
                if not parsed.scheme:
                    url = "http://" + url
                if not validators.url(url):
                    return "Invalid", f"Invalid URL format: {url}"

                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
                async with session.get(url, headers=headers, timeout=20, allow_redirects=False) as response:
                    if response.status == 200:
                        return "Active", f"Status: {response.status}"
                    elif response.status in (301, 302, 303, 307, 308):
                        location = response.headers.get('Location', 'Unknown')
                        return f"Redirect ({response.status})", f"Redirect to: {location}"
                    else:
                        return "Inactive", f"Status: {response.status}"
            except aiohttp.ClientError as e:
                if attempt < retries - 1:
                    await asyncio.sleep(backoff_factor * (2 ** attempt))
                    continue
                return "Error", f"Connection error: {str(e)}"
            except Exception as e:
                return "Error", f"Unexpected error: {str(e)}"
        return "Error", "Max retries exceeded"

    async def trace_redirects_async(self, url, session, retries=3, backoff_factor=1):
        """Asynchronously trace redirect chain with retry logic"""
        for attempt in range(retries):
            try:
                parsed = urlparse(url)
                if not parsed.scheme:
                    url = "http://" + url
                if not validators.url(url):
                    return [{"url": url, "status": "Invalid URL", "headers": {}}]

                redirect_chain = []
                async with session.get(url, allow_redirects=True, timeout=20) as response:
                    for resp in response.history:
                        redirect_chain.append({
                            "url": str(resp.url),
                            "status": resp.status,
                            "headers": dict(resp.headers)
                        })
                    redirect_chain.append({
                        "url": str(response.url),
                        "status": response.status,
                        "headers": dict(response.headers)
                    })
                return redirect_chain
            except Exception as e:
                if attempt < retries - 1:
                    await asyncio.sleep(backoff_factor * (2 ** attempt))
                    continue
                return [{"url": url, "status": f"Error: {str(e)}", "headers": {}}]
        return [{"url": url, "status": "Max retries exceeded", "headers": {}}]

    def score_url_risk(self, url):
        """Score URL risk based on various factors"""
        risk_score = 0
        risk_reasons = []
        
        suspicious_extensions = ['.php', '.asp', '.exe', '.js', '.jar']
        if any(ext in url.lower() for ext in suspicious_extensions):
            risk_score += 2
            risk_reasons.append("Suspicious extension")
        
        suspicious_keywords = ['login', 'account', 'verify', 'secure', 'banking', 'paypal']
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            risk_score += 1
            risk_reasons.append("Suspicious keywords in URL")
        
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, url):
            risk_score += 2
            risk_reasons.append("IP address in URL")
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd']
        if any(shortener in url.lower() for shortener in shorteners):
            risk_score += 1
            risk_reasons.append("URL shortening service")
        
        suspicious_tlds = ['.tk', '.gq', '.ml', '.cf', '.ga', '.xyz']
        parsed = urlparse(url)
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 1 and domain_parts[-1] in suspicious_tlds:
            risk_score += 2
            risk_reasons.append("Suspicious TLD")
        
        return ("High" if risk_score >= 3 else "Medium" if risk_score >= 1 else "Low"), risk_reasons

    async def check_virustotal_batch(self, urls, session, semaphore):
        """Batch check URLs with VirusTotal API with rate limiting"""
        results = {}
        async def check_single(url):
            async with semaphore:
                try:
                    if cached_result := await self.check_cache(url, 'virustotal'):
                        return url, cached_result
                    params = {'apikey': self.api_keys.get('virustotal', ''), 'resource': url}
                    async with session.get('https://www.virustotal.com/vtapi/v2/url/report', params=params) as response:
                        if response.status == 200:
                            result = await response.json()
                            if result['response_code'] == 1:
                                result_data = {
                                    "positives": result['positives'],
                                    "total": result['total'],
                                    "scan_date": result['scan_date'],
                                    "scans": {k: v for k, v in result['scans'].items() if v['detected']}
                                }
                                await self.cache_result(url, 'virustotal', result_data)
                                return url, result_data
                            return url, {"error": "Not found in VirusTotal"}
                        return url, {"error": f"API error: {response.status}"}
                except Exception as e:
                    return url, {"error": str(e)}
        
        tasks = [check_single(url) for url in urls]
        results_list = await asyncio.gather(*tasks)
        return dict(results_list)

    async def check_urlscan_batch(self, urls, session, semaphore):
        """Batch submit URLs to URLScan.io and retrieve results with rate limiting"""
        results = {}
        async def check_single(url):
            async with semaphore:
                try:
                    if cached_result := await self.check_cache(url, 'urlscan'):
                        return url, cached_result
                    headers = {'API-Key': self.api_keys.get('urlscan', ''), 'Content-Type': 'application/json'}
                    data = {'url': url, 'visibility': 'public'}
                    async with session.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data) as response:
                        if response.status == 200:
                            result = await response.json()
                            scan_id = result['uuid']
                            await asyncio.sleep(10)
                            async with session.get(f'https://urlscan.io/api/v1/result/{scan_id}/') as result_response:
                                if result_response.status == 200:
                                    result_data = await result_response.json()
                                    result_dict = {
                                        "scan_id": scan_id,
                                        "page_url": result_data['page']['url'],
                                        "domain": result_data['page']['domain'],
                                        "screenshot_url": result_data['task']['screenshotURL']
                                    }
                                    await self.cache_result(url, 'urlscan', result_dict)
                                    return url, result_dict
                                return url, {"error": "Scan results not ready"}
                        return url, {"error": f"API error: {response.status}"}
                except Exception as e:
                    return url, {"error": str(e)}
        
        tasks = [check_single(url) for url in urls]
        results_list = await asyncio.gather(*tasks)
        return dict(results_list)

    async def check_cache(self, url, api_type):
        """Check if cached API result is valid"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT external_checks, external_checks_timestamp
                    FROM urls
                    WHERE url = ?
                ''', (url,))
                row = cursor.fetchone()
                if row and row[0]:
                    checks = json.loads(row[0])
                    timestamp = row[1]
                    if timestamp and (datetime.now() - datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")).total_seconds() < self.cache_ttl:
                        return checks.get(api_type)
                return None
        except Exception as e:
            self.log_error(f"Cache check error for {url}: {str(e)}")
            return None

    async def cache_result(self, url, api_type, result):
        """Cache API result in database"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT external_checks
                    FROM urls
                    WHERE url = ?
                ''', (url,))
                row = cursor.fetchone()
                checks = json.loads(row[0]) if row and row[0] else {}
                checks[api_type] = result
                cursor.execute('''
                    UPDATE urls
                    SET external_checks = ?, external_checks_timestamp = ?
                    WHERE url = ?
                ''', (json.dumps(checks), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), url))
                conn.commit()
        except Exception as e:
            self.log_error(f"Cache update error for {url}: {str(e)}")

    def check_virustotal(self):
        """Check selected URLs with VirusTotal API"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select URLs to check")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in selected]
        self.status_var.set(f"Checking {len(urls)} URLs with VirusTotal...")
        self.progress_var.set(0)
        
        def worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def async_worker():
                    semaphore = asyncio.Semaphore(4)  # VirusTotal limit: 4 requests/min
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=4)) as session:
                        results = await self.check_virustotal_batch(urls, session, semaphore)
                    self.root.after(0, lambda: self.display_virustotal_results(results))
                loop.run_until_complete(async_worker())
            finally:
                loop.close()
        
        threading.Thread(target=worker, daemon=True).start()

    def display_virustotal_results(self, results):
        """Display VirusTotal results in GUI"""
        self.status_var.set("Ready")
        self.progress_var.set(100)
        for url, result in results.items():
            if "error" in result:
                messagebox.showerror("Error", f"VirusTotal check failed for {url}: {result['error']}")
                continue
            details = f"VirusTotal Results for {url}:\n"
            details += f"Detection: {result['positives']}/{result['total']}\n"
            details += f"Last Scan: {result['scan_date']}\n"
            details += "\nScan Results:\n"
            for scanner, scan_result in result['scans'].items():
                details += f"{scanner}: {scan_result['result']}\n"
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
        self.log_info(f"Checked {len(results)} URLs with VirusTotal")

    def check_urlscan(self):
        """Check selected URLs with URLScan.io API"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select URLs to check")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in selected]
        self.status_var.set(f"Checking {len(urls)} URLs with URLScan.io...")
        self.progress_var.set(0)
        
        def worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def async_worker():
                    semaphore = asyncio.Semaphore(2)  # URLScan limit: 2 requests/min
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=2)) as session:
                        results = await self.check_urlscan_batch(urls, session, semaphore)
                    self.root.after(0, lambda: self.display_urlscan_results(results))
                loop.run_until_complete(async_worker())
            finally:
                loop.close()
        
        threading.Thread(target=worker, daemon=True).start()

    def display_urlscan_results(self, results):
        """Display URLScan.io results in GUI"""
        self.status_var.set("Ready")
        self.progress_var.set(100)
        for url, result in results.items():
            if "error" in result:
                messagebox.showerror("Error", f"URLScan check failed for {url}: {result['error']}")
                continue
            details = f"URLScan.io Results for {url}:\n"
            details += f"Scan ID: {result['scan_id']}\n"
            details += f"Page URL: {result['page_url']}\n"
            details += f"Domain: {result['domain']}\n"
            self.details_text.delete(1.0, tk.END)
            self.details_text.insert(tk.END, details)
            self.display_screenshot(result['screenshot_url'])
        self.log_info(f"Checked {len(results)} URLs with URLScan.io")

    def display_screenshot(self, url):
        """Display URL screenshot in a new window"""
        try:
            import requests
            response = requests.get(url, stream=True, timeout=10)
            if response.status_code == 200:
                img = Image.open(response.raw)
                img.thumbnail((600, 400))
                screenshot_window = tk.Toplevel(self.root)
                screenshot_window.title("URL Screenshot")
                photo = ImageTk.PhotoImage(img)
                label = tk.Label(screenshot_window, image=photo)
                label.image = photo
                label.pack()
            else:
                self.log_error(f"Failed to download screenshot: {response.status_code}")
        except Exception as e:
            self.log_error(f"Error displaying screenshot: {str(e)}")

    def extract_urls_from_text(self):
        """Extract URLs from text in the entry field"""
        text = self.url_entry.get()
        if not text:
            messagebox.showwarning("Warning", "Please enter text to extract URLs from")
            return
        
        self.url_entry.delete(0, tk.END)
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        urls = [url for url in re.findall(url_pattern, text) if validators.url(url)]
        
        if urls:
            self.process_urls(urls, is_auto_check=False)
        else:
            messagebox.showinfo("Info", "No valid URLs found in the text")

    def import_urls(self):
        """Import URLs from a file"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
            urls = [url for url in re.findall(url_pattern, content) if validators.url(url)]
            if urls:
                self.process_urls(urls, is_auto_check=False)
            else:
                messagebox.showwarning("Warning", "No valid URLs found in the file")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import URLs: {str(e)}")
            self.log_error(f"Import URLs error: {str(e)}")

    def process_urls(self, urls, is_auto_check=False):
        """Process a list of URLs"""
        self.status_var.set(f"Processing {len(urls)} URLs...")
        self.progress_var.set(0)
        
        # Clear queue and enqueue URLs
        while not self.url_queue.empty():
            self.url_queue.get()
        for url in urls:
            self.url_queue.put(url)
        
        def worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def async_worker():
                    async with aiohttp.ClientSession() as session:
                        total = self.url_queue.qsize()
                        processed = 0
                        while not self.url_queue.empty():
                            batch = []
                            for _ in range(min(self.batch_size, self.url_queue.qsize())):
                                batch.append(self.url_queue.get())
                            tasks = [self.process_single_url(url, session, processed + idx, total, is_auto_check) for idx, url in enumerate(batch)]
                            await asyncio.gather(*tasks)
                            processed += len(batch)
                            self.root.after(0, lambda: self.progress_var.set((processed / total) * 100))
                    self.root.after(0, lambda: self.status_var.set("Ready"))
                    self.root.after(0, lambda: self.progress_var.set(100))
                start_time = time.time()
                loop.run_until_complete(async_worker())
                self.log_info(f"Processed {len(urls)} URLs in {time.time() - start_time:.2f} seconds")
            except Exception as e:
                self.log_error(f"URL processing error: {str(e)}")
                self.root.after(0, lambda: self.status_var.set("Error occurred during processing"))
            finally:
                loop.close()
        
        threading.Thread(target=worker, daemon=True).start()

    async def process_single_url(self, url, session, idx, total, is_auto_check):
        """Process a single URL with enhanced status change handling"""
        start_time = time.time()
        existing = False
        current_status = None
        
        # Check if URL exists in tree
        for item in self.tree.get_children():
            if self.tree.item(item)['values'][0] == url:
                existing = True
                current_status = self.tree.item(item)['values'][1]
                break
        
        if existing and not is_auto_check:
            # Run askyesno synchronously in Tkinter's main thread
            def ask_recheck():
                return messagebox.askyesno("Confirm", f"URL {url} already exists. Re-check it?")
            recheck = self.root.after_idle(ask_recheck)
            if not recheck:
                return
        
        # Perform URL checks
        status, details = await self.check_url_async(url, session)
        redirect_chain = await self.trace_redirects_async(url, session)
        risk_level, risk_reasons = self.score_url_risk(url)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        url_data = {
            "url": url,
            "status": status,
            "last_checked": now,
            "risk_level": risk_level,
            "redirect_chain": json.dumps(redirect_chain),
            "external_checks": json.dumps({}),
            "external_checks_timestamp": now,
            "comments": ""
        }
        
        if existing:
            for item in self.tree.get_children():
                if self.tree.item(item)['values'][0] == url:
                    first_detected = self.tree.item(item)['values'][4]
                    old_status = self.tree.item(item)['values'][1]
                    old_risk = self.tree.item(item)['values'][2]
                    url_data["first_detected"] = first_detected
                    
                    # Update treeview
                    self.root.after(0, lambda: self.tree.item(item, values=(
                        url, status, risk_level, now, first_detected, self.tree.item(item)['values'][5]
                    )))
                    
                    # Handle status changes
                    if old_status != status:
                        message = f"Status changed for {url}: {old_status} → {status}"
                        if is_auto_check:
                            self.log_info(message)
                            if self.email_notifications_enabled:
                                # Only send email for significant changes
                                if (old_status == "Active" and status != "Active") or \
                                   (old_status != "Active" and status == "Active"):
                                    subject_prefix = "URGENT" if status == "Active" else "INFO"
                                    asyncio.create_task(
                                        self.send_email_notification(
                                            f"Phishing URL status change detected!\n\n{message}\n\nCurrent risk level: {risk_level}",
                                            subject_prefix
                                        )
                                    )
                        else:
                            self.root.after(0, lambda: self.show_notification(message))
                    
                    # Handle risk level changes
                    if old_risk != risk_level:
                        message = f"Risk level changed for {url}: {old_risk} → {risk_level}"
                        self.log_info(message)
                        if is_auto_check and self.email_notifications_enabled and risk_level == "High":
                            asyncio.create_task(
                                self.send_email_notification(
                                    f"Risk level increased for URL!\n\n{message}\n\nCurrent status: {status}",
                                    "WARNING"
                                )
                            )
                    break
            self.update_url_in_db(url, url_data)
        else:
            url_data["first_detected"] = now
            self.root.after(0, lambda: self.tree.insert("", tk.END, values=(
                url, status, risk_level, now, now, ""
            )))
            self.add_url_to_db(url_data)
        
        self.root.after(0, lambda: self.apply_risk_coloring())
        self.log_info(f"URL checked: {url}, Status: {status}, Risk: {risk_level}, Time: {time.time() - start_time:.2f}s")

    def add_url_to_db(self, url_data):
        """Add URL data to SQLite database"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO urls (url, status, last_checked, first_detected, risk_level, redirect_chain, external_checks, external_checks_timestamp, comments)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    url_data["url"],
                    url_data["status"],
                    url_data["last_checked"],
                    url_data["first_detected"],
                    url_data["risk_level"],
                    url_data["redirect_chain"],
                    url_data["external_checks"],
                    url_data["external_checks_timestamp"],
                    url_data["comments"]
                ))
                conn.commit()
        except Exception as e:
            self.log_error(f"Database error (add_url_to_db): {str(e)}")

    def update_url_in_db(self, url, update_data):
        """Update URL data in SQLite database"""
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                set_clause = ", ".join([f"{key} = ?" for key in update_data.keys()])
                cursor.execute(f'''
                    UPDATE urls
                    SET {set_clause}
                    WHERE url = ?
                ''', (*update_data.values(), url))
                conn.commit()
        except Exception as e:
            self.log_error(f"Database error (update_url_in_db): {str(e)}")

    def delete_selected_urls(self):
        """Delete selected URLs from Treeview and database"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select URLs to delete")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in selected]
        if not messagebox.askyesno("Confirm", f"Delete {len(urls)} selected URLs?"):
            return
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                for url in urls:
                    items = [item for item in self.tree.get_children() if self.tree.item(item)['values'][0] == url]
                    if items:
                        self.root.after(0, lambda item=items[0]: self.tree.delete(item))
                    cursor.execute("DELETE FROM urls WHERE url = ?", (url,))
                    self.log_info(f"URL deleted: {url}")
                conn.commit()
            self.root.after(0, lambda: self.status_var.set(f"Deleted {len(urls)} URLs"))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to delete URLs: {str(e)}"))
            self.log_error(f"Error deleting URLs: {str(e)}")

    def load_history(self):
        """Load URL history from database"""
        try:
            self.root.after(0, lambda: self.tree.delete(*self.tree.get_children()))
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT url, status, risk_level, last_checked, first_detected, comments
                    FROM urls
                    ORDER BY last_checked DESC
                ''')
                for row in cursor.fetchall():
                    self.root.after(0, lambda r=row: self.tree.insert("", tk.END, values=r))
            self.root.after(0, self.apply_risk_coloring)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to load history: {str(e)}"))
            self.log_error(f"Load history error: {str(e)}")

    def apply_risk_coloring(self):
        """Apply color coding based on risk level with inactive handling"""
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            risk_level = values[2]
            status = values[1]
            
            # Use inactive color for inactive URLs regardless of risk level
            if status in ["Inactive", "Error", "Timeout", "Unreachable", "Invalid"]:
                self.tree.tag_configure("Inactive", background=self.risk_colors.get("Inactive", "#e6e6e6"))
                self.tree.item(item, tags=("Inactive",))
            else:
                self.tree.tag_configure(risk_level, background=self.risk_colors.get(risk_level, "#ffffff"))
                self.tree.item(item, tags=(risk_level,))

    def show_url_details(self, event):
        """Show details for selected URL"""
        selected = self.tree.selection()
        if not selected:
            return
        
        url = self.tree.item(selected[0])['values'][0]
        try:
            with sqlite3.connect(self.db_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT url, status, risk_level, last_checked, first_detected, redirect_chain, external_checks, comments
                    FROM urls
                    WHERE url = ?
                ''', (url,))
                row = cursor.fetchone()
            
            if row:
                details = f"URL: {row[0]}\n"
                details += f"Status: {row[1]}\n"
                details += f"Risk Level: {row[2]}\n"
                details += f"Last Checked: {row[3]}\n"
                details += f"First Detected: {row[4]}\n"
                details += "\nRedirect Chain:\n"
                redirect_chain = json.loads(row[5])
                for step in redirect_chain:
                    details += f"-> {step['url']} ({step['status']})\n"
                details += f"\nComments:\n{row[7]}\n"
                self.root.after(0, lambda: self.details_text.delete(1.0, tk.END))
                self.root.after(0, lambda: self.details_text.insert(tk.END, details))
        except Exception as e:
            self.log_error(f"Error showing URL details: {str(e)}")

    def check_single_url(self):
        """Check a single URL from the entry field"""
        url = self.url_entry.get().strip()
        if not url or not validators.url(url):
            messagebox.showwarning("Warning", "Please enter a valid URL")
            return
        
        self.url_entry.delete(0, tk.END)
        self.process_urls([url], is_auto_check=False)

    def recheck_selected(self):
        """Re-check selected URLs"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select URLs to re-check")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in selected]
        self.process_urls(urls, is_auto_check=False)

    def recheck_all(self):
        """Re-check all URLs"""
        if not self.tree.get_children():
            messagebox.showwarning("Warning", "No URLs to re-check")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in self.tree.get_children()]
        self.process_urls(urls, is_auto_check=False)

    def remove_inactive_urls(self):
        """Remove only very old inactive URLs based on threshold"""
        inactive_statuses = ["Inactive", "Error", "Timeout", "Unreachable", "Invalid"]
        threshold_date = (datetime.now() - timedelta(days=self.inactive_threshold)).strftime("%Y-%m-%d %H:%M:%S")
        
        to_remove = []
        for item in self.tree.get_children():
            if (self.tree.item(item)['values'][1] in inactive_statuses and 
                self.tree.item(item)['values'][3] < threshold_date):
                to_remove.append(item)
        
        if not to_remove:
            messagebox.showinfo("Info", f"No inactive URLs older than {self.inactive_threshold} days found")
            return
        
        if messagebox.askyesno("Confirm", f"Remove {len(to_remove)} inactive URLs older than {self.inactive_threshold} days?"):
            try:
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    for item in to_remove:
                        url = self.tree.item(item)['values'][0]
                        self.root.after(0, lambda: self.tree.delete(item))
                        cursor.execute("DELETE FROM urls WHERE url = ?", (url,))
                        self.log_info(f"URL removed: {url}")
                        if self.email_notifications_enabled:
                            asyncio.create_task(
                                self.send_email_notification(
                                    f"Removed inactive URL (older than {self.inactive_threshold} days):\n\n{url}",
                                    "CLEANUP"
                                )
                            )
                    conn.commit()
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to remove inactive URLs: {str(e)}"))
                self.log_error(f"Error removing URLs: {str(e)}")

    def toggle_auto_check(self):
        """Toggle automatic checking of URLs"""
        if self.auto_check_running:
            self.auto_check_running = False
            self.root.after(0, lambda: self.status_var.set("Auto-check stopped"))
            self.root.after(0, lambda: messagebox.showinfo("Info", "Auto-check stopped"))
            self.log_info("Auto-check stopped")
        else:
            self.auto_check_running = True
            threading.Thread(target=self.auto_check_loop, daemon=True).start()
            self.root.after(0, lambda: self.status_var.set("Auto-check started"))
            self.root.after(0, lambda: messagebox.showinfo("Info", "Auto-check started. Running every 2 hours."))
            self.log_info("Auto-check started")

    def toggle_auto_remove(self):
        """Toggle automatic removal of inactive URLs"""
        self.auto_remove_inactive = not self.auto_remove_inactive
        status = "ON" if self.auto_remove_inactive else "OFF"
        self.root.after(0, lambda: self.status_var.set(f"Auto-remove inactive URLs: {status}"))
        self.root.after(0, lambda: messagebox.showinfo("Info", f"Auto-remove inactive URLs: {status}"))
        self.log_info(f"Auto-remove set to {status}")

    def toggle_email_notifications(self):
        """Toggle email notifications for status changes"""
        self.email_notifications_enabled = not self.email_notifications_enabled
        status = "ON" if self.email_notifications_enabled else "OFF"
        self.root.after(0, lambda: self.status_var.set(f"Email notifications: {status}"))
        self.root.after(0, lambda: messagebox.showinfo("Info", f"Email notifications: {status}"))
        self.log_info(f"Email notifications set to {status}")

    async def send_email_notification(self, message, subject_prefix="ALERT"):
        """Enhanced email notification with HTML formatting and error handling"""
        if not self.email_notifications_enabled or not self.smtp_config.get("host"):
            return False
        
        try:
            # Create message container
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f'[{subject_prefix}] Phishing URL Status Change'
            msg['From'] = f'{self.smtp_config.get("from_name", "Phishing Monitor")} <{self.smtp_config.get("user", "")}>'
            msg['To'] = self.smtp_config.get('recipient', '')
            
            # Create HTML version
            html = f"""\
            <html>
              <head></head>
              <body>
                <h2>Phishing URL Checker Notification</h2>
                <p>{message.replace('\n', '<br>')}</p>
                <hr>
                <p>Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
              </body>
            </html>
            """
            
            # Record the MIME types
            part = MIMEText(html, 'html')
            msg.attach(part)
            
            # Send the message via SMTP server
            port = int(self.smtp_config.get('port', 465))
            with smtplib.SMTP_SSL(self.smtp_config.get('host', ''), port) as server:
                server.login(self.smtp_config.get('user', ''), self.smtp_config.get('password', ''))
                server.send_message(msg)
            
            self.log_info(f"Email notification sent: {message}")
            return True
        except smtplib.SMTPException as e:
            self.log_error(f"SMTP error sending email: {str(e)}")
        except Exception as e:
            self.log_error(f"Failed to send email notification: {str(e)}")
        return False

    def auto_check_loop(self):
        """Optimized auto-check loop with better error handling"""
        while self.auto_check_running:
            try:
                if self.tree.get_children():
                    urls = [self.tree.item(item)['values'][0] for item in self.tree.get_children()]
                    self.process_urls(urls, is_auto_check=True)
                    
                    # Only remove inactive URLs if enabled and not during initial checks
                    if self.auto_remove_inactive and self.auto_check_running:
                        self.remove_inactive_urls()
                
                # Sleep in smaller intervals to allow quicker shutdown
                for _ in range(self.check_interval):
                    if not self.auto_check_running:
                        break
                    time.sleep(1)
            except Exception as e:
                self.log_error(f"Auto-check loop error: {str(e)}")
                # Try to send email notification about the error
                if self.email_notifications_enabled:
                    asyncio.create_task(
                        self.send_email_notification(
                            f"Auto-check loop encountered an error:\n\n{str(e)}\n\nTrying to continue...",
                            "ERROR"
                        )
                    )
                time.sleep(60)  # Wait before retrying to prevent tight loop on failure

    def export_history(self, format_type):
        """Export history to CSV or JSON file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[(f"{format_type.upper()} Files", f"*.{format_type}"), ("All Files", "*.*")],
            initialfile=f"phishing_url_history.{format_type}"
        )
        
        if not file_path:
            return
        
        try:
            if format_type == "csv":
                with open(file_path, mode='w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["URL", "Status", "Risk Level", "Last Checked", "First Detected", "Comments"])
                    for item in self.tree.get_children():
                        writer.writerow(self.tree.item(item)['values'])
            else:  # JSON
                data = [
                    {
                        "URL": self.tree.item(item)['values'][0],
                        "Status": self.tree.item(item)['values'][1],
                        "Risk Level": self.tree.item(item)['values'][2],
                        "Last Checked": self.tree.item(item)['values'][3],
                        "First Detected": self.tree.item(item)['values'][4],
                        "Comments": self.tree.item(item)['values'][5]
                    }
                    for item in self.tree.get_children()
                ]
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            
            self.root.after(0, lambda: messagebox.showinfo("Success", f"History exported to {file_path}"))
            self.log_info(f"Exported history to {file_path}")
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to export history: {str(e)}"))
            self.log_error(f"Export error: {str(e)}")

    def add_comment(self):
        """Add comment to selected URL"""
        selected = self.tree.selection()
        if not selected or len(selected) > 1:
            messagebox.showwarning("Warning", "Please select a single URL to add a comment")
            return
        
        item = selected[0]
        current_comment = self.tree.item(item)['values'][5]
        comment = tk.simpledialog.askstring("Add Comment", "Enter your comment:", initialvalue=current_comment)
        if comment is not None:
            values = list(self.tree.item(item)['values'])
            values[5] = comment
            self.root.after(0, lambda: self.tree.item(item, values=values))
            url = values[0]
            try:
                with sqlite3.connect(self.db_file) as conn:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE urls SET comments = ? WHERE url = ?", (comment, url))
                    conn.commit()
                self.log_info(f"Comment added to URL: {url}")
            except Exception as e:
                self.log_error(f"Error updating comment: {str(e)}")

    def report_to_cert(self):
        """Report selected URLs to CERT"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select URLs to report")
            return
        
        urls = [self.tree.item(item)['values'][0] for item in selected]
        report_text = "\n".join(urls)
        self.root.after(0, lambda: messagebox.showinfo(
            "Report to CERT",
            f"The following URLs will be reported:\n\n{report_text}\n\n"
            "In a real implementation, this would be sent to your CERT contact."
        ))
        self.log_info(f"Reported URLs to CERT: {', '.join(urls)}")

    def trace_selected_redirects(self):
        """Trace redirects for selected URL"""
        selected = self.tree.selection()
        if not selected or len(selected) > 1:
            messagebox.showwarning("Warning", "Please select a single URL to trace redirects")
            return
        
        url = self.tree.item(selected[0])['values'][0]
        self.status_var.set(f"Tracing redirects for {url}...")
        self.progress_var.set(0)
        
        def worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def async_worker():
                    async with aiohttp.ClientSession() as session:
                        redirect_chain = await self.trace_redirects_async(url, session)
                    self.root.after(0, lambda: self.display_redirects(url, redirect_chain))
                loop.run_until_complete(async_worker())
            finally:
                loop.close()
        
        threading.Thread(target=worker, daemon=True).start()

    def display_redirects(self, url, redirect_chain):
        """Display redirect chain in GUI"""
        self.status_var.set("Ready")
        self.progress_var.set(100)
        details = f"Redirect chain for {url}:\n\n"
        for i, step in enumerate(redirect_chain, 1):
            details += f"{i}. {step['url']} ({step['status']})\n"
            if step.get('headers'):
                details += "   Headers:\n"
                for key, value in step['headers'].items():
                    if key.lower() in ['location', 'server', 'content-type']:
                        details += f"   - {key}: {value}\n"
            details += "\n"
        self.root.after(0, lambda: self.details_text.delete(1.0, tk.END))
        self.root.after(0, lambda: self.details_text.insert(tk.END, details))
        self.update_url_in_db(url, {'redirect_chain': json.dumps(redirect_chain)})

    def analyze_risk_selected(self):
        """Analyze risk for selected URL"""
        selected = self.tree.selection()
        if not selected or len(selected) > 1:
            messagebox.showwarning("Warning", "Please select a single URL to analyze risk")
            return
        
        url = self.tree.item(selected[0])['values'][0]
        risk_level, risk_reasons = self.score_url_risk(url)
        details = f"Risk analysis for {url}:\n\n"
        details += f"Risk Level: {risk_level}\n"
        details += "Risk Factors:\n"
        details += "\n".join(f"- {reason}" for reason in risk_reasons)
        self.root.after(0, lambda: self.details_text.delete(1.0, tk.END))
        self.root.after(0, lambda: self.details_text.insert(tk.END, details))
        
        for item in self.tree.get_children():
            if self.tree.item(item)['values'][0] == url:
                values = list(self.tree.item(item)['values'])
                values[2] = risk_level
                self.root.after(0, lambda: self.tree.item(item, values=values))
                break
        
        self.update_url_in_db(url, {'risk_level': risk_level})
        self.root.after(0, self.apply_risk_coloring)

    def show_notification(self, message):
        """Show notification about URL status change (non-auto-check only)"""
        top = tk.Toplevel(self.root)
        top.title("Status Change Notification")
        top.geometry("400x150")
        ttk.Label(top, text=message, wraplength=380, padding=10).pack(pady=10)
        ttk.Button(top, text="OK", command=top.destroy).pack(pady=5)
        self.log_info(f"Status change notification: {message}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingURLChecker(root)
    root.mainloop()
