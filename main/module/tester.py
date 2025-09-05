import asyncio
import base64
import json
import subprocess
import tempfile
import os
import time
import sys
import logging
import socket
import random
import hashlib
import shutil
import datetime
from urllib.parse import unquote, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from enum import Enum
import ipaddress
import threading
from queue import Queue, Empty
import signal
import math
import uuid
import warnings

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    import requests
    # Try to import PySocks for SOCKS5 support
    try:
        import socks
        HAS_SOCKS = True
    except ImportError:
        HAS_SOCKS = False
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    HAS_SOCKS = False

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def setup_logging():
    """Setup dual logging with clean console output and detailed file logging"""
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_formatter = logging.Formatter('%(message)s')

    file_handler = logging.FileHandler('../log/proxy_tester.log', encoding='utf-8')
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


if sys.platform.startswith('win'):
    try:
        os.system('chcp 65001 >nul 2>&1')
    except:
        pass

logger = setup_logging()

_unsupported_methods = set()


class TestResult(Enum):
    SUCCESS = "success"
    PARSE_ERROR = "parse_error"
    SYNTAX_ERROR = "syntax_error"
    CONNECTION_ERROR = "connection_error"
    TIMEOUT = "timeout"
    PORT_CONFLICT = "port_conflict"
    INVALID_CONFIG = "invalid_config"
    NETWORK_ERROR = "network_error"
    HANG_TIMEOUT = "hang_timeout"
    PROCESS_KILLED = "process_killed"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"


class ProxyProtocol(Enum):
    SHADOWSOCKS = "shadowsocks"
    VMESS = "vmess"
    VLESS = "vless"


@dataclass
class ProxyConfig:
    protocol: ProxyProtocol
    server: str
    port: int
    remarks: str = ""

    # Protocol-specific fields
    # Shadowsocks
    method: str = ""
    password: str = ""

    # VMess
    uuid: str = ""
    alterId: int = 0
    cipher: str = "auto"

    # VLESS
    flow: str = ""
    encryption: str = "none"

    # Common transport settings
    network: str = "tcp"
    tls: str = ""
    sni: str = ""
    path: str = ""
    host: str = ""
    alpn: str = ""
    fingerprint: str = ""
    headerType: str = ""
    serviceName: str = ""

    # Additional fields
    raw_config: Dict[str, Any] = field(default_factory=dict)
    config_id: Optional[int] = None
    line_number: Optional[int] = None

    def __post_init__(self):
        if not self.is_valid():
            raise ValueError(f"Invalid proxy configuration: {self}")

    def is_valid(self) -> bool:
        """Enhanced validation for all protocols"""
        # Common validation
        if not (1 <= self.port <= 65535):
            return False

        if not self._is_valid_address(self.server):
            return False

        # Protocol-specific validation
        if self.protocol == ProxyProtocol.SHADOWSOCKS:
            return self._validate_shadowsocks()
        elif self.protocol == ProxyProtocol.VMESS:
            return self._validate_vmess()
        elif self.protocol == ProxyProtocol.VLESS:
            return self._validate_vless()

        return False

    def _validate_shadowsocks(self) -> bool:
        """Validate Shadowsocks configuration"""
        valid_methods = {
            'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305',
            'aes-128-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-256-ctr',
            'chacha20', 'chacha20-ietf', 'chacha20-ietf-poly1305',
            'rc4-md5', 'aes-256-ocb', 'xchacha20-poly1305',
            '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
            '2022-blake3-chacha20-poly1305'
        }

        if self.method.lower() not in valid_methods:
            _unsupported_methods.add(self.method)
            logger.debug(f"Potentially unsupported method: {self.method}")

        if not self.password or len(self.password) < 1:
            return False

        return True

    def _validate_vmess(self) -> bool:
        """Validate VMess configuration"""
        if not self.uuid:
            return False

        try:
            # Validate UUID format
            uuid.UUID(self.uuid)
        except ValueError:
            return False

        if self.alterId < 0:
            return False

        return True

    def _validate_vless(self) -> bool:
        """Validate VLESS configuration"""
        if not self.uuid:
            return False

        try:
            # Validate UUID format
            uuid.UUID(self.uuid)
        except ValueError:
            return False

        return True

    def _is_valid_address(self, address: str) -> bool:
        """Validate IP address or domain name"""
        # Remove IPv6 brackets if present
        clean_address = address.strip('[]')

        try:
            ipaddress.ip_address(clean_address)
            return True
        except ValueError:
            # Validate domain name format
            if len(clean_address) > 253 or not clean_address:
                return False

            # Check if it's a valid domain name
            if clean_address.startswith('.') or clean_address.endswith('.'):
                return False

            if '..' in clean_address:
                return False

            # Split into labels and validate each
            labels = clean_address.split('.')
            if len(labels) < 2:  # At least domain.tld
                return False

            for label in labels:
                if not label or len(label) > 63:
                    return False
                if label.startswith('-') or label.endswith('-'):
                    return False
                if not all(c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in label):
                    return False

            return True

    def get_hash(self) -> str:
        """Generate unique hash for configuration"""
        if self.protocol == ProxyProtocol.SHADOWSOCKS:
            config_str = f"ss://{self.server}:{self.port}:{self.method}:{self.password}"
        elif self.protocol == ProxyProtocol.VMESS:
            config_str = f"vmess://{self.server}:{self.port}:{self.uuid}:{self.alterId}:{self.network}"
        elif self.protocol == ProxyProtocol.VLESS:
            config_str = f"vless://{self.server}:{self.port}:{self.uuid}:{self.network}"
        else:
            config_str = f"{self.protocol.value}://{self.server}:{self.port}"

        return hashlib.md5(config_str.encode()).hexdigest()


@dataclass
class TestResultData:
    config: ProxyConfig
    result: TestResult
    test_time: float
    response_time: Optional[float] = None
    error_message: str = ""
    external_ip: Optional[str] = None
    proxy_port: Optional[int] = None
    batch_id: Optional[int] = None

    def to_dict(self) -> Dict:
        result_dict = asdict(self)
        result_dict['result'] = self.result.value
        result_dict['protocol'] = self.config.protocol.value
        # Convert ProxyProtocol enum to string in config
        if 'config' in result_dict and 'protocol' in result_dict['config']:
            if hasattr(result_dict['config']['protocol'], 'value'):
                result_dict['config']['protocol'] = result_dict['config']['protocol'].value
        return result_dict


class ProcessManager:
    """Enhanced process management with forced cleanup"""

    def __init__(self):
        self.active_processes: Dict[int, subprocess.Popen] = {}
        self.lock = threading.Lock()
        self.cleanup_thread = None
        self.running = False

    def start_monitoring(self):
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.cleanup_thread.start()

    def stop_monitoring(self):
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=1)
        self._cleanup_all_processes()

    def register_process(self, process: subprocess.Popen):
        with self.lock:
            self.active_processes[process.pid] = process

    def unregister_process(self, process: subprocess.Popen):
        with self.lock:
            self.active_processes.pop(process.pid, None)

    def _monitor_processes(self):
        """Monitor and clean up zombie processes"""
        while self.running:
            time.sleep(2)
            with self.lock:
                dead_pids = []
                for pid, process in list(self.active_processes.items()):
                    if process.poll() is not None:
                        dead_pids.append(pid)

                for pid in dead_pids:
                    self.active_processes.pop(pid, None)

    def _cleanup_all_processes(self):
        """Force cleanup all active processes"""
        with self.lock:
            for pid, process in list(self.active_processes.items()):
                try:
                    self._force_kill_process(process)
                except:
                    pass
            self.active_processes.clear()

    def _force_kill_process(self, process: subprocess.Popen):
        """Force kill process with all children"""
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=0.3)
                    return
                except subprocess.TimeoutExpired:
                    pass

                process.kill()
                process.wait(timeout=0.3)

                if sys.platform.startswith('win'):
                    try:
                        subprocess.run(['taskkill', '/F', '/T', '/PID', str(process.pid)],
                                       capture_output=True, timeout=3, encoding='utf-8', errors='ignore')
                    except:
                        pass
        except:
            pass


class FastPortManager:
    """Optimized port management with pre-validated pool"""

    def __init__(self, start_port: int = 10000, end_port: int = 20000):
        self.start_port = start_port
        self.end_port = end_port
        self.available_ports = Queue()
        self.used_ports = set()
        self.lock = threading.Lock()
        self._initialize_port_pool()

    def _initialize_port_pool(self):
        """Initialize port pool with validated ports"""
        logger.info(f"Initializing fast port pool ({self.start_port}-{self.end_port})...")

        chunk_size = 100
        available_count = 0

        for start in range(self.start_port, self.end_port + 1, chunk_size):
            end = min(start + chunk_size, self.end_port + 1)
            for port in range(start, end):
                if self._is_port_available_fast(port):
                    self.available_ports.put(port)
                    available_count += 1

        logger.info(f"Fast port pool initialized with {available_count} available ports")

    def _is_port_available_fast(self, port: int) -> bool:
        """Fast port availability check"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.05)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))
                return True
        except OSError:
            return False

    def get_available_port(self, timeout: float = 0.1) -> Optional[int]:
        """Get available port with short timeout"""
        try:
            port = self.available_ports.get(timeout=timeout)
            with self.lock:
                self.used_ports.add(port)
            return port
        except Empty:
            return self._find_emergency_port()

    def _find_emergency_port(self) -> Optional[int]:
        """Emergency port finding when pool is empty"""
        sample_size = min(100, self.end_port - self.start_port + 1)
        port_sample = random.sample(range(self.start_port, self.end_port + 1), sample_size)

        with self.lock:
            for port in port_sample:
                if port not in self.used_ports and self._is_port_available_fast(port):
                    self.used_ports.add(port)
                    return port
        return None

    def release_port(self, port: int):
        """Release port back to pool"""
        with self.lock:
            self.used_ports.discard(port)

        def return_port():
            time.sleep(0.02)
            try:
                self.available_ports.put(port)
            except:
                pass

        threading.Timer(0.02, return_port).start()


class FastNetworkTester:
    """Optimized network tester with connection pooling"""

    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=20,
                pool_maxsize=100,
                max_retries=0
            )
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

        # More reliable test URLs with fallbacks
        self.test_urls = [
            'http://httpbin.org/ip',
            'http://icanhazip.com',
            'http://ifconfig.me/ip',
            'http://api.ipify.org',
            'http://ipinfo.io/ip',
            'http://checkip.amazonaws.com',
            'https://httpbin.org/ip',
            'https://icanhazip.com',
            'https://ifconfig.me/ip',
            'https://api.ipify.org'
        ]

    def test_proxy_connection(self, proxy_port: int) -> Tuple[bool, Optional[str], float]:
        """Test proxy connection with multiple fallback URLs"""
        start_time = time.time()

        # First check if the proxy port is responsive
        if not self._is_proxy_responsive(proxy_port):
            return False, None, time.time() - start_time

        # Try more URLs for better success rate
        test_url_count = min(8, len(self.test_urls))  # Increased from 4 to 8
        for test_url in random.sample(self.test_urls, test_url_count):
            try:
                success, ip, response_time = self._single_test(proxy_port, test_url)
                if success:
                    return True, ip, response_time
            except Exception as e:
                logger.debug(f"Test with {test_url} failed: {e}")
                continue

        return False, None, time.time() - start_time

    def _is_proxy_responsive(self, port: int) -> bool:
        """Quick proxy responsiveness check"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)  # Increased from 0.05 to 2.0 seconds
                result = s.connect_ex(('127.0.0.1', port))
                return result == 0
        except:
            return False

    def _single_test(self, proxy_port: int, test_url: str) -> Tuple[bool, Optional[str], float]:
        """Test a single URL through the proxy"""
        # Shadowsocks creates SOCKS5 proxies, not HTTP proxies
        proxies = {
            'http': f'socks5://127.0.0.1:{proxy_port}',
            'https': f'socks5://127.0.0.1:{proxy_port}'
        }

        start_time = time.time()

        try:
            if self.session:
                response = self.session.get(
                    test_url,
                    proxies=proxies,
                    timeout=self.timeout,
                    verify=False  # Disable SSL verification for testing
                )
                response_time = time.time() - start_time

                if response.status_code == 200:
                    # Try to extract IP from response
                    ip_text = response.text.strip()

                    # Handle JSON responses
                    if 'application/json' in response.headers.get('content-type', ''):
                        try:
                            data = response.json()
                            ip_text = data.get('origin', data.get('ip', ip_text))
                        except:
                            pass

                    # Validate IP format
                    try:
                        # Check if it looks like an IP address
                        if '.' in ip_text and len(ip_text.split('.')) == 4:
                            return True, ip_text, response_time
                        elif ':' in ip_text:  # IPv6
                            return True, ip_text, response_time
                    except:
                        pass

                    return False, None, response_time

            return False, None, time.time() - start_time

        except requests.exceptions.RequestException:
            return False, None, time.time() - start_time
        except Exception:
            return False, None, time.time() - start_time


class OptimizedHangDetector:
    """Improved hang detection with faster response"""

    def __init__(self, max_hang_time: float = 12.0):
        self.max_hang_time = max_hang_time
        self.active_operations = {}
        self.lock = threading.Lock()
        self.monitor_thread = None
        self.running = False
        self.hang_callbacks = {}

    def start_monitoring(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_hangs, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)

    def register_operation(self, op_id: str, callback=None):
        with self.lock:
            self.active_operations[op_id] = time.time()
            if callback:
                self.hang_callbacks[op_id] = callback

    def unregister_operation(self, op_id: str):
        with self.lock:
            self.active_operations.pop(op_id, None)
            self.hang_callbacks.pop(op_id, None)

    def _monitor_hangs(self):
        """Monitor for hanging operations with callbacks"""
        while self.running:
            current_time = time.time()
            hanging_ops = []

            with self.lock:
                for op_id, start_time in list(self.active_operations.items()):
                    if current_time - start_time > self.max_hang_time:
                        hanging_ops.append(op_id)

            for op_id in hanging_ops:
                callback = self.hang_callbacks.get(op_id)
                if callback:
                    try:
                        callback()
                    except:
                        pass
                self.unregister_operation(op_id)

            if hanging_ops:
                logger.warning(f"🧹 Cleaned up {len(hanging_ops)} hanging operations")

            time.sleep(2)


class EnhancedProxyTester:
    """Enhanced multi-protocol proxy tester"""

    def __init__(self,
                 xray_path: Optional[str] = None,
                 max_workers: int = 1000,  # Reduced from 500 to prevent system overload
                 timeout: int = 15,  # Increased timeout for better success rate
                 port_range: Tuple[int, int] = (10000, 20000),
                 batch_size: int = 1000,  # Reduced from 500
                 incremental_save: bool = True,
                 incremental_files: Dict[str, str] = None):

        self.xray_path = xray_path or self._find_xray_executable()
        self.max_workers = max_workers
        self.timeout = timeout
        self.batch_size = batch_size
        self.incremental_save = incremental_save
        self.incremental_files = incremental_files or {
            'shadowsocks': '../data/working_json/working_shadowsocks.txt',
            'vmess': '../data/working_json/working_vmess.txt',
            'vless': '../data/working_json/working_vless.txt'
        }

        # URL format files
        self.url_files = {
            'shadowsocks': '../data/working_url/working_shadowsocks_urls.txt',
            'vmess': '../data/working_url/working_vmess_urls.txt',
            'vless': '../data/working_url/working_vless_urls.txt'
        }

        # File handles for immediate writing
        self.output_file_handles = {}
        self.url_file_handles = {}

        # Initialize optimized managers
        self.port_manager = FastPortManager(port_range[0], port_range[1])
        self.process_manager = ProcessManager()
        self.hang_detector = OptimizedHangDetector(max_hang_time=12.0)
        self.network_tester = FastNetworkTester(timeout)

        # Check for SOCKS5 support
        if not HAS_SOCKS:
            logger.warning("⚠️  PySocks library not found. SOCKS5 support may be limited.")
            logger.warning("   Install with: pip install PySocks")
            logger.warning("   This may significantly affect shadowsocks testing success rate.")

        self._validate_xray()

        # Results storage
        self.results: List[TestResultData] = []
        self.results_lock = threading.Lock()

        if self.incremental_save:
            self._setup_incremental_save()

        # Enhanced statistics
        self.stats = {
            'total': 0, 'success': 0, 'failed': 0, 'parse_errors': 0,
            'syntax_errors': 0, 'connection_errors': 0, 'timeouts': 0,
            'hang_timeouts': 0, 'process_killed': 0,
            'shadowsocks': {'total': 0, 'success': 0, 'failed': 0},
            'vmess': {'total': 0, 'success': 0, 'failed': 0},
            'vless': {'total': 0, 'success': 0, 'failed': 0}
        }

        logger.info(f"Enhanced tester initialized: {max_workers} workers, batch size: {batch_size}")
        if self.incremental_save:
            logger.info(f"🔄 Incremental save enabled")

    def __del__(self):
        """Destructor to ensure files are closed"""
        try:
            self._close_incremental_files()
        except:
            pass

    def _setup_incremental_save(self):
        """Setup incremental save files with immediate writing"""
        try:
            # Setup JSON format files
            for protocol, filename in self.incremental_files.items():
                # Create/clear the file and keep handle open
                f = open(filename, 'w', encoding='utf-8')
                f.write(f"# Working {protocol.upper()} Configurations (JSON Format)\n")
                f.write(f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: Each line contains one working_url configuration in JSON\n\n")
                f.flush()
                self.output_file_handles[protocol] = f

            # Setup URL format files
            for protocol, filename in self.url_files.items():
                f = open(filename, 'w', encoding='utf-8')
                f.write(f"# Working {protocol.upper()} Configurations (URL Format)\n")
                f.write(f"# Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: Each line contains one working_url configuration as URL\n\n")
                f.flush()
                self.url_file_handles[protocol] = f

            logger.info(f"🔄 Incremental save files initialized (JSON + URL formats)")
        except Exception as e:
            logger.error(f"❌ Failed to setup incremental save files: {e}")
            self.incremental_save = False

    def _save_config_immediately(self, result: 'TestResultData'):
        """Save a successful config immediately to both JSON and URL format files"""
        if not self.incremental_save or result.result != TestResult.SUCCESS:
            return

        try:
            protocol = result.config.protocol.value
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

            # Save JSON format
            if protocol in self.output_file_handles:
                file_handle = self.output_file_handles[protocol]
                config_line = self._create_working_config_line(result)

                file_handle.write(
                    f"# Tested at: {timestamp} | Response: {result.response_time:.3f}s | IP: {result.external_ip}\n")
                file_handle.write(f"{config_line}\n\n")
                file_handle.flush()

            # Save URL format
            if protocol in self.url_file_handles:
                url_handle = self.url_file_handles[protocol]
                config_url = self._create_config_url(result)

                url_handle.write(
                    f"# Tested at: {timestamp} | Response: {result.response_time:.3f}s | IP: {result.external_ip}\n")
                url_handle.write(f"{config_url}\n\n")
                url_handle.flush()

        except Exception as e:
            logger.error(f"❌ Failed to save config immediately: {e}")

    def _create_working_config_line(self, result: 'TestResultData') -> str:
        """Create a working_url config line for immediate saving"""
        config = result.config

        # Create a compact but complete representation
        if config.protocol == ProxyProtocol.SHADOWSOCKS:
            return json.dumps({
                'protocol': 'shadowsocks',
                'server': config.server,
                'port': config.port,
                'method': config.method,
                'password': config.password,
                'network': config.network or 'tcp',
                'tls': config.tls,
                'remarks': config.remarks,
                'test_time': result.response_time,
                'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))

        elif config.protocol == ProxyProtocol.VMESS:
            return json.dumps({
                'protocol': 'vmess',
                'server': config.server,
                'port': config.port,
                'uuid': config.uuid,
                'alterId': config.alterId,
                'cipher': config.cipher,
                'network': config.network or 'tcp',
                'path': config.path,
                'host': config.host,
                'tls': config.tls,
                'sni': config.sni,
                'remarks': config.remarks,
                'test_time': result.response_time,
                'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))

        elif config.protocol == ProxyProtocol.VLESS:
            return json.dumps({
                'protocol': 'vless',
                'server': config.server,
                'port': config.port,
                'uuid': config.uuid,
                'flow': config.flow,
                'encryption': config.encryption,
                'network': config.network or 'tcp',
                'path': config.path,
                'host': config.host,
                'tls': config.tls,
                'sni': config.sni,
                'remarks': config.remarks,
                'test_time': result.response_time,
                'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))

        return json.dumps(config.raw_config, ensure_ascii=False, separators=(',', ':'))

    def _create_config_url(self, result: 'TestResultData') -> str:
        """Create URL format for working_url configurations"""
        config = result.config

        try:
            if config.protocol == ProxyProtocol.SHADOWSOCKS:
                # ss://method:password@server:port#remarks
                auth = f"{config.method}:{config.password}"
                auth_b64 = base64.b64encode(auth.encode()).decode()
                remarks = quote(config.remarks or f"SS-{config.server}")
                return f"ss://{auth_b64}@{config.server}:{config.port}#{remarks}"

            elif config.protocol == ProxyProtocol.VMESS:
                # vmess://base64(json)
                vmess_config = {
                    "v": "2",
                    "ps": config.remarks or f"VMess-{config.server}",
                    "add": config.server,
                    "port": str(config.port),
                    "id": config.uuid,
                    "aid": str(config.alterId),
                    "scy": config.cipher,
                    "net": config.network or "tcp",
                    "type": config.headerType or "none",
                    "host": config.host or "",
                    "path": config.path or "",
                    "tls": config.tls or "",
                    "sni": config.sni or "",
                    "alpn": config.alpn or ""
                }
                vmess_json = json.dumps(vmess_config, separators=(',', ':'))
                vmess_b64 = base64.b64encode(vmess_json.encode()).decode()
                return f"vmess://{vmess_b64}"

            elif config.protocol == ProxyProtocol.VLESS:
                # vless://uuid@server:port?params#remarks
                params = []
                if config.encryption and config.encryption != "none":
                    params.append(f"encryption={quote(config.encryption)}")
                if config.flow:
                    params.append(f"flow={quote(config.flow)}")
                if config.tls:
                    params.append(f"security={quote(config.tls)}")
                if config.network and config.network != "tcp":
                    params.append(f"type={quote(config.network)}")
                if config.host:
                    params.append(f"host={quote(config.host)}")
                if config.path:
                    params.append(f"path={quote(config.path)}")
                if config.sni:
                    params.append(f"sni={quote(config.sni)}")
                if config.alpn:
                    params.append(f"alpn={quote(config.alpn)}")
                if config.serviceName:
                    params.append(f"serviceName={quote(config.serviceName)}")
                if config.fingerprint:
                    params.append(f"fp={quote(config.fingerprint)}")

                param_str = "&".join(params)
                query = f"?{param_str}" if param_str else ""
                remarks = quote(config.remarks or f"VLESS-{config.server}")
                return f"vless://{config.uuid}@{config.server}:{config.port}{query}#{remarks}"

        except Exception as e:
            logger.debug(f"Error creating URL for {config.protocol.value}: {e}")

        # Fallback: return a simple representation
        return f"{config.protocol.value}://{config.server}:{config.port}"

    def _find_xray_executable(self) -> str:
        xray_path = shutil.which('xray')
        if xray_path:
            return xray_path

        if sys.platform.startswith('win'):
            search_paths = [
                'xray.exe', './xray.exe', './Xray-windows-64/xray.exe',
                'C:\\Program Files\\Xray\\xray.exe'
            ]
        else:
            search_paths = [
                'xray', './xray', '/usr/local/bin/xray', '/usr/bin/xray'
            ]

        for path in search_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path

        return 'xray'

    def _validate_xray(self):
        """Validate Xray installation"""
        try:
            result = subprocess.run([self.xray_path, 'version'],
                                    capture_output=True, text=True, timeout=3,
                                    encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                version = result.stdout.strip().split()[1] if len(result.stdout.split()) > 1 else 'Unknown'
                logger.info(f"Xray version: {version}")
            else:
                logger.warning("Could not determine Xray version")
        except Exception as e:
            raise RuntimeError(f"Invalid Xray installation: {e}")

    def load_configs_from_json(self, file_path: str, protocol: ProxyProtocol) -> List[ProxyConfig]:
        """Load configurations from JSON file"""
        if not os.path.exists(file_path):
            logger.warning(f"Configuration file not found: {file_path}")
            return []

        configs = []
        seen_hashes = set()
        stats = {
            'total_configs': 0,
            'parsed_successfully': 0,
            'parse_failures': 0,
            'duplicates': 0,
            'invalid_configs': 0
        }

        logger.info(f"📁 Loading {protocol.value} configurations from: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            stats['total_configs'] = len(data.get('configs', []))
            logger.info(f"📄 File contains {stats['total_configs']} {protocol.value} configurations")

            for config_data in data.get('configs', []):
                try:
                    config = self._create_proxy_config_from_json(config_data, protocol)
                    if config:
                        config_hash = config.get_hash()
                        if config_hash not in seen_hashes:
                            configs.append(config)
                            seen_hashes.add(config_hash)
                            stats['parsed_successfully'] += 1
                            logger.debug(f"✅ Loaded: {config.server}:{config.port}")
                        else:
                            stats['duplicates'] += 1
                            logger.debug(f"⚠️ Duplicate config")
                    else:
                        stats['invalid_configs'] += 1

                except Exception as e:
                    stats['parse_failures'] += 1
                    logger.debug(f"❌ Parse failed: {e}")

        except Exception as e:
            logger.error(f"❌ Failed to load JSON file {file_path}: {e}")
            return []

        # Enhanced summary
        logger.info(f"📊 {protocol.value.upper()} loading results:")
        logger.info(f"  ├─ Total configs: {stats['total_configs']}")
        logger.info(f"  ├─ Successfully parsed: {stats['parsed_successfully']}")
        logger.info(f"  ├─ Parse failures: {stats['parse_failures']}")
        logger.info(f"  ├─ Invalid configs: {stats['invalid_configs']}")
        logger.info(f"  ├─ Duplicates removed: {stats['duplicates']}")
        logger.info(f"  └─ Unique configs for testing: {len(configs)}")

        return configs

    def _create_proxy_config_from_json(self, config_data: Dict, protocol: ProxyProtocol) -> Optional[ProxyConfig]:
        """Create ProxyConfig from JSON data"""
        try:
            if protocol == ProxyProtocol.SHADOWSOCKS:
                return ProxyConfig(
                    protocol=protocol,
                    server=config_data.get('server', ''),
                    port=int(config_data.get('port', 0)),
                    method=config_data.get('method', ''),
                    password=config_data.get('password', ''),
                    remarks=config_data.get('remarks', ''),
                    network=config_data.get('network', 'tcp'),
                    tls=config_data.get('tls', ''),
                    raw_config=config_data
                )

            elif protocol == ProxyProtocol.VMESS:
                return ProxyConfig(
                    protocol=protocol,
                    server=config_data.get('server', ''),
                    port=int(config_data.get('port', 0)),
                    uuid=config_data.get('id', config_data.get('uuid', '')),
                    alterId=int(config_data.get('alterId', 0)),
                    cipher=config_data.get('cipher', config_data.get('scy', 'auto')),
                    remarks=config_data.get('ps', config_data.get('remarks', '')),
                    network=config_data.get('net', config_data.get('network', 'tcp')),
                    tls=config_data.get('tls', ''),
                    sni=config_data.get('sni', ''),
                    path=config_data.get('path', ''),
                    host=config_data.get('host', ''),
                    alpn=config_data.get('alpn', ''),
                    headerType=config_data.get('type', config_data.get('headerType', '')),
                    raw_config=config_data
                )

            elif protocol == ProxyProtocol.VLESS:
                return ProxyConfig(
                    protocol=protocol,
                    server=config_data.get('server', ''),
                    port=int(config_data.get('port', 0)),
                    uuid=config_data.get('id', config_data.get('uuid', '')),
                    flow=config_data.get('flow', ''),
                    encryption=config_data.get('encryption', 'none'),
                    remarks=config_data.get('ps', config_data.get('remarks', '')),
                    network=config_data.get('net', config_data.get('network', 'tcp')),
                    tls=config_data.get('tls', config_data.get('security', '')),
                    sni=config_data.get('sni', ''),
                    path=config_data.get('path', ''),
                    host=config_data.get('host', ''),
                    alpn=config_data.get('alpn', ''),
                    serviceName=config_data.get('serviceName', ''),
                    fingerprint=config_data.get('fp', config_data.get('fingerprint', '')),
                    raw_config=config_data
                )

        except (ValueError, TypeError) as e:
            logger.debug(f"Invalid config data: {e}")
            return None

        return None

    def _generate_xray_config(self, config: ProxyConfig, listen_port: int) -> Dict:
        """Generate Xray configuration for testing with better protocol support"""
        xray_config = {
            "log": {
                "loglevel": "warning",
                "error": os.devnull
            },
            "inbounds": [
                {
                    "port": listen_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True,
                        "ip": "127.0.0.1"
                    },
                    "sniffing": {
                        "enabled": False
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": config.protocol.value,
                    "settings": {},
                    "streamSettings": {
                        "sockopt": {
                            "tcpKeepAliveInterval": 30
                        }
                    }
                }
            ]
        }

        # Shadowsocks configuration
        if config.protocol == ProxyProtocol.SHADOWSOCKS:
            xray_config["outbounds"][0]["settings"] = {
                "servers": [
                    {
                        "address": config.server,
                        "port": config.port,
                        "method": config.method,
                        "password": config.password,
                        "level": 0
                    }
                ]
            }

        # VMess configuration
        elif config.protocol == ProxyProtocol.VMESS:
            xray_config["outbounds"][0]["settings"] = {
                "vnext": [
                    {
                        "address": config.server,
                        "port": config.port,
                        "users": [
                            {
                                "id": config.uuid,
                                "alterId": config.alterId,
                                "security": config.cipher,
                                "level": 0
                            }
                        ]
                    }
                ]
            }

        # VLESS configuration
        elif config.protocol == ProxyProtocol.VLESS:
            xray_config["outbounds"][0]["settings"] = {
                "vnext": [
                    {
                        "address": config.server,
                        "port": config.port,
                        "users": [
                            {
                                "id": config.uuid,
                                "flow": config.flow,
                                "encryption": config.encryption,
                                "level": 0
                            }
                        ]
                    }
                ]
            }

        # Configure stream settings for all protocols
        stream_settings = xray_config["outbounds"][0]["streamSettings"]

        # Network type
        if config.network and config.network != "tcp":
            stream_settings["network"] = config.network

            # WebSocket settings
            if config.network == "ws":
                ws_settings = {}
                if config.path:
                    ws_settings["path"] = config.path
                if config.host:
                    ws_settings["headers"] = {"Host": config.host}
                stream_settings["wsSettings"] = ws_settings

            # HTTP/2 settings
            elif config.network == "h2":
                h2_settings = {}
                if config.path:
                    h2_settings["path"] = config.path
                if config.host:
                    h2_settings["host"] = [config.host]
                stream_settings["httpSettings"] = h2_settings

            # gRPC settings
            elif config.network == "grpc":
                grpc_settings = {}
                if config.serviceName:
                    grpc_settings["serviceName"] = config.serviceName
                stream_settings["grpcSettings"] = grpc_settings

        # TLS settings
        if config.tls:
            stream_settings["security"] = config.tls
            tls_settings = {}

            if config.sni:
                tls_settings["serverName"] = config.sni
            elif config.host:
                tls_settings["serverName"] = config.host

            if config.alpn:
                tls_settings["alpn"] = config.alpn.split(",") if isinstance(config.alpn, str) else config.alpn

            if config.fingerprint:
                tls_settings["fingerprint"] = config.fingerprint

            # Allow insecure for testing
            tls_settings["allowInsecure"] = True

            if config.tls == "tls":
                stream_settings["tlsSettings"] = tls_settings
            elif config.tls == "reality":
                stream_settings["realitySettings"] = tls_settings

        return xray_config

    def _test_single_config(self, config: ProxyConfig, batch_id: int = 0) -> TestResultData:
        """Test a single proxy configuration with better error handling"""
        test_start = time.time()
        proxy_port = None
        process = None
        config_file = None
        operation_id = f"test_{config.get_hash()}_{int(time.time())}"

        try:
            self.hang_detector.register_operation(operation_id)

            # Get available port
            proxy_port = self.port_manager.get_available_port()
            if not proxy_port:
                return TestResultData(
                    config=config,
                    result=TestResult.PORT_CONFLICT,
                    test_time=time.time() - test_start,
                    batch_id=batch_id
                )

            # Generate Xray config
            xray_config = self._generate_xray_config(config, proxy_port)

            # Write config to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(xray_config, f, indent=2)
                config_file = f.name

            # Test config syntax first
            try:
                syntax_test = subprocess.run(
                    [self.xray_path, 'run', '-test', '-config', config_file],
                    capture_output=True,
                    timeout=2,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                if syntax_test.returncode != 0:
                    return TestResultData(
                        config=config,
                        result=TestResult.SYNTAX_ERROR,
                        test_time=time.time() - test_start,
                        error_message=syntax_test.stderr[:200],
                        batch_id=batch_id
                    )
            except subprocess.TimeoutExpired:
                return TestResultData(
                    config=config,
                    result=TestResult.SYNTAX_ERROR,
                    test_time=time.time() - test_start,
                    error_message="Syntax test timeout",
                    batch_id=batch_id
                )

            # Start Xray process
            with open(os.devnull, 'w') as devnull:
                process = subprocess.Popen(
                    [self.xray_path, 'run', '-config', config_file],
                    stdout=devnull,
                    stderr=devnull,
                    text=True,
                    encoding='utf-8',
                    errors='ignore'
                )

            self.process_manager.register_process(process)

            # Wait for Xray to start (increased wait time)
            time.sleep(2.0)  # Increased from 0.1 to 2.0 seconds

            # Check if process is still running
            if process.poll() is not None:
                return TestResultData(
                    config=config,
                    result=TestResult.CONNECTION_ERROR,
                    test_time=time.time() - test_start,
                    error_message="Xray process terminated",
                    batch_id=batch_id
                )

            # Test connection through proxy
            success, external_ip, response_time = self.network_tester.test_proxy_connection(proxy_port)

            if success:
                result = TestResultData(
                    config=config,
                    result=TestResult.SUCCESS,
                    test_time=time.time() - test_start,
                    response_time=response_time,
                    external_ip=external_ip,
                    proxy_port=proxy_port,
                    batch_id=batch_id
                )
                logger.info(
                    f"\n✅ SUCCESS: {config.protocol.value}://{config.server}:{config.port} ({response_time:.3f}s)")
                # Save immediately and log in one clean message
                self._save_config_immediately(result)
                return result
            else:
                return TestResultData(
                    config=config,
                    result=TestResult.NETWORK_ERROR,
                    test_time=time.time() - test_start,
                    error_message="Network test failed",
                    proxy_port=proxy_port,
                    batch_id=batch_id
                )

        except subprocess.TimeoutExpired:
            return TestResultData(
                config=config,
                result=TestResult.TIMEOUT,
                test_time=time.time() - test_start,
                batch_id=batch_id
            )
        except Exception as e:
            logger.debug(f"Test error for {config.server}:{config.port}: {e}")
            return TestResultData(
                config=config,
                result=TestResult.NETWORK_ERROR,
                test_time=time.time() - test_start,
                error_message=str(e),
                batch_id=batch_id
            )
        finally:
            # Cleanup process
            if process:
                try:
                    self.process_manager._force_kill_process(process)
                    self.process_manager.unregister_process(process)
                except:
                    pass

            # Cleanup config file
            if config_file and os.path.exists(config_file):
                try:
                    os.unlink(config_file)
                except:
                    pass

            # Release port
            if proxy_port:
                self.port_manager.release_port(proxy_port)

            self.hang_detector.unregister_operation(operation_id)

    def _close_incremental_files(self):
        """Close all open file handles"""
        for handle in self.output_file_handles.values():
            try:
                handle.close()
            except:
                pass
        for handle in self.url_file_handles.values():
            try:
                handle.close()
            except:
                pass
        self.output_file_handles.clear()
        self.url_file_handles.clear()

    def test_configs(self, configs: List[ProxyConfig], batch_id: int = 0) -> List[TestResultData]:
        """Test multiple configurations with optimized execution"""
        if not configs:
            return []

        batch_results = []
        batch_start = time.time()
        tested_count = 0
        successful_count = 0

        logger.info(f"\n🧪 Testing batch {batch_id} with {len(configs)} configurations...")

        # Use ThreadPoolExecutor with limited workers and better error handling
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(configs))) as executor:
            future_to_config = {}
            for config in configs:
                try:
                    future = executor.submit(self._test_single_config, config, batch_id)
                    future_to_config[future] = config
                except Exception as e:
                    logger.debug(f"Failed to submit task for {config.server}:{config.port}: {e}")
                    error_result = TestResultData(
                        config=config,
                        result=TestResult.NETWORK_ERROR,
                        test_time=time.time() - batch_start,
                        error_message=f"Submit failed: {e}",
                        batch_id=batch_id
                    )
                    batch_results.append(error_result)
                    self._update_stats(error_result)

            if HAS_TQDM:
                progress_bar = tqdm(total=len(configs), desc=f"Batch {batch_id}", unit="config", ncols=80)
            else:
                logger.info(f"Progress: 0/{len(configs)}")

            try:
                for future in as_completed(future_to_config, timeout=self.timeout + 5):
                    config = future_to_config[future]
                    tested_count += 1

                    try:
                        result = future.result(timeout=1.0)
                        batch_results.append(result)

                        # Update statistics
                        self._update_stats(result)

                        # Save successful configs immediately
                        if result.result == TestResult.SUCCESS:
                            successful_count += 1
                            self._save_config_immediately(result)

                        # Update progress
                        if HAS_TQDM:
                            progress_bar.update(1)
                            progress_bar.set_postfix({
                                'success': successful_count,
                                'tested': tested_count
                            })
                        elif tested_count % 50 == 0:
                            logger.info(f"Progress: {tested_count}/{len(configs)} (success: {successful_count})")

                    except TimeoutError:
                        logger.debug(f"Timeout getting result for {config.server}:{config.port}")
                        error_result = TestResultData(
                            config=config,
                            result=TestResult.TIMEOUT,
                            test_time=time.time() - batch_start,
                            batch_id=batch_id
                        )
                        batch_results.append(error_result)
                        self._update_stats(error_result)

                    except Exception as e:
                        logger.debug(f"Error getting result for {config.server}:{config.port}: {e}")
                        error_result = TestResultData(
                            config=config,
                            result=TestResult.NETWORK_ERROR,
                            test_time=time.time() - batch_start,
                            error_message=str(e),
                            batch_id=batch_id
                        )
                        batch_results.append(error_result)
                        self._update_stats(error_result)

            except TimeoutError:
                # Handle case where as_completed times out
                logger.warning(f"\n⏰ Batch {batch_id}: Timeout reached, processing remaining futures")

                # Cancel and process remaining futures
                for future, config in future_to_config.items():
                    if not future.done():
                        future.cancel()
                        tested_count += 1
                        error_result = TestResultData(
                            config=config,
                            result=TestResult.TIMEOUT,
                            test_time=time.time() - batch_start,
                            error_message="Batch timeout",
                            batch_id=batch_id
                        )
                        batch_results.append(error_result)
                        self._update_stats(error_result)

                        if HAS_TQDM:
                            progress_bar.update(1)

            if HAS_TQDM:
                progress_bar.close()

        # Force cleanup any remaining tasks
        try:
            executor.shutdown(wait=False)
        except:
            pass

        batch_time = time.time() - batch_start
        logger.info(f"\n✅ Batch {batch_id} completed: {successful_count}/{len(configs)} successful ({batch_time:.2f}s)")

        return batch_results

    def _update_stats(self, result: TestResultData):
        """Update statistics with thread safety"""
        with self.results_lock:
            self.stats['total'] += 1
            protocol = result.config.protocol.value

            # Update protocol-specific stats
            if protocol in self.stats:
                self.stats[protocol]['total'] += 1
                if result.result == TestResult.SUCCESS:
                    self.stats[protocol]['success'] += 1
                else:
                    self.stats[protocol]['failed'] += 1

            # Update overall result stats
            if result.result == TestResult.SUCCESS:
                self.stats['success'] += 1
            else:
                self.stats['failed'] += 1

                if result.result == TestResult.PARSE_ERROR:
                    self.stats['parse_errors'] += 1
                elif result.result == TestResult.SYNTAX_ERROR:
                    self.stats['syntax_errors'] += 1
                elif result.result == TestResult.CONNECTION_ERROR:
                    self.stats['connection_errors'] += 1
                elif result.result == TestResult.TIMEOUT:
                    self.stats['timeouts'] += 1
                elif result.result == TestResult.HANG_TIMEOUT:
                    self.stats['hang_timeouts'] += 1
                elif result.result == TestResult.PROCESS_KILLED:
                    self.stats['process_killed'] += 1

    def run_tests(self, configs: List[ProxyConfig]) -> List[TestResultData]:
        """Run tests on all configurations with batch processing and signal handling"""
        if not configs:
            logger.warning("No configurations to test")
            return []

        # Setup signal handler for graceful shutdown
        def signal_handler(signum, frame):
            logger.info(f"\n⚠️  Received signal {signum}, shutting down gracefully...")
            self.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)

        # Start monitoring services
        self.process_manager.start_monitoring()
        self.hang_detector.start_monitoring()

        all_results = []
        total_configs = len(configs)

        logger.info(f"\n🚀 Starting comprehensive proxy testing for {total_configs} configurations")
        logger.info(f"⚙️  Settings: {self.max_workers} workers, {self.timeout}s timeout, batch size: {self.batch_size}")

        try:
            # Process in batches
            for batch_idx, i in enumerate(range(0, total_configs, self.batch_size)):
                batch = configs[i:i + self.batch_size]
                batch_id = batch_idx + 1

                logger.info(f"\n📦 Processing batch {batch_id} ({len(batch)} configs)...")

                try:
                    batch_results = self.test_configs(batch, batch_id)
                    all_results.extend(batch_results)

                    # Save intermediate results
                    self._save_results(all_results)

                    # Show batch summary
                    self._print_batch_summary(batch_results, batch_id)

                    # Small delay between batches to prevent resource exhaustion
                    if batch_idx < (total_configs // self.batch_size):
                        time.sleep(0.5)

                except KeyboardInterrupt:
                    logger.info(f"\n⏹️  Batch {batch_id} interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"❌ Batch {batch_id} failed: {e}")
                    continue

        except KeyboardInterrupt:
            logger.info("\n⏹️  Testing interrupted by user")
        finally:
            # Stop monitoring services
            self.process_manager.stop_monitoring()
            self.hang_detector.stop_monitoring()

        # Final results
        if all_results:
            self._print_final_summary(all_results)

        return all_results

    def _print_batch_summary(self, results: List[TestResultData], batch_id: int):
        """Print summary for a batch"""
        success_count = sum(1 for r in results if r.result == TestResult.SUCCESS)
        total_count = len(results)

        logger.info(f"\n📊 Batch {batch_id} Summary: {success_count}/{total_count} successful "
                    f"({success_count / total_count * 100:.1f}%)")

    def _print_final_summary(self, results: List[TestResultData]):
        """Print comprehensive final summary"""
        success_count = sum(1 for r in results if r.result == TestResult.SUCCESS)
        total_count = len(results)

        logger.info("=" * 60)
        logger.info("🎯 FINAL TESTING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"📈 Total configurations tested: {total_count}")
        logger.info(f"✅ Successful connections: {success_count}")
        logger.info(f"❌ Failed connections: {total_count - success_count}")
        logger.info(f"📊 Success rate: {success_count / total_count * 100:.2f}%")

        # Protocol breakdown
        logger.info("\n📋 Protocol Breakdown:")
        for protocol in ['shadowsocks', 'vmess', 'vless']:
            if self.stats[protocol]['total'] > 0:
                success_pct = (self.stats[protocol]['success'] / self.stats[protocol]['total'] * 100) if \
                self.stats[protocol]['total'] > 0 else 0
                logger.info(
                    f"  {protocol.upper():<12}: {self.stats[protocol]['success']:>4}/{self.stats[protocol]['total']:>4} "
                    f"({success_pct:5.1f}%)")

        # Error breakdown
        if total_count - success_count > 0:
            logger.info("\n🔍 Error Breakdown:")
            error_stats = {
                'Connection Errors': self.stats['connection_errors'],
                'Timeouts': self.stats['timeouts'],
                'Parse Errors': self.stats['parse_errors'],
                'Syntax Errors': self.stats['syntax_errors'],
                'Hang Timeouts': self.stats['hang_timeouts'],
                'Process Killed': self.stats['process_killed']
            }

            for error_type, count in error_stats.items():
                if count > 0:
                    pct = count / total_count * 100
                    logger.info(f"  {error_type:<18}: {count:>4} ({pct:5.1f}%)")

        # Response time statistics for successful connections
        success_times = [r.response_time for r in results if r.result == TestResult.SUCCESS and r.response_time]
        if success_times:
            avg_time = sum(success_times) / len(success_times)
            min_time = min(success_times)
            max_time = max(success_times)
            logger.info(f"\n⏱️  Response Times (successful only):")
            logger.info(f"  Average: {avg_time:.3f}s")
            logger.info(f"  Minimum: {min_time:.3f}s")
            logger.info(f"  Maximum: {max_time:.3f}s")

        # Unsupported methods warning
        if _unsupported_methods:
            logger.info(f"\n⚠️  Unsupported methods detected: {', '.join(_unsupported_methods)}")
            logger.info("  These methods may not work with this Xray version")

        logger.info("=" * 60)

    def _save_results(self, results: List[TestResultData]):
        """Save results to JSON file"""
        try:
            results_data = [r.to_dict() for r in results]
            with open('../log/test_results.json', 'w', encoding='utf-8') as f:
                json.dump(results_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    def cleanup(self):
        """Cleanup resources"""
        try:
            self._close_incremental_files()
            self.process_manager.stop_monitoring()
            self.hang_detector.stop_monitoring()
            self.port_manager = None
        except:
            pass


def main():
    """Main function with enhanced argument parsing and error handling"""
    import argparse

    parser = argparse.ArgumentParser(description='Enhanced Professional Proxy Configuration Tester')
    parser.add_argument('--shadowsocks', '-ss', help='Shadowsocks JSON config file')
    parser.add_argument('--vmess', '-vm', help='VMess JSON config file')
    parser.add_argument('--vless', '-vl', help='VLESS JSON config file')
    parser.add_argument('--workers', '-w', type=int, default=1000, help='Number of concurrent workers')
    parser.add_argument('--timeout', '-t', type=int, default=20, help='Connection timeout in seconds')
    parser.add_argument('--batch-size', '-b', type=int, default=1000, help='Batch size for processing')
    parser.add_argument('--xray-path', '-x', help='Path to Xray executable')
    parser.add_argument('--no-incremental', action='store_true', help='Disable incremental saving')

    args = parser.parse_args()

    # Check for default config files if no arguments provided
    if not any([args.shadowsocks, args.vmess, args.vless]):
        default_files = {
            'shadowsocks': '../data/raw/shadowsocks_configs.json',
            'vmess': '../data/raw/vmess_configs.json',
            'vless': '../data/raw/vless_configs.json'
        }

        # Check which default files exist
        existing_defaults = []
        for protocol, filename in default_files.items():
            if os.path.exists(filename):
                existing_defaults.append((protocol, filename))

        if existing_defaults:
            logger.info("🔍 No config files specified, using available default files:")
            for protocol, filename in existing_defaults:
                logger.info(f"  📁 Found: {filename}")
                if protocol == 'shadowsocks':
                    args.shadowsocks = filename
                elif protocol == 'vmess':
                    args.vmess = filename
                elif protocol == 'vless':
                    args.vless = filename
        else:
            parser.error("At least one config file (--shadowsocks, --vmess, or --vless) is required, or place default config files (shadowsocks_configs.json, vmess_configs.json, vless_configs.json) in the current directory")

    # Initialize tester
    try:
        tester = EnhancedProxyTester(
            xray_path=args.xray_path,
            max_workers=args.workers,
            timeout=args.timeout,
            batch_size=args.batch_size,
            incremental_save=not args.no_incremental
        )
    except Exception as e:
        logger.error(f"Failed to initialize tester: {e}")
        return

    all_configs = []

    # Load configurations
    if args.shadowsocks:
        ss_configs = tester.load_configs_from_json(args.shadowsocks, ProxyProtocol.SHADOWSOCKS)
        all_configs.extend(ss_configs)

    if args.vmess:
        vm_configs = tester.load_configs_from_json(args.vmess, ProxyProtocol.VMESS)
        all_configs.extend(vm_configs)

    if args.vless:
        vl_configs = tester.load_configs_from_json(args.vless, ProxyProtocol.VLESS)
        all_configs.extend(vl_configs)

    if not all_configs:
        logger.error("No valid configurations found to test")
        return

    logger.info(f"🎯 Total unique configurations for testing: {len(all_configs)}")

    # Run tests
    try:
        results = tester.run_tests(all_configs)
        logger.info(f"Testing completed. Results saved to test_results.json")

        # Show working_url configs summary
        working_configs = [r for r in results if r.result == TestResult.SUCCESS]
        if working_configs:
            logger.info(f"\n💾 Working configurations saved to:")
            for protocol in ['shadowsocks', 'vmess', 'vless']:
                if tester.incremental_files.get(protocol):
                    logger.info(f"  JSON: {tester.incremental_files[protocol]}")
                if tester.url_files.get(protocol):
                    logger.info(f"  URL: {tester.url_files[protocol]}")
        else:
            logger.info("❌ No working_url configurations found")

    except KeyboardInterrupt:
        logger.info("\n⏹️  Testing interrupted by user")
    except Exception as e:
        logger.error(f"❌ Testing failed: {e}")
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()
