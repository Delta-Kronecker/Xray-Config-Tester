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
    file_formatter = logging.Formatter('[%(asctime)s] %(levelname)-8s %(message)s')
    console_formatter = logging.Formatter('%(levelname)-8s %(message)s')

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
    method: str = ""
    password: str = ""
    uuid: str = ""
    alterId: int = 0
    cipher: str = "auto"
    flow: str = ""
    encryption: str = "none"
    network: str = "tcp"
    tls: str = ""
    sni: str = ""
    path: str = ""
    host: str = ""
    alpn: str = ""
    fingerprint: str = ""
    headerType: str = ""
    serviceName: str = ""
    raw_config: Dict[str, Any] = field(default_factory=dict)
    config_id: Optional[int] = None
    line_number: Optional[int] = None

    def __post_init__(self):
        if not self.is_valid():
            raise ValueError(f"Invalid proxy configuration: {self}")

    def is_valid(self) -> bool:
        if not (1 <= self.port <= 65535):
            return False
        if not self._is_valid_address(self.server):
            return False

        if self.protocol == ProxyProtocol.SHADOWSOCKS:
            return self._validate_shadowsocks()
        elif self.protocol == ProxyProtocol.VMESS:
            return self._validate_vmess()
        elif self.protocol == ProxyProtocol.VLESS:
            return self._validate_vless()

        return False

    def _validate_shadowsocks(self) -> bool:
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
            logger.debug("Unsupported method: %s", self.method)

        if not self.password or len(self.password) < 1:
            return False

        return True

    def _validate_vmess(self) -> bool:
        if not self.uuid:
            return False
        try:
            uuid.UUID(self.uuid)
        except ValueError:
            return False
        if self.alterId < 0:
            return False
        return True

    def _validate_vless(self) -> bool:
        if not self.uuid:
            return False
        try:
            uuid.UUID(self.uuid)
        except ValueError:
            return False
        return True

    def _is_valid_address(self, address: str) -> bool:
        clean_address = address.strip('[]')
        try:
            ipaddress.ip_address(clean_address)
            return True
        except ValueError:
            if len(clean_address) > 253 or not clean_address:
                return False
            if clean_address.startswith('.') or clean_address.endswith('.'):
                return False
            if '..' in clean_address:
                return False
            labels = clean_address.split('.')
            if len(labels) < 2:
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
        if 'config' in result_dict and 'protocol' in result_dict['config']:
            if hasattr(result_dict['config']['protocol'], 'value'):
                result_dict['config']['protocol'] = result_dict['config']['protocol'].value
        return result_dict


class ProcessManager:
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
        while self.running:
            time.sleep(2)
            with self.lock:
                dead_pids = [pid for pid, proc in self.active_processes.items() if proc.poll() is not None]
                for pid in dead_pids:
                    self.active_processes.pop(pid, None)

    def _cleanup_all_processes(self):
        with self.lock:
            for pid, process in list(self.active_processes.items()):
                try:
                    self._force_kill_process(process)
                except:
                    pass
            self.active_processes.clear()

    def _force_kill_process(self, process: subprocess.Popen):
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
    def __init__(self, start_port: int = 10000, end_port: int = 20000):
        self.start_port = start_port
        self.end_port = end_port
        self.available_ports = Queue()
        self.used_ports = set()
        self.lock = threading.Lock()
        self._initialize_port_pool()

    def _initialize_port_pool(self):
        logger.info("Port pool ready (%d-%d)", self.start_port, self.end_port)
        chunk_size = 100
        available_count = 0
        for start in range(self.start_port, self.end_port + 1, chunk_size):
            end = min(start + chunk_size, self.end_port + 1)
            for port in range(start, end):
                if self._is_port_available_fast(port):
                    self.available_ports.put(port)
                    available_count += 1
        logger.info("Port pool initialized (%d ports)", available_count)

    def _is_port_available_fast(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.05)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('127.0.0.1', port))
                return True
        except OSError:
            return False

    def get_available_port(self, timeout: float = 0.1) -> Optional[int]:
        try:
            port = self.available_ports.get(timeout=timeout)
            with self.lock:
                self.used_ports.add(port)
            return port
        except Empty:
            return self._find_emergency_port()

    def _find_emergency_port(self) -> Optional[int]:
        sample_size = min(100, self.end_port - self.start_port + 1)
        port_sample = random.sample(range(self.start_port, self.end_port + 1), sample_size)
        with self.lock:
            for port in port_sample:
                if port not in self.used_ports and self._is_port_available_fast(port):
                    self.used_ports.add(port)
                    return port
        return None

    def release_port(self, port: int):
        with self.lock:
            self.used_ports.discard(port)
        threading.Timer(0.02, lambda: self.available_ports.put(port)).start()


class FastNetworkTester:
    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=100, max_retries=0)
            self.session.mount('http://', adapter)
            self.session.mount('https://', adapter)

        self.test_urls = [
            'http://httpbin.org/ip', 'http://icanhazip.com', 'http://ifconfig.me/ip',
            'http://api.ipify.org', 'http://ipinfo.io/ip', 'http://checkip.amazonaws.com',
            'https://httpbin.org/ip', 'https://icanhazip.com', 'https://ifconfig.me/ip',
            'https://api.ipify.org'
        ]

    def test_proxy_connection(self, proxy_port: int) -> Tuple[bool, Optional[str], float]:
        start = time.time()
        if not self._is_proxy_responsive(proxy_port):
            return False, None, time.time() - start
        for url in random.sample(self.test_urls, min(8, len(self.test_urls))):
            try:
                ok, ip, rt = self._single_test(proxy_port, url)
                if ok:
                    return True, ip, rt
            except Exception as e:
                logger.debug("Test failed for %s: %s", url, e)
                continue
        return False, None, time.time() - start

    def _is_proxy_responsive(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                return s.connect_ex(('127.0.0.1', port)) == 0
        except:
            return False

    def _single_test(self, proxy_port: int, test_url: str) -> Tuple[bool, Optional[str], float]:
        proxies = {
            'http': f'socks5://127.0.0.1:{proxy_port}',
            'https': f'socks5://127.0.0.1:{proxy_port}'
        }
        start = time.time()
        try:
            if self.session:
                resp = self.session.get(test_url, proxies=proxies, timeout=self.timeout, verify=False)
                rt = time.time() - start
                if resp.status_code == 200:
                    ip = resp.text.strip()
                    if 'application/json' in resp.headers.get('content-type', ''):
                        try:
                            data = resp.json()
                            ip = data.get('origin', data.get('ip', ip))
                        except:
                            pass
                    if '.' in ip or ':' in ip:
                        return True, ip, rt
            return False, None, time.time() - start
        except requests.exceptions.RequestException:
            return False, None, time.time() - start
        except Exception:
            return False, None, time.time() - start


class OptimizedHangDetector:
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
        while self.running:
            current = time.time()
            hanging = []
            with self.lock:
                for oid, ts in list(self.active_operations.items()):
                    if current - ts > self.max_hang_time:
                        hanging.append(oid)
            for oid in hanging:
                cb = self.hang_callbacks.get(oid)
                if cb:
                    try:
                        cb()
                    except:
                        pass
                self.unregister_operation(oid)
            if hanging:
                logger.warning("Cleaned %d hanging operations", len(hanging))
            time.sleep(2)


class EnhancedProxyTester:
    def __init__(self,
                 xray_path: Optional[str] = None,
                 max_workers: int = 1000,
                 timeout: int = 8,
                 port_range: Tuple[int, int] = (10000, 20000),
                 batch_size: int = 1000,
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
        self.url_files = {
            'shadowsocks': '../data/working_url/working_shadowsocks_urls.txt',
            'vmess': '../data/working_url/working_vmess_urls.txt',
            'vless': '../data/working_url/working_vless_urls.txt'
        }
        self.output_file_handles = {}
        self.url_file_handles = {}

        self.port_manager = FastPortManager(port_range[0], port_range[1])
        self.process_manager = ProcessManager()
        self.hang_detector = OptimizedHangDetector(max_hang_time=12.0)
        self.network_tester = FastNetworkTester(timeout)

        if not HAS_SOCKS:
            logger.warning("PySocks not found – SOCKS5 support limited")

        self._validate_xray()

        self.results: List[TestResultData] = []
        self.results_lock = threading.Lock()

        if self.incremental_save:
            self._setup_incremental_save()

        self.stats = {
            'total': 0, 'success': 0, 'failed': 0, 'parse_errors': 0,
            'syntax_errors': 0, 'connection_errors': 0, 'timeouts': 0,
            'hang_timeouts': 0, 'process_killed': 0,
            'shadowsocks': {'total': 0, 'success': 0, 'failed': 0},
            'vmess': {'total': 0, 'success': 0, 'failed': 0},
            'vless': {'total': 0, 'success': 0, 'failed': 0}
        }

        logger.info("Tester ready | workers=%d batch=%d", max_workers, batch_size)
        if self.incremental_save:
            logger.info("Incremental save active")

    def __del__(self):
        try:
            self._close_incremental_files()
        except:
            pass

    def _setup_incremental_save(self):
        try:
            for protocol, filename in self.incremental_files.items():
                f = open(filename, 'w', encoding='utf-8')
                f.write(f"# Working {protocol.upper()} (JSON)\n")
                f.flush()
                self.output_file_handles[protocol] = f

            for protocol, filename in self.url_files.items():
                f = open(filename, 'w', encoding='utf-8')
                f.write(f"# Working {protocol.upper()} (URL)\n")
                f.flush()
                self.url_file_handles[protocol] = f

            logger.info("Incremental save files ready")
        except Exception as e:
            logger.error("Failed to setup incremental save: %s", e)
            self.incremental_save = False

    def _save_config_immediately(self, result: TestResultData):
        if not self.incremental_save or result.result != TestResult.SUCCESS:
            return
        try:
            protocol = result.config.protocol.value
            config_line = self._create_working_config_line(result)
            config_url = self._create_config_url(result)

            if protocol in self.output_file_handles:
                f = self.output_file_handles[protocol]
                f.write(f"# {result.response_time:.3f}s {result.external_ip}\n{config_line}\n\n")
                f.flush()

            if protocol in self.url_file_handles:
                u = self.url_file_handles[protocol]
                u.write(f"# {result.response_time:.3f}s {result.external_ip}\n{config_url}\n\n")
                u.flush()
        except Exception as e:
            logger.error("Immediate save failed: %s", e)

    def _create_working_config_line(self, result: TestResultData) -> str:
        config = result.config
        if config.protocol == ProxyProtocol.SHADOWSOCKS:
            return json.dumps({
                'protocol': 'shadowsocks', 'server': config.server, 'port': config.port,
                'method': config.method, 'password': config.password, 'network': config.network or 'tcp',
                'tls': config.tls, 'remarks': config.remarks, 'test_time': result.response_time,
                'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))
        elif config.protocol == ProxyProtocol.VMESS:
            return json.dumps({
                'protocol': 'vmess', 'server': config.server, 'port': config.port, 'uuid': config.uuid,
                'alterId': config.alterId, 'cipher': config.cipher, 'network': config.network or 'tcp',
                'path': config.path, 'host': config.host, 'tls': config.tls, 'sni': config.sni,
                'remarks': config.remarks, 'test_time': result.response_time, 'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))
        elif config.protocol == ProxyProtocol.VLESS:
            return json.dumps({
                'protocol': 'vless', 'server': config.server, 'port': config.port, 'uuid': config.uuid,
                'flow': config.flow, 'encryption': config.encryption, 'network': config.network or 'tcp',
                'path': config.path, 'host': config.host, 'tls': config.tls, 'sni': config.sni,
                'remarks': config.remarks, 'test_time': result.response_time, 'external_ip': result.external_ip
            }, ensure_ascii=False, separators=(',', ':'))
        return json.dumps(config.raw_config, ensure_ascii=False, separators=(',', ':'))

    def _create_config_url(self, result: TestResultData) -> str:
        config = result.config
        try:
            if config.protocol == ProxyProtocol.SHADOWSOCKS:
                auth = f"{config.method}:{config.password}"
                auth_b64 = base64.b64encode(auth.encode()).decode()
                remarks = quote(config.remarks or f"SS-{config.server}")
                return f"ss://{auth_b64}@{config.server}:{config.port}#{remarks}"
            elif config.protocol == ProxyProtocol.VMESS:
                vmess_config = {
                    "v": "2", "ps": config.remarks or f"VMess-{config.server}", "add": config.server,
                    "port": str(config.port), "id": config.uuid, "aid": str(config.alterId),
                    "scy": config.cipher, "net": config.network or "tcp", "type": config.headerType or "none",
                    "host": config.host or "", "path": config.path or "", "tls": config.tls or "",
                    "sni": config.sni or "", "alpn": config.alpn or ""
                }
                return f"vmess://{base64.b64encode(json.dumps(vmess_config, separators=(',', ':')).encode()).decode()}"
            elif config.protocol == ProxyProtocol.VLESS:
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
            logger.debug("URL create error for %s: %s", config.protocol.value, e)
        return f"{config.protocol.value}://{config.server}:{config.port}"

    def _find_xray_executable(self) -> str:
        xray_path = shutil.which('xray')
        if xray_path:
            return xray_path
        if sys.platform.startswith('win'):
            search_paths = ['xray.exe', './xray.exe', './Xray-windows-64/xray.exe',
                            'C:\\Program Files\\Xray\\xray.exe']
        else:
            search_paths = ['xray', './xray', '/usr/local/bin/xray', '/usr/bin/xray']
        for path in search_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
        return 'xray'

    def _validate_xray(self):
        try:
            result = subprocess.run([self.xray_path, 'version'], capture_output=True, text=True, timeout=3,
                                    encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                version = result.stdout.strip().split()[1] if len(result.stdout.split()) > 1 else 'Unknown'
                logger.info("Xray version: %s", version)
            else:
                logger.warning("Could not determine Xray version")
        except Exception as e:
            raise RuntimeError(f"Invalid Xray installation: {e}")

    def load_configs_from_json(self, file_path: str, protocol: ProxyProtocol) -> List[ProxyConfig]:
        if not os.path.exists(file_path):
            logger.warning("Config file not found: %s", file_path)
            return []
        configs = []
        seen_hashes = set()
        stats = {'total': 0, 'parsed': 0, 'failed': 0, 'dupes': 0, 'invalid': 0}
        logger.info("Loading %s from %s", protocol.value, file_path)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            stats['total'] = len(data.get('configs', []))
            for cfg in data.get('configs', []):
                try:
                    config = self._create_proxy_config_from_json(cfg, protocol)
                    if config:
                        h = config.get_hash()
                        if h not in seen_hashes:
                            configs.append(config)
                            seen_hashes.add(h)
                            stats['parsed'] += 1
                        else:
                            stats['dupes'] += 1
                    else:
                        stats['invalid'] += 1
                except Exception as e:
                    stats['failed'] += 1
                    logger.debug("Parse failed: %s", e)
        except Exception as e:
            logger.error("Failed to load %s: %s", file_path, e)
            return []
        logger.info("Loaded %s: total=%d parsed=%d invalid=%d dupes=%d unique=%d",
                    protocol.value, stats['total'], stats['parsed'], stats['invalid'], stats['dupes'], len(configs))
        return configs

    def _create_proxy_config_from_json(self, data: Dict, protocol: ProxyProtocol) -> Optional[ProxyConfig]:
        try:
            if protocol == ProxyProtocol.SHADOWSOCKS:
                return ProxyConfig(protocol=protocol, server=data.get('server', ''), port=int(data.get('port', 0)),
                                   method=data.get('method', ''), password=data.get('password', ''),
                                   remarks=data.get('remarks', ''), network=data.get('network', 'tcp'),
                                   tls=data.get('tls', ''), raw_config=data)
            elif protocol == ProxyProtocol.VMESS:
                return ProxyConfig(protocol=protocol, server=data.get('server', ''), port=int(data.get('port', 0)),
                                   uuid=data.get('id', data.get('uuid', '')), alterId=int(data.get('alterId', 0)),
                                   cipher=data.get('cipher', data.get('scy', 'auto')),
                                   remarks=data.get('ps', data.get('remarks', '')),
                                   network=data.get('net', data.get('network', 'tcp')), tls=data.get('tls', ''),
                                   sni=data.get('sni', ''), path=data.get('path', ''), host=data.get('host', ''),
                                   alpn=data.get('alpn', ''), headerType=data.get('type', data.get('headerType', '')),
                                   raw_config=data)
            elif protocol == ProxyProtocol.VLESS:
                return ProxyConfig(protocol=protocol, server=data.get('server', ''), port=int(data.get('port', 0)),
                                   uuid=data.get('id', data.get('uuid', '')), flow=data.get('flow', ''),
                                   encryption=data.get('encryption', 'none'),
                                   remarks=data.get('ps', data.get('remarks', '')),
                                   network=data.get('net', data.get('network', 'tcp')),
                                   tls=data.get('tls', data.get('security', '')), sni=data.get('sni', ''),
                                   path=data.get('path', ''), host=data.get('host', ''), alpn=data.get('alpn', ''),
                                   serviceName=data.get('serviceName', ''),
                                   fingerprint=data.get('fp', data.get('fingerprint', '')), raw_config=data)
        except (ValueError, TypeError) as e:
            logger.debug("Invalid config data: %s", e)
            return None
        return None

    def _generate_xray_config(self, config: ProxyConfig, listen_port: int) -> Dict:
        xray_config = {
            "log": {"loglevel": "warning", "error": os.devnull},
            "inbounds": [{
                "port": listen_port, "listen": "127.0.0.1", "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
                "sniffing": {"enabled": False}
            }],
            "outbounds": [{
                "protocol": config.protocol.value,
                "settings": {},
                "streamSettings": {"sockopt": {"tcpKeepAliveInterval": 30}}
            }]
        }

        if config.protocol == ProxyProtocol.SHADOWSOCKS:
            xray_config["outbounds"][0]["settings"] = {
                "servers": [{"address": config.server, "port": config.port, "method": config.method,
                             "password": config.password, "level": 0}]
            }
        elif config.protocol == ProxyProtocol.VMESS:
            xray_config["outbounds"][0]["settings"] = {
                "vnext": [{"address": config.server, "port": config.port,
                           "users": [{"id": config.uuid, "alterId": config.alterId,
                                      "security": config.cipher, "level": 0}]}]
            }
        elif config.protocol == ProxyProtocol.VLESS:
            xray_config["outbounds"][0]["settings"] = {
                "vnext": [{"address": config.server, "port": config.port,
                           "users": [{"id": config.uuid, "flow": config.flow,
                                      "encryption": config.encryption, "level": 0}]}]
            }

        ss = xray_config["outbounds"][0]["streamSettings"]
        if config.network and config.network != "tcp":
            ss["network"] = config.network
            if config.network == "ws":
                ws = {}
                if config.path:
                    ws["path"] = config.path
                if config.host:
                    ws["headers"] = {"Host": config.host}
                ss["wsSettings"] = ws
            elif config.network == "h2":
                h2 = {}
                if config.path:
                    h2["path"] = config.path
                if config.host:
                    h2["host"] = [config.host]
                ss["httpSettings"] = h2
            elif config.network == "grpc":
                grpc = {}
                if config.serviceName:
                    grpc["serviceName"] = config.serviceName
                ss["grpcSettings"] = grpc

        if config.tls:
            ss["security"] = config.tls
            tls = {}
            if config.sni:
                tls["serverName"] = config.sni
            elif config.host:
                tls["serverName"] = config.host
            if config.alpn:
                tls["alpn"] = config.alpn.split(",") if isinstance(config.alpn, str) else config.alpn
            if config.fingerprint:
                tls["fingerprint"] = config.fingerprint
            tls["allowInsecure"] = True
            if config.tls == "tls":
                ss["tlsSettings"] = tls
            elif config.tls == "reality":
                ss["realitySettings"] = tls

        return xray_config

    def _test_single_config(self, config: ProxyConfig, batch_id: int = 0) -> TestResultData:
        start = time.time()
        proxy_port = None
        process = None
        config_file = None
        op_id = f"test_{config.get_hash()}_{int(time.time())}"

        try:
            self.hang_detector.register_operation(op_id)

            proxy_port = self.port_manager.get_available_port()
            if not proxy_port:
                return TestResultData(config=config, result=TestResult.PORT_CONFLICT,
                                      test_time=time.time() - start, batch_id=batch_id)

            xray_config = self._generate_xray_config(config, proxy_port)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(xray_config, f, indent=2)
                config_file = f.name

            try:
                syntax = subprocess.run(
                    [self.xray_path, 'run', '-test', '-config', config_file],
                    capture_output=True, timeout=1.0, text=True, encoding='utf-8', errors='ignore'
                )
                if syntax.returncode != 0:
                    return TestResultData(config=config, result=TestResult.SYNTAX_ERROR,
                                          test_time=time.time() - start,
                                          error_message=syntax.stderr[:200], batch_id=batch_id)
            except subprocess.TimeoutExpired:
                return TestResultData(config=config, result=TestResult.SYNTAX_ERROR,
                                      test_time=time.time() - start,
                                      error_message="Syntax test timeout", batch_id=batch_id)

            with open(os.devnull, 'w') as devnull:
                process = subprocess.Popen(
                    [self.xray_path, 'run', '-config', config_file],
                    stdout=devnull, stderr=devnull, text=True, encoding='utf-8', errors='ignore'
                )
            self.process_manager.register_process(process)
            time.sleep(0.5)
            if process.poll() is not None:
                return TestResultData(config=config, result=TestResult.CONNECTION_ERROR,
                                      test_time=time.time() - start,
                                      error_message="Xray terminated", batch_id=batch_id)

            ok, ip, rt = self.network_tester.test_proxy_connection(proxy_port)
            if ok:
                res = TestResultData(config=config, result=TestResult.SUCCESS,
                                     test_time=time.time() - start,
                                     response_time=rt, external_ip=ip, proxy_port=proxy_port,
                                     batch_id=batch_id)
                logger.info("SUCCESS %s:%d %.3fs", config.server, config.port, rt)
                self._save_config_immediately(res)
                return res
            else:
                return TestResultData(config=config, result=TestResult.NETWORK_ERROR,
                                      test_time=time.time() - start,
                                      error_message="Network test failed",
                                      proxy_port=proxy_port, batch_id=batch_id)

        except subprocess.TimeoutExpired:
            return TestResultData(config=config, result=TestResult.TIMEOUT,
                                  test_time=time.time() - start, batch_id=batch_id)
        except Exception as e:
            logger.debug("Test error %s:%d – %s", config.server, config.port, e)
            return TestResultData(config=config, result=TestResult.NETWORK_ERROR,
                                  test_time=time.time() - start,
                                  error_message=str(e), batch_id=batch_id)
        finally:
            if process:
                try:
                    process.terminate()
                    try:
                        process.wait(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=0.5)
                    self.process_manager.unregister_process(process)
                except:
                    pass
            if config_file and os.path.exists(config_file):
                try:
                    os.unlink(config_file)
                except:
                    pass
            if proxy_port:
                self.port_manager.release_port(proxy_port)
            self.hang_detector.unregister_operation(op_id)

    def _close_incremental_files(self):
        for h in list(self.output_file_handles.values()) + list(self.url_file_handles.values()):
            try:
                h.close()
            except:
                pass
        self.output_file_handles.clear()
        self.url_file_handles.clear()

    def test_configs(self, configs: List[ProxyConfig], batch_id: int = 0) -> List[TestResultData]:
        if not configs:
            return []
        results = []
        start = time.time()
        logger.info("Batch %d – %d configs", batch_id, len(configs))
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(configs))) as exe:
            future_to_config = {exe.submit(self._test_single_config, cfg, batch_id): cfg for cfg in configs}
            if HAS_TQDM:
                pbar = tqdm(total=len(future_to_config), desc=f"Batch {batch_id}", unit="cfg", ncols=80)
            else:
                logger.info("Progress: 0/%d", len(future_to_config))
            try:
                for fut in as_completed(future_to_config, timeout=min(self.timeout + 5, self.timeout * 1.5)):
                    cfg = future_to_config[fut]
                    try:
                        res = fut.result(timeout=1.0)
                        results.append(res)
                        self._update_stats(res)
                        if res.result == TestResult.SUCCESS:
                            self._save_config_immediately(res)
                        if HAS_TQDM:
                            pbar.update(1)
                            pbar.set_postfix({'ok': self.stats['success'], 'done': len(results)})
                    except TimeoutError:
                        results.append(TestResultData(config=cfg, result=TestResult.TIMEOUT,
                                                      test_time=time.time() - start,
                                                      error_message="Batch timeout", batch_id=batch_id))
                        self._update_stats(results[-1])
            except TimeoutError:
                logger.warning("Batch %d – global timeout, cancelling", batch_id)
                for fut, cfg in future_to_config.items():
                    if not fut.done():
                        fut.cancel()
                        results.append(TestResultData(config=cfg, result=TestResult.TIMEOUT,
                                                      test_time=time.time() - start,
                                                      error_message="Batch timeout", batch_id=batch_id))
                        self._update_stats(results[-1])
            finally:
                if HAS_TQDM:
                    pbar.close()
        logger.info("Batch %d – %d/%d ok (%.1fs)",
                    batch_id, sum(1 for r in results if r.result == TestResult.SUCCESS),
                    len(configs), time.time() - start)
        return results

    def _update_stats(self, result: TestResultData):
        with self.results_lock:
            self.stats['total'] += 1
            proto = result.config.protocol.value
            if proto in self.stats:
                self.stats[proto]['total'] += 1
                if result.result == TestResult.SUCCESS:
                    self.stats[proto]['success'] += 1
                    self.stats['success'] += 1
                else:
                    self.stats[proto]['failed'] += 1
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
        if not configs:
            logger.warning("No configs to test")
            return []
        signal.signal(signal.SIGINT, lambda s, f: (logger.info("Interrupted – shutting down"), self.cleanup(), sys.exit(0)))
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, lambda s, f: (logger.info("Terminated – shutting down"), self.cleanup(), sys.exit(0)))

        self.process_manager.start_monitoring()
        self.hang_detector.start_monitoring()

        all_results = []
        total = len(configs)
        logger.info("Testing %d configs | workers=%d timeout=%ds batch=%d",
                    total, self.max_workers, self.timeout, self.batch_size)
        try:
            for idx, i in enumerate(range(0, total, self.batch_size)):
                batch = configs[i:i + self.batch_size]
                batch_id = idx + 1
                logger.info("Batch %d – %d configs", batch_id, len(batch))
                try:
                    res = self.test_configs(batch, batch_id)
                    all_results.extend(res)
                    self._save_results(all_results)
                    if idx < (total // self.batch_size):
                        time.sleep(0.5)
                except KeyboardInterrupt:
                    logger.info("Batch %d interrupted", batch_id)
                    break
                except Exception as e:
                    logger.error("Batch %d failed: %s", batch_id, e)
                    continue
        except KeyboardInterrupt:
            logger.info("Testing interrupted")
        finally:
            self.process_manager.stop_monitoring()
            self.hang_detector.stop_monitoring()
        if all_results:
            self._print_final_summary(all_results)
        return all_results

    def _print_final_summary(self, results: List[TestResultData]):
        ok = sum(1 for r in results if r.result == TestResult.SUCCESS)
        total = len(results)
        logger.info("=" * 60)
        logger.info("FINAL SUMMARY")
        logger.info("=" * 60)
        logger.info("Total tested: %d", total)
        logger.info("Successful  : %d", ok)
        logger.info("Failed      : %d", total - ok)
        logger.info("Success rate: %.2f%%", ok / total * 100)
        for proto in ['shadowsocks', 'vmess', 'vless']:
            if self.stats[proto]['total']:
                logger.info("%-12s: %d/%d (%.1f%%)", proto.upper(),
                            self.stats[proto]['success'], self.stats[proto]['total'],
                            self.stats[proto]['success'] / self.stats[proto]['total'] * 100)
        if total - ok > 0:
            logger.info("Error breakdown:")
            for err, cnt in [('Connection', self.stats['connection_errors']),
                             ('Timeout', self.stats['timeouts']),
                             ('Parse', self.stats['parse_errors']),
                             ('Syntax', self.stats['syntax_errors']),
                             ('Hang', self.stats['hang_timeouts']),
                             ('Killed', self.stats['process_killed'])]:
                if cnt:
                    logger.info("  %-18s: %d (%.1f%%)", err, cnt, cnt / total * 100)
        times = [r.response_time for r in results if r.result == TestResult.SUCCESS and r.response_time]
        if times:
            logger.info("Response times (success only): avg=%.3fs min=%.3fs max=%.3fs",
                        sum(times) / len(times), min(times), max(times))
        if _unsupported_methods:
            logger.info("Unsupported methods: %s", ", ".join(_unsupported_methods))
        logger.info("=" * 60)

    def _save_results(self, results: List[TestResultData]):
        try:
            with open('../log/test_results.json', 'w', encoding='utf-8') as f:
                json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error("Save results failed: %s", e)

    def cleanup(self):
        try:
            self._close_incremental_files()
            self.process_manager.stop_monitoring()
            self.hang_detector.stop_monitoring()
            self.port_manager = None
        except:
            pass


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Proxy Configuration Tester")
    parser.add_argument('--shadowsocks', '-ss', help="Shadowsocks JSON file")
    parser.add_argument('--vmess', '-vm', help="VMess JSON file")
    parser.add_argument('--vless', '-vl', help="VLESS JSON file")
    parser.add_argument('--workers', '-w', type=int, default=1000, help="Concurrent workers")
    parser.add_argument('--timeout', '-t', type=int, default=8, help="Timeout (seconds)")
    parser.add_argument('--batch-size', '-b', type=int, default=1000, help="Batch size")
    parser.add_argument('--xray-path', '-x', help="Path to Xray executable")
    parser.add_argument('--no-incremental', action='store_true', help="Disable incremental save")
    args = parser.parse_args()

    if not any([args.shadowsocks, args.vmess, args.vless]):
        defaults = {
            'shadowsocks': '../v2ray_config_collector/data/unique/protocols/shadowsocks_configs.json',
            'vmess': '../v2ray_config_collector/data/unique/protocols/vmess_configs.json',
            'vless': '../v2ray_config_collector/data/unique/protocols/vless_configs.json'
        }
        found = []
        for proto, fn in defaults.items():
            if os.path.exists(fn):
                found.append((proto, fn))
        if not found:
            parser.error("Provide at least one config file or place defaults in ../data/raw/")
        for proto, fn in found:
            if proto == 'shadowsocks':
                args.shadowsocks = fn
            elif proto == 'vmess':
                args.vmess = fn
            elif proto == 'vless':
                args.vless = fn

    try:
        tester = EnhancedProxyTester(
            xray_path=args.xray_path,
            max_workers=args.workers,
            timeout=args.timeout,
            batch_size=args.batch_size,
            incremental_save=not args.no_incremental
        )
    except Exception as e:
        logger.error("Init failed: %s", e)
        return

    all_configs = []
    if args.shadowsocks:
        all_configs.extend(tester.load_configs_from_json(args.shadowsocks, ProxyProtocol.SHADOWSOCKS))
    if args.vmess:
        all_configs.extend(tester.load_configs_from_json(args.vmess, ProxyProtocol.VMESS))
    if args.vless:
        all_configs.extend(tester.load_configs_from_json(args.vless, ProxyProtocol.VLESS))

    if not all_configs:
        logger.error("No valid configs to test")
        return

    logger.info("Total unique configs: %d", len(all_configs))
    try:
        results = tester.run_tests(all_configs)
        logger.info("Testing complete – results saved to test_results.json")
        ok = [r for r in results if r.result == TestResult.SUCCESS]
        if ok:
            logger.info("Working configs saved to:")
            for proto in ['shadowsocks', 'vmess', 'vless']:
                if tester.incremental_files.get(proto):
                    logger.info("  JSON: %s", tester.incremental_files[proto])
                if tester.url_files.get(proto):
                    logger.info("  URL : %s", tester.url_files[proto])
        else:
            logger.info("No working configs found")
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Testing failed: %s", e)
    finally:
        tester.cleanup()


if __name__ == "__main__":
    main()