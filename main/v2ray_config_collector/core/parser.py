import json
import base64
import urllib.parse
import os
from datetime import datetime
from tqdm import tqdm
from .logger import get_logger_manager, get_logger
def is_valid_port(port):
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False
def is_valid_address_port(address, port):
    if not port:
        return False
    if address is not None and address.strip() == '':
        return False
    return is_valid_port(port)
def parse_server_port(server_port_str):
    if server_port_str.startswith('['):
        if ']:' in server_port_str:
            bracket_end = server_port_str.find(']:')
            server = server_port_str[1:bracket_end]
            port_str = server_port_str[bracket_end + 2:].split('#')[0].split('/')[0].split('?')[0]
            port = int(port_str) if port_str.isdigit() else 443
        else:
            server = server_port_str[1:-1] if server_port_str.endswith(']') else server_port_str[1:]
            port = 443
    elif ':' in server_port_str:
        server = server_port_str.rsplit(':', 1)[0]
        port_str = server_port_str.rsplit(':', 1)[1].split('#')[0].split('/')[0].split('?')[0]
        port = int(port_str) if port_str.isdigit() else 443
    else:
        server = server_port_str.split('#')[0].split('/')[0].split('?')[0]
        port = 443
    return server, port

class FormatConverter:
    def __init__(self, input_files=None, output_file=None):
        # Initialize logging
        self.logger_manager = get_logger_manager()
        self.logger = get_logger('parser')
        
        package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if input_files is None:
            input_files = [
                os.path.join(package_dir, 'data', 'raw', 'raw_configs.txt'),
                os.path.join(package_dir, 'data', 'raw', 'raw_base64.txt'),
                os.path.join(package_dir, 'data', 'raw', 'raw_json.json')
            ]
        if output_file is None:
            output_file = os.path.join(package_dir, 'data', 'processed', 'normalized_configs.json')
        self.input_files = input_files if isinstance(input_files, list) else [input_files]
        self.output_file = output_file
        
        # Log initialization
        self.logger.info("FormatConverter initialized", extra={
            'input_files': self.input_files,
            'output_file': output_file,
            'input_file_count': len(self.input_files)
        })
        
        self.stats = {
            'total_configs': 0,
            'successful_conversions': 0,
            'failed_conversions': 0,
            'filtered_configs': 0,
            'vmess_count': 0,
            'vless_count': 0,
            'trojan_count': 0,
            'ss_count': 0,
            'ssr_count': 0,
            'tuic_count': 0,
            'hysteria_count': 0,
            'other_count': 0
        }
        self.failed_configs = []
        self.filtered_configs = []
        self.failure_reasons = {
            'base64_decode_error': 0,
            'json_parse_error': 0,
            'invalid_format': 0,
            'missing_required_fields': 0,
            'url_parse_error': 0,
            'unknown_protocol': 0,
            'invalid_address_port': 0,
            'general_exception': 0
        }
        self.converted_configs = []

    def safe_decode_base64(self, data):
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            return base64.b64decode(data).decode('utf-8')
        except Exception as e:
            self.failure_reasons['base64_decode_error'] += 1
            return None
    def safe_json_loads(self, data):
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            self.failure_reasons['json_parse_error'] += 1
            return None

    def parse_vmess(self, config_url):
        try:
            encoded_data = config_url.replace('vmess://', '')
            decoded_data = self.safe_decode_base64(encoded_data)
            if not decoded_data:
                return None
            config_data = self.safe_json_loads(decoded_data)
            if not config_data:
                return None
            result = {
                'type': 'vmess',
                'server': config_data.get('add', ''),
                'port': int(config_data.get('port', 0)) if config_data.get('port') else 0,
                'uuid': config_data.get('id', ''),
                'alterId': int(config_data.get('aid', 0)) if config_data.get('aid') else 0,
                'cipher': config_data.get('scy', 'auto'),
                'network': config_data.get('net', 'tcp'),
                'tls': config_data.get('tls', ''),
                'sni': config_data.get('sni', ''),
                'path': config_data.get('path', ''),
                'host': config_data.get('host', ''),
                'remarks': config_data.get('ps', ''),
                'alpn': config_data.get('alpn', ''),
                'fingerprint': config_data.get('fp', ''),
                'type_network': config_data.get('type', ''),
                'security': config_data.get('security', ''),
                'raw_config': config_data
            }
            self.stats['vmess_count'] += 1
            return result
        except Exception as e:
            return None

    def parse_vless(self, config_url):
        try:
            url_data = config_url.replace('vless://', '')
            if '@' not in url_data:
                return None
            uuid_part, server_part = url_data.split('@', 1)
            if '?' in server_part:
                server_port, params = server_part.split('?', 1)
            else:
                server_port = server_part
                params = ''
            if ':' in server_port:
                server = server_port.rsplit(':', 1)[0]
                port_str = server_port.rsplit(':', 1)[1].split('#')[0].split('/')[0]
                port = int(port_str) if port_str.isdigit() else 443
            else:
                server = server_port.split('#')[0].split('/')[0]
                port = 443
            parsed_params = urllib.parse.parse_qs(params)
            remarks = ''
            if '#' in config_url:
                remarks = urllib.parse.unquote(config_url.split('#')[-1])
            result = {
                'type': 'vless',
                'server': server,
                'port': port,
                'uuid': uuid_part,
                'flow': parsed_params.get('flow', [''])[0],
                'encryption': parsed_params.get('encryption', ['none'])[0],
                'network': parsed_params.get('type', ['tcp'])[0],
                'tls': parsed_params.get('security', [''])[0],
                'sni': parsed_params.get('sni', [''])[0],
                'path': parsed_params.get('path', [''])[0],
                'host': parsed_params.get('host', [''])[0],
                'remarks': remarks,
                'alpn': parsed_params.get('alpn', [''])[0],
                'fingerprint': parsed_params.get('fp', [''])[0],
                'headerType': parsed_params.get('headerType', [''])[0],
                'serviceName': parsed_params.get('serviceName', [''])[0],
                'raw_params': parsed_params
            }
            self.stats['vless_count'] += 1
            return result
        except Exception as e:
            return None

    def parse_trojan(self, config_url):
        try:
            url_data = config_url.replace('trojan://', '')
            if '@' not in url_data:
                return None
            password, server_part = url_data.split('@', 1)
            if '?' in server_part:
                server_port, params = server_part.split('?', 1)
            else:
                server_port = server_part
                params = ''
            if ':' in server_port:
                server = server_port.rsplit(':', 1)[0]
                port_str = server_port.rsplit(':', 1)[1].split('#')[0].split('/')[0]
                port = int(port_str) if port_str.isdigit() else 443
            else:
                server = server_port.split('#')[0].split('/')[0]
                port = 443
            parsed_params = urllib.parse.parse_qs(params)
            remarks = ''
            if '#' in config_url:
                remarks = urllib.parse.unquote(config_url.split('#')[-1])
            result = {
                'type': 'trojan',
                'server': server,
                'port': port,
                'password': password,
                'sni': parsed_params.get('sni', [''])[0],
                'alpn': parsed_params.get('alpn', [''])[0],
                'fingerprint': parsed_params.get('fp', [''])[0],

                'allowInsecure': parsed_params.get('allowInsecure', ['0'])[0] == '1',
                'remarks': remarks,
                'network': parsed_params.get('type', ['tcp'])[0],
                'path': parsed_params.get('path', [''])[0],
                'host': parsed_params.get('host', [''])[0],
                'raw_params': parsed_params
            }
            self.stats['trojan_count'] += 1
            return result
        except Exception as e:
            return None

    def parse_shadowsocks(self, config_url):
        try:
            url_data = config_url.replace('ss://', '')
            remarks = ''
            if '#' in config_url:
                remarks = urllib.parse.unquote(config_url.split('#')[-1])
                url_data = url_data.split('#')[0]
            if '?' in url_data and '@' in url_data:
                auth_part, server_params = url_data.split('@', 1)
                if '?' in server_params:
                    server_port, params = server_params.split('?', 1)
                    parsed_params = urllib.parse.parse_qs(params)
                else:
                    server_port = server_params
                    parsed_params = {}
                if ':' in auth_part:
                    method, password = auth_part.split(':', 1)
                else:
                    decoded_auth = self.safe_decode_base64(auth_part)
                    if decoded_auth and ':' in decoded_auth:
                        method, password = decoded_auth.split(':', 1)
                    else:
                        method = 'aes-256-gcm'
                        password = auth_part
                if ':' in server_port:
                    server = server_port.rsplit(':', 1)[0]
                    port_str = server_port.rsplit(':', 1)[1]
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    server = server_port
                    port = 443
                result = {
                    'type': 'shadowsocks',
                    'server': server,
                    'port': port,
                    'method': method,
                    'password': password,
                    'remarks': remarks,
                    'plugin': '',
                    'plugin_opts': '',
                    'non_standard': True,
                    'raw_params': parsed_params
                }
                self.stats['ss_count'] += 1
                return result
            if '@' in url_data:
                auth_part, server_part = url_data.split('@', 1)
                if ':' not in auth_part:
                    decoded_auth = self.safe_decode_base64(auth_part)
                    if decoded_auth and ':' in decoded_auth:
                        method, password = decoded_auth.split(':', 1)
                    else:
                        method = auth_part
                        password = auth_part
                else:
                    method, password = auth_part.split(':', 1)
                if ':' in server_part:
                    server = server_part.rsplit(':', 1)[0]
                    port_str = server_part.rsplit(':', 1)[1].split('?')[0].split('#')[0]
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    server = server_part.split('?')[0].split('#')[0]
                    port = 443
            else:
                decoded_data = self.safe_decode_base64(url_data)
                if not decoded_data or '@' not in decoded_data:
                    return None
                auth_part, server_part = decoded_data.split('@', 1)
                if ':' in auth_part:
                    method, password = auth_part.split(':', 1)
                else:
                    method = auth_part
                    password = auth_part
                if ':' in server_part:
                    server, port_str = server_part.split(':', 1)
                    port_str = port_str.split('?')[0].split('#')[0]
                    port = int(port_str) if port_str.isdigit() else 443
                else:
                    server = server_part
                    port = 443
            result = {
                'type': 'shadowsocks',
                'server': server,
                'port': port,
                'method': method,
                'password': password,
                'remarks': remarks,
                'plugin': '',
                'plugin_opts': ''
            }
            self.stats['ss_count'] += 1
            return result
        except Exception as e:
            return None

    def parse_ssr(self, config_url):
        try:
            encoded_data = config_url.replace('ssr://', '')
            decoded_data = self.safe_decode_base64(encoded_data)
            if not decoded_data:
                return None
            parts = decoded_data.split('/?')
            main_part = parts[0]
            params_part = parts[1] if len(parts) > 1 else ''
            main_parts = main_part.split(':')
            if len(main_parts) < 6:
                while len(main_parts) < 6:
                    main_parts.append('')
                if not main_parts[0] or not main_parts[1]:
                    return None
            server = main_parts[0]
            port = int(main_parts[1])
            protocol = main_parts[2]
            method = main_parts[3]
            obfs = main_parts[4]
            password_b64 = main_parts[5]
            password = self.safe_decode_base64(password_b64) or password_b64
            params = {}
            if params_part:
                param_pairs = params_part.split('&')
                for pair in param_pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        params[key] = urllib.parse.unquote(value)
            obfsparam = self.safe_decode_base64(params.get('obfsparam', '')) or params.get('obfsparam', '')
            protoparam = self.safe_decode_base64(params.get('protoparam', '')) or params.get('protoparam', '')
            group = self.safe_decode_base64(params.get('group', '')) or params.get('group', '')
            remarks = self.safe_decode_base64(params.get('remarks', '')) or params.get('remarks', '')
            result = {
                'type': 'ssr',
                'server': server,
                'port': port,
                'protocol': protocol,
                'method': method,
                'obfs': obfs,
                'password': password,
                'obfs_param': obfsparam,
                'protocol_param': protoparam,
                'remarks': remarks,
                'group': group,
                'raw_params': params
            }
            self.stats['ssr_count'] += 1
            return result
        except Exception as e:
            return None

    def parse_tuic(self, config_url):
        try:
            url_data = config_url.replace('tuic://', '')
            if '@' not in url_data:
                return None
            auth_part, server_part = url_data.split('@', 1)
            if ':' in auth_part:
                uuid, password = auth_part.split(':', 1)
            else:
                uuid = auth_part
                password = ''
            if '?' in server_part:
                server_port, params = server_part.split('?', 1)
            else:
                server_port = server_part
                params = ''
            if ':' in server_port:
                server = server_port.rsplit(':', 1)[0]
                port_str = server_port.rsplit(':', 1)[1].split('#')[0].split('/')[0]
                port = int(port_str) if port_str.isdigit() else 443
            else:
                server = server_port.split('#')[0].split('/')[0]
                port = 443
            parsed_params = urllib.parse.parse_qs(params)
            remarks = ''
            if '#' in config_url:
                remarks = urllib.parse.unquote(config_url.split('#')[-1])
            result = {
                'type': 'tuic',
                'server': server,
                'port': port,
                'uuid': uuid,
                'password': password,
                'version': parsed_params.get('version', ['5'])[0],
                'alpn': parsed_params.get('alpn', ['h3'])[0],
                'sni': parsed_params.get('sni', [''])[0],
                'allowInsecure': parsed_params.get('allowInsecure', ['0'])[0] == '1',
                'congestion_control': parsed_params.get('congestion_control', ['cubic'])[0],
                'udp_relay_mode': parsed_params.get('udp_relay_mode', ['native'])[0],
                'reduce_rtt': parsed_params.get('reduce_rtt', ['0'])[0] == '1',
                'remarks': remarks,
                'raw_params': parsed_params
            }
            self.stats['tuic_count'] += 1
            return result
        except Exception as e:
            return None
    def parse_hysteria2(self, config_url):
        try:
            if config_url.startswith('hysteria2://'):
                url_data = config_url.replace('hysteria2://', '')
            else:
                url_data = config_url.replace('hy2://', '')
            if '@' not in url_data:
                return None
            auth_part, server_part = url_data.split('@', 1)
            if '?' in server_part:
                server_port, params = server_part.split('?', 1)
            else:
                server_port = server_part
                params = ''
            if ':' in server_port:
                server = server_port.rsplit(':', 1)[0]
                port_str = server_port.rsplit(':', 1)[1].split('#')[0].split('/')[0]
                port = int(port_str) if port_str.isdigit() else 443
            else:
                server = server_port.split('#')[0].split('/')[0]
                port = 443
            parsed_params = urllib.parse.parse_qs(params)
            remarks = ''
            if '#' in config_url:
                remarks = urllib.parse.unquote(config_url.split('#')[-1])
            result = {
                'type': 'hysteria2',
                'server': server,
                'port': port,
                'auth': auth_part,
                'sni': parsed_params.get('sni', [''])[0],
                'insecure': parsed_params.get('insecure', ['0'])[0] == '1',
                'pinSHA256': parsed_params.get('pinSHA256', [''])[0],
                'obfs': parsed_params.get('obfs', [''])[0],
                'obfs_password': parsed_params.get('obfs-password', [''])[0],
                'up': parsed_params.get('up', [''])[0],
                'down': parsed_params.get('down', [''])[0],
                'alpn': parsed_params.get('alpn', ['h3'])[0],
                'remarks': remarks,
                'raw_params': parsed_params
            }
            self.stats['hysteria_count'] += 1
            return result
        except Exception as e:
            return None

    def detect_protocol(self, config_line):
        if config_line.startswith('vmess://'):
            return 'vmess'
        elif config_line.startswith('vless://'):
            return 'vless'
        elif config_line.startswith('trojan://'):
            return 'trojan'
        elif config_line.startswith('ss://'):
            return 'shadowsocks'
        elif config_line.startswith('ssr://'):
            return 'ssr'
        elif config_line.startswith('tuic://'):
            return 'tuic'
        elif config_line.startswith(('hysteria2://', 'hy2://')):
            return 'hysteria2'
        else:
            return 'unknown'
    def parse_config_with_reason(self, config_line):
        config_line = config_line.strip()
        if not config_line or config_line.startswith('#'):
            return None, 'empty_or_comment'
        try:
            if config_line.startswith('vmess://'):
                result = self.parse_vmess(config_line)
                return result, None if result else 'vmess_parse_failed'
            elif config_line.startswith('vless://'):
                result = self.parse_vless(config_line)
                return result, None if result else 'vless_parse_failed'
            elif config_line.startswith('trojan://'):
                result = self.parse_trojan(config_line)
                return result, None if result else 'trojan_parse_failed'
            elif config_line.startswith('ss://'):
                result = self.parse_shadowsocks(config_line)
                return result, None if result else 'shadowsocks_parse_failed'
            elif config_line.startswith('ssr://'):
                result = self.parse_ssr(config_line)
                return result, None if result else 'ssr_parse_failed'
            elif config_line.startswith('tuic://'):
                result = self.parse_tuic(config_line)
                return result, None if result else 'tuic_parse_failed'
            elif config_line.startswith(('hysteria2://', 'hy2://')):
                result = self.parse_hysteria2(config_line)
                return result, None if result else 'hysteria2_parse_failed'
            else:
                self.stats['other_count'] += 1
                self.failure_reasons['unknown_protocol'] += 1
                return None, 'unknown_protocol'
        except Exception as e:
            self.failure_reasons['general_exception'] += 1
            return None, f'exception: {str(e)[:50]}'
    def parse_config(self, config_line):
        result, _ = self.parse_config_with_reason(config_line)
        return result

    def read_base64_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            decoded_lines = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                decoded_content = self.safe_decode_base64(line)
                if decoded_content:
                    config_lines = decoded_content.split('\n')
                    decoded_lines.extend([l.strip() for l in config_lines if l.strip()])
                else:
                    if any(line.startswith(proto) for proto in 
                           ['vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://', 'hy2://']):
                        decoded_lines.append(line)
            return decoded_lines
        except FileNotFoundError:
            print(f"File {file_path} not found!")
            return []
        except Exception as e:
            print(f"Error reading base64 file {file_path}: {e}")
            return []
    def read_json_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
            configs = []
            if isinstance(json_data, list):
                for item in json_data:
                    configs.extend(self.extract_configs_from_json(item))
            elif isinstance(json_data, dict):
                configs.extend(self.extract_configs_from_json(json_data))
            return configs
        except FileNotFoundError:
            print(f"File {file_path} not found!")
            return []
        except Exception as e:
            print(f"Error reading JSON file {file_path}: {e}")
            return []
    def extract_configs_from_json(self, json_obj):
        configs = []
        def search_configs(obj):
            if isinstance(obj, dict):
                if 'outbounds' in obj and isinstance(obj['outbounds'], list):
                    for outbound in obj['outbounds']:
                        if isinstance(outbound, dict):
                            config_url = self.convert_structured_to_url(outbound)
                            if config_url:
                                configs.append(config_url)
                for key, value in obj.items():
                    if isinstance(value, str) and any(value.startswith(proto) for proto in 
                        ['vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://', 'tuic://', 'hysteria2://', 'hy2://']):
                        configs.append(value)
                    elif isinstance(value, (dict, list)):
                        search_configs(value)
            elif isinstance(obj, list):
                for item in obj:
                    search_configs(item)
        search_configs(json_obj)
        return configs
    def convert_structured_to_url(self, outbound):
        try:
            if not isinstance(outbound, dict):
                return None
            config_type = outbound.get('type', '').lower()
            if config_type == 'hysteria2':
                server = outbound.get('server', '')
                server_port = outbound.get('server_port', 443)
                password = outbound.get('password', '')
                tag = outbound.get('tag', '')
                if server and password:
                    url = f"hysteria2://{password}@{server}:{server_port}"
                    if tag:
                        url += f"#{tag}"
                    return url
            elif config_type == 'wireguard':
                settings = outbound.get('settings', {})
                peers = settings.get('peers', [])
                if peers and len(peers) > 0:
                    endpoint = peers[0].get('endpoint', '')
                    public_key = peers[0].get('publicKey', '')
                    tag = outbound.get('tag', '')
                    if endpoint and public_key:
                        return f"# Wireguard config: {tag} - {endpoint}"
            return None
        except Exception:
            return None

    def convert_configs(self):
        self.logger.info("Starting config conversion process")
        self.logger_manager.start_performance_timer('convert_configs')
        
        all_lines = []
        total_files_processed = 0
        file_stats = {}
        
        # Process each input file
        for file_path in self.input_files:
            if not os.path.exists(file_path):
                print(f"File {file_path} not found, skipping...")
                self.logger.warning("Input file not found", extra={'file_path': file_path})
                continue
                
            self.logger.info("Processing input file", extra={'file_path': file_path})
            print(f"Processing file: {file_path}")
            
            # Get file size for logging
            file_size = os.path.getsize(file_path)
            file_type = 'unknown'
            configs_from_file = []
            
            if file_path.endswith('.json'):
                file_type = 'json'
                configs_from_file = self.read_json_file(file_path)
                all_lines.extend(configs_from_file)
                print(f"Extracted {len(configs_from_file)} configs from JSON file")
            elif 'base64' in file_path.lower():
                file_type = 'base64'
                configs_from_file = self.read_base64_file(file_path)
                all_lines.extend(configs_from_file)
                print(f"Decoded {len(configs_from_file)} lines from base64 file")
            else:
                file_type = 'text'
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    configs_from_file = [line.strip() for line in lines]
                    all_lines.extend(configs_from_file)
                    print(f"Read {len(lines)} lines from text file")
                except Exception as e:
                    error_msg = f"Error reading file {file_path}: {e}"
                    print(error_msg)
                    self.logger.error("Failed to read input file", extra={
                        'file_path': file_path,
                        'error': str(e)
                    })
                    continue
                    
            # Log file processing results
            file_stats[file_path] = {
                'file_type': file_type,
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'configs_extracted': len(configs_from_file)
            }
            
            self.logger.info("File processed successfully", extra={
                'file_path': file_path,
                'file_type': file_type,
                'file_size_kb': file_size / 1024,
                'configs_extracted': len(configs_from_file)
            })
            
            total_files_processed += 1
            
        if not all_lines:
            print("No configs found in any input files!")
            self.logger.error("No configs found in any input files")
            self.logger_manager.end_performance_timer('convert_configs')
            return
            
        # Log input analysis summary
        total_input_size = sum(stats['file_size_bytes'] for stats in file_stats.values())
        self.logger.info("Input analysis completed", extra={
            'total_files_processed': total_files_processed,
            'total_configs_loaded': len(all_lines),
            'total_input_size_kb': total_input_size / 1024,
            'file_breakdown': file_stats
        })
        
        print(f"\nTotal configs from {total_files_processed} files: {len(all_lines)}")
        print("=" * len(f"Total configs from {total_files_processed} files: {len(all_lines)}"))
        # Log stage transition for input loading
        self.logger_manager.log_stage_transition(
            'config_loading',
            len(all_lines),
            len(all_lines),  # No loss in loading stage
            input_size=total_input_size,
            metadata={'files_processed': total_files_processed}
        )
        
        self.logger.info("Starting config parsing", extra={
            'total_lines': len(all_lines),
            'parsing_stage': 'individual_config_processing'
        })
        
        with tqdm(total=len(all_lines), desc="Processing configs", unit="line") as pbar:
            for i, line in enumerate(all_lines, 1):
                line = line.strip()
                pbar.update(1)
                if not line or line.startswith('#'):
                    continue
                    
                self.stats['total_configs'] += 1
                parsed_config, failure_reason = self.parse_config_with_reason(line)
                
                if parsed_config:
                    server = parsed_config.get('server', '')
                    port = parsed_config.get('port', 0)
                    protocol = parsed_config.get('type', 'unknown')
                    
                    if is_valid_address_port(server, port):
                        parsed_config['id'] = self.stats['total_configs']
                        parsed_config['line_number'] = i
                        parsed_config['parsed_at'] = datetime.now().isoformat()
                        self.converted_configs.append(parsed_config)
                        self.stats['successful_conversions'] += 1
                    else:
                        self.stats['filtered_configs'] += 1
                        self.failure_reasons['invalid_address_port'] += 1
                        self.filtered_configs.append({
                            'line_number': i,
                            'raw_config': line[:100] + ('...' if len(line) > 100 else ''),
                            'filter_reason': 'invalid_address_or_port',
                            'server': server,
                            'port': port,
                            'protocol': protocol
                        })
                        
                        # Log filtered config
                        self.logger.debug("Config filtered due to invalid address/port", extra={
                            'line_number': i,
                            'protocol': protocol,
                            'server': server,
                            'port': port,
                            'reason': 'invalid_address_or_port'
                        })
                else:
                    self.stats['failed_conversions'] += 1
                    protocol = self.detect_protocol(line)
                    self.failed_configs.append({
                        'line_number': i,
                        'raw_config': line[:100] + ('...' if len(line) > 100 else ''),
                        'failure_reason': failure_reason,
                        'protocol': protocol
                    })
                    
                    # Log failed conversion
                    self.logger.debug("Config conversion failed", extra={
                        'line_number': i,
                        'protocol': protocol,
                        'failure_reason': failure_reason,
                        'config_preview': line[:50] + '...' if len(line) > 50 else line
                    })
        
        # Log conversion completion
        success_rate = (self.stats['successful_conversions'] / self.stats['total_configs'] * 100) if self.stats['total_configs'] > 0 else 0
        filter_rate = (self.stats['filtered_configs'] / self.stats['total_configs'] * 100) if self.stats['total_configs'] > 0 else 0
        
        self.logger.info("Config parsing completed", extra={
            'total_configs': self.stats['total_configs'],
            'successful_conversions': self.stats['successful_conversions'],
            'failed_conversions': self.stats['failed_conversions'],
            'filtered_configs': self.stats['filtered_configs'],
            'success_rate': success_rate,
            'filter_rate': filter_rate,
            'protocol_breakdown': {
                'vmess': self.stats['vmess_count'],
                'vless': self.stats['vless_count'],
                'trojan': self.stats['trojan_count'],
                'shadowsocks': self.stats['ss_count'],
                'ssr': self.stats['ssr_count'],
                'tuic': self.stats['tuic_count'],
                'hysteria2': self.stats['hysteria_count'],
                'other': self.stats['other_count']
            }
        })
        
        # Log stage transition for parsing
        self.logger_manager.log_stage_transition(
            'config_parsing',
            self.stats['total_configs'],
            self.stats['successful_conversions'],
            metadata={
                'failed_conversions': self.stats['failed_conversions'],
                'filtered_configs': self.stats['filtered_configs'],
                'success_rate': success_rate
            }
        )
        
        self.save_json()
        
        # End performance timer
        duration = self.logger_manager.end_performance_timer('convert_configs', {
            'total_configs': self.stats['total_configs'],
            'successful_conversions': self.stats['successful_conversions'],
            'success_rate': success_rate
        })
        
        self.print_summary()

    def save_json(self):
        self.logger.info("Starting to save converted configs", extra={
            'converted_configs_count': len(self.converted_configs),
            'output_file': self.output_file
        })
        
        try:
            output_dir = os.path.dirname(self.output_file)
            os.makedirs(output_dir, exist_ok=True)
            
            output_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'source_files': self.input_files,
                    'total_configs': len(self.converted_configs),
                    'statistics': self.stats,
                    'failure_reasons': self.failure_reasons
                },
                'configs': self.converted_configs,
                'failed_configs': self.failed_configs[:10],
                'filtered_configs': self.filtered_configs[:10]
            }
            
            # Calculate output data size
            json_str = json.dumps(output_data, ensure_ascii=False, indent=2)
            output_size = len(json_str.encode('utf-8'))
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(json_str)
                
            # Get actual file size
            file_size = os.path.getsize(self.output_file)
            
            self.logger.info("Converted configs saved successfully", extra={
                'converted_configs_count': len(self.converted_configs),
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'output_file': self.output_file,
                'failed_configs_included': len(self.failed_configs[:10]),
                'filtered_configs_included': len(self.filtered_configs[:10])
            })
            
            # Log stage transition for saving
            self.logger_manager.log_stage_transition(
                'config_saving',
                len(self.converted_configs),
                len(self.converted_configs),  # No loss in saving
                output_size=file_size,
                metadata={
                    'output_format': 'json',
                    'metadata_included': True
                }
            )
            
            print(f"{len(self.converted_configs)} configs saved to file {self.output_file}")
            
        except Exception as e:
            error_msg = f"Error saving JSON file: {e}"
            print(error_msg)
            self.logger.error("Failed to save converted configs", extra={
                'error': str(e),
                'converted_configs_count': len(self.converted_configs),
                'output_file': self.output_file
            })
    def print_summary(self):
        title = "JSON Conversion Summary:"
        print(f"\n{title}")
        print("=" * len(title))
        print(f"Total configs: {self.stats['total_configs']}")
        print(f"Successful conversions: {self.stats['successful_conversions']}")
        print(f"Filtered (invalid address/port): {self.stats['filtered_configs']}")
        print(f"Failed conversions: {self.stats['failed_conversions']}")
        if self.stats['total_configs'] > 0:
            success_rate = (self.stats['successful_conversions'] / self.stats['total_configs']) * 100
            filter_rate = (self.stats['filtered_configs'] / self.stats['total_configs']) * 100
            print(f"Success rate: {success_rate:.1f}%")
            print(f"Filter rate: {filter_rate:.1f}%")
        print(f"\nStatistics by type:")
        print(f"   VMess: {self.stats['vmess_count']}")
        print(f"   VLess: {self.stats['vless_count']}")
        print(f"   Trojan: {self.stats['trojan_count']}")
        print(f"   Shadowsocks: {self.stats['ss_count']}")
        print(f"   SSR: {self.stats['ssr_count']}")
        print(f"   TUIC: {self.stats['tuic_count']}")
        print(f"   Hysteria2: {self.stats['hysteria_count']}")
        print(f"   Others: {self.stats['other_count']}")
        print(f"\nOutput file: {self.output_file}")
        try:
            import os
            file_size = os.path.getsize(self.output_file) / 1024
            print(f"File size: {file_size:.1f} KB")
        except:
            pass
        print("=" * len("Remove duplicate configurations"))
def main():
    title = "Convert proxy configurations to JSON format"
    print(title)
    print("=" * len(title))
    converter = FormatConverter()
    converter.convert_configs()
if __name__ == "__main__":
    main()