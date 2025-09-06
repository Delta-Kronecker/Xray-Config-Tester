import json
import os
import hashlib
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm
import time
from .logger import get_logger_manager, get_logger
class ConfigDeduplicator:
    def __init__(self, input_file=None, output_dir=None):
        # Initialize logging
        self.logger_manager = get_logger_manager()
        self.logger = get_logger('deduplicator')
        
        package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if input_file is None:
            input_file = os.path.join(package_dir, 'data', 'processed', 'normalized_configs.json')
        if output_dir is None:
            output_dir = os.path.join(package_dir, 'data', 'unique')
        self.input_file = input_file
        self.output_dir = output_dir
        
        # Log initialization
        self.logger.info("ConfigDeduplicator initialized", extra={
            'input_file': input_file,
            'output_dir': output_dir
        })
        
        self.stats = {
            'total_configs': 0,
            'unique_configs': 0,
            'duplicates_removed': 0,
            'protocols': defaultdict(int),
            'duplicate_groups': 0
        }
        self.configs = []
        self.unique_configs = []
        self.duplicate_groups = []
    def load_configs(self):
        self.logger.info("Starting to load configs for deduplication", extra={
            'input_file': self.input_file
        })
        self.logger_manager.start_performance_timer('load_configs')
        
        try:
            if not os.path.exists(self.input_file):
                error_msg = f"File {self.input_file} not found!"
                print(error_msg)
                self.logger.error("Input file not found", extra={'input_file': self.input_file})
                return False
                
            # Get file size for logging
            file_size = os.path.getsize(self.input_file)
            self.logger.info("Input file analysis", extra={
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'file_size_mb': file_size / (1024 * 1024)
            })
            
            with open(self.input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            if 'configs' in data:
                self.configs = data['configs']
                # Log metadata if available
                if 'metadata' in data:
                    metadata = data['metadata']
                    self.logger.info("Input metadata found", extra={
                        'source_metadata': metadata
                    })
            else:
                self.configs = data if isinstance(data, list) else []
                self.logger.warning("No metadata found in input file - using raw config list")
                
            self.stats['total_configs'] = len(self.configs)
            
            # Analyze protocol distribution
            protocol_stats = defaultdict(int)
            for config in self.configs:
                protocol = config.get('type', 'unknown')
                protocol_stats[protocol] += 1
                self.stats['protocols'][protocol] += 1
                
            self.logger.info("Configs loaded successfully", extra={
                'total_configs': self.stats['total_configs'],
                'protocol_distribution': dict(protocol_stats),
                'unique_protocols': len(protocol_stats)
            })
            
            # Log stage transition for loading
            self.logger_manager.log_stage_transition(
                'config_loading_for_dedup',
                self.stats['total_configs'],
                self.stats['total_configs'],  # No loss in loading
                input_size=file_size,
                metadata={'protocols_found': len(protocol_stats)}
            )
            
            duration = self.logger_manager.end_performance_timer('load_configs', {
                'configs_loaded': self.stats['total_configs'],
                'file_size_mb': file_size / (1024 * 1024)
            })
            
            return True
            
        except Exception as e:
            error_msg = f"Error loading file: {e}"
            print(error_msg)
            self.logger.error("Failed to load configs", extra={
                'input_file': self.input_file,
                'error': str(e)
            })
            self.logger_manager.end_performance_timer('load_configs')
            return False
    def generate_config_hash(self, config):
        """
        Generate hash based only on server address and port for aggressive deduplication.
        Configs with same server and port are considered duplicates regardless of protocol or auth.
        """
        key_parts = []
        
        # Essential parameter 1: Server address
        server = config.get('server', '')
        if isinstance(server, (int, float)):
            server = str(server)
        elif not isinstance(server, str):
            server = str(server)
        key_parts.append(f"server:{server}")
        
        # Essential parameter 2: Port
        port = config.get('port', '')
        if isinstance(port, (int, float)):
            port = str(port)
        elif not isinstance(port, str):
            port = str(port)
        key_parts.append(f"port:{port}")
        
        # Note: Removed protocol type, uuid, password, and all other parameters from hash generation
        # Only server:port combination is used for deduplication
        
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode('utf-8')).hexdigest()
    def find_duplicates(self):
        print("Starting analysis and duplicate detection...")
        self.logger.info("Starting duplicate detection process", extra={
            'total_configs': len(self.configs),
            'deduplication_algorithm': 'hash_based_grouping'
        })
        self.logger_manager.start_performance_timer('find_duplicates')
        
        start_time = time.time()
        hash_to_configs = defaultdict(list)
        
        print("Phase 1: Generating hashes and grouping configs...")
        self.logger.info("Phase 1: Hash generation started")
        
        for i, config in enumerate(tqdm(self.configs, desc="Analyzing configs", unit="config")):
            config_hash = self.generate_config_hash(config)
            config['_hash'] = config_hash
            config['_original_index'] = i
            hash_to_configs[config_hash].append(config)
            
        hash_time = time.time() - start_time
        print(f"Hash generation completed in {hash_time:.2f} seconds")
        print(f"Found {len(hash_to_configs)} unique hash groups")
        
        self.logger.info("Phase 1 completed: Hash generation", extra={
            'duration': hash_time,
            'unique_hash_groups': len(hash_to_configs),
            'total_configs_processed': len(self.configs),
            'processing_speed': len(self.configs) / hash_time if hash_time > 0 else 0
        })
        
        print("\nPhase 2: Processing duplicate groups...")
        self.logger.info("Phase 2: Duplicate group processing started")
        duplicate_start = time.time()
        import sys
        sys.stdout.flush()
        time.sleep(0.1)
        
        duplicate_groups_found = 0
        largest_group_size = 0
        
        for config_hash, configs_group in tqdm(hash_to_configs.items(), desc="Processing groups", unit="group"):
            group_size = len(configs_group)
            if group_size > largest_group_size:
                largest_group_size = group_size
                
            if group_size > 1:
                self.duplicate_groups.append(configs_group)
                self.stats['duplicate_groups'] += 1
                duplicate_groups_found += 1
                
                best_config = self.select_best_config(configs_group)
                self.unique_configs.append(best_config)
                self.stats['duplicates_removed'] += group_size - 1
                
                # Log large duplicate groups
                if group_size > 10:
                    self.logger.warning("Large duplicate group found", extra={
                        'group_size': group_size,
                        'config_hash': config_hash,
                        'protocol': best_config.get('type', 'unknown'),
                        'server': best_config.get('server', 'unknown')
                    })
            else:
                self.unique_configs.append(configs_group[0])
                
        self.stats['unique_configs'] = len(self.unique_configs)
        duplicate_time = time.time() - duplicate_start
        total_time = time.time() - start_time
        
        print(f"Duplicate processing completed in {duplicate_time:.2f} seconds")
        print(f"Total analysis time: {total_time:.2f} seconds")
        
        efficiency = (self.stats['duplicates_removed'] / self.stats['total_configs']) * 100 if self.stats['total_configs'] > 0 else 0
        
        self.logger.info("Duplicate detection completed", extra={
            'total_configs': self.stats['total_configs'],
            'unique_configs': self.stats['unique_configs'],
            'duplicates_removed': self.stats['duplicates_removed'],
            'duplicate_groups': self.stats['duplicate_groups'],
            'efficiency_percentage': efficiency,
            'largest_group_size': largest_group_size,
            'total_duration': total_time,
            'hash_generation_duration': hash_time,
            'processing_duration': duplicate_time,
            'processing_speed': self.stats['total_configs'] / total_time if total_time > 0 else 0
        })
        
        # Log stage transition for deduplication
        self.logger_manager.log_stage_transition(
            'deduplication',
            self.stats['total_configs'],
            self.stats['unique_configs'],
            metadata={
                'duplicates_removed': self.stats['duplicates_removed'],
                'duplicate_groups': self.stats['duplicate_groups'],
                'efficiency_percentage': efficiency,
                'largest_group_size': largest_group_size
            }
        )
        
        print(f"\nDuplicate analysis completed:")
        print(f"   Total: {self.stats['total_configs']:,} | Unique: {self.stats['unique_configs']:,} | Removed: {self.stats['duplicates_removed']:,}")
        print(f"   Optimization: {efficiency:.1f}% | Duplicate groups: {self.stats['duplicate_groups']:,}")
        print(f"   Processing speed: {self.stats['total_configs']/total_time:.0f} configs/second")
        
        duration = self.logger_manager.end_performance_timer('find_duplicates', {
            'configs_processed': self.stats['total_configs'],
            'duplicates_removed': self.stats['duplicates_removed'],
            'efficiency': efficiency
        })
    def select_best_config(self, configs_group):
        def config_score(config):
            score = 0
            if config.get('remarks') and config.get('remarks').strip():
                score += 10
            filled_fields = sum(1 for v in config.values() 
                              if v and str(v).strip() and not str(v).startswith('_'))
            score += filled_fields
            score += config.get('_original_index', 0) * 0.01
            return score
        best_config = max(configs_group, key=config_score)
        return best_config
    def save_all_configs(self):
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Set all configs' remarks to the specified value
            for config in self.unique_configs:
                config['remarks'] = '@XrayTurbo🔥'
            
            output_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'source_file': self.input_file,
                    'total_original_configs': self.stats['total_configs'],
                    'unique_configs': self.stats['unique_configs'],
                    'duplicates_removed': self.stats['duplicates_removed'],
                    'duplicate_groups': self.stats['duplicate_groups'],
                    'protocols': dict(self.stats['protocols'])
                },
                'configs': [self.clean_config(config) for config in self.unique_configs]
            }
            all_configs_file = os.path.join(self.output_dir, 'deduplicated.json')
            with open(all_configs_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            print(f"General JSON file saved ({self.stats['unique_configs']:,} configs)")
            import sys
            sys.stdout.flush()
            time.sleep(0.1)
            all_configs_txt = os.path.join(self.output_dir, 'deduplicated.txt')
            with open(all_configs_txt, 'w', encoding='utf-8') as f:
                f.write(f"Unique V2Ray Configs - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total unique configs: {self.stats['unique_configs']}\n")
                f.write(f"Duplicates removed: {self.stats['duplicates_removed']}\n\n")
                for config in tqdm(self.unique_configs, desc="Writing general TXT file", unit="config", leave=False):
                    url = self.reconstruct_config_url(config)
                    if url:
                        f.write(f"{url}\n")
                    else:
                        f.write(f"{config['type']} - {config.get('server', 'unknown')}:{config.get('port', 'unknown')} - reconstruction failed\n")
            import sys
            sys.stdout.flush()
            time.sleep(0.1)
            print(f"General TXT file saved")
        except Exception as e:
            print(f"Error saving general file: {e}")
    def save_by_protocol(self):
        try:
            print(f"\nSaving protocol files...")
            save_start = time.time()
            protocols_dir = os.path.join(self.output_dir, 'protocols')
            os.makedirs(protocols_dir, exist_ok=True)
            print("Phase 3: Grouping configs by protocol...")
            import sys
            sys.stdout.flush()
            time.sleep(0.1)
            protocol_groups = defaultdict(list)
            for config in self.unique_configs:
                protocol = config.get('type', 'unknown')
                protocol_groups[protocol].append(config)
            sys.stdout.flush()
            time.sleep(0.1)
            print(f"Found {len(protocol_groups)} different protocols")
            print("Phase 4: Writing protocol-specific files...")
            for protocol, configs in protocol_groups.items():
                try:
                    # Set all configs' remarks to the specified value
                    for config in configs:
                        config['remarks'] = '@XrayTurbo🔥'
                    protocol_file = os.path.join(protocols_dir, f'{protocol}_configs.json')
                    protocol_data = {
                        'metadata': {
                            'protocol': protocol,
                            'generated_at': datetime.now().isoformat(),
                            'total_configs': len(configs)
                        },
                        'configs': [self.clean_config(config) for config in configs]
                    }
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        json.dump(protocol_data, f, ensure_ascii=False, indent=2)
                    protocol_txt = os.path.join(protocols_dir, f'{protocol}_configs.txt')
                    with open(protocol_txt, 'w', encoding='utf-8') as f:
                        f.write(f"{protocol.upper()} Configs - Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total configs: {len(configs)}\n")
                        f.write(f"Ready-to-use URLs below:\n\n")
                        for config in tqdm(configs, desc=f"Writing {protocol} configs", unit="config", leave=False):
                            url = self.reconstruct_config_url(config)
                            if url:
                                f.write(f"{url}\n")
                            else:
                                server = config.get('server', 'unknown')
                                port = config.get('port', 'unknown')
                                remarks = config.get('remarks', 'No name')[:50]
                                f.write(f"Failed to reconstruct: {server}:{port} - {remarks}\n")
                    print(f"   {protocol}: {len(configs):,} configs")
                except KeyboardInterrupt:
                    print(f"Saving {protocol} stopped")
                    raise
                except Exception as e:
                    print(f"Error saving {protocol}: {e}")
                    continue
            save_time = time.time() - save_start
            print(f"\nProtocol files saved in {save_time:.2f} seconds")
        except KeyboardInterrupt:
            print("Protocol saving process stopped")
            raise
        except Exception as e:
            print(f"Error saving protocol files: {e}")
    def clean_config(self, config):
        cleaned = config.copy()
        for key in list(cleaned.keys()):
            if key.startswith('_'):
                del cleaned[key]
        return cleaned
    def reconstruct_config_url(self, config):
        try:
            config_copy = config.copy()
            protocol = config_copy.get('type', '')
            if protocol == 'vmess':
                return self.reconstruct_vmess_url(config_copy)
            elif protocol == 'vless':
                return self.reconstruct_vless_url(config_copy)
            elif protocol == 'trojan':
                return self.reconstruct_trojan_url(config_copy)
            elif protocol == 'shadowsocks':
                return self.reconstruct_shadowsocks_url(config_copy)
            elif protocol == 'ssr':
                return self.reconstruct_ssr_url(config_copy)
            elif protocol == 'tuic':
                return self.reconstruct_tuic_url(config_copy)
            elif protocol == 'hysteria2':
                return self.reconstruct_hysteria2_url(config_copy)
            else:
                return None
        except Exception as e:
            return None
    def reconstruct_vmess_url(self, config):
        try:
            if 'raw_config' in config and isinstance(config['raw_config'], dict):
                import base64
                raw_config_copy = config['raw_config'].copy()
                if config.get('remarks'):
                    raw_config_copy['ps'] = config['remarks']
                raw_json = json.dumps(raw_config_copy, separators=(',', ':'))
                encoded = base64.b64encode(raw_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{encoded}"
            else:
                vmess_data = {
                    'v': '2',
                    'ps': config.get('remarks', ''),
                    'add': config.get('server', ''),
                    'port': str(config.get('port', 443)),
                    'id': config.get('uuid', ''),
                    'aid': str(config.get('alterId', 0)),
                    'scy': config.get('cipher', 'auto'),
                    'net': config.get('network', 'tcp'),
                    'type': config.get('type_network', ''),
                    'host': config.get('host', ''),
                    'path': config.get('path', ''),
                    'tls': config.get('tls', ''),
                    'sni': config.get('sni', ''),
                    'alpn': config.get('alpn', ''),
                    'fp': config.get('fingerprint', '')
                }
                import base64
                raw_json = json.dumps(vmess_data, separators=(',', ':'))
                encoded = base64.b64encode(raw_json.encode('utf-8')).decode('utf-8')
                return f"vmess://{encoded}"
        except:
            return None
    def reconstruct_vless_url(self, config):
        try:
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 443)
            uuid = config.get('uuid', '')
            remarks = config.get('remarks', '')
            params = {}
            if config.get('flow'): params['flow'] = config['flow']
            if config.get('encryption'): params['encryption'] = config['encryption']
            if config.get('network'): params['type'] = config['network']
            if config.get('tls'): params['security'] = config['tls']
            if config.get('sni'): params['sni'] = config['sni']
            if config.get('path'): params['path'] = config['path']
            if config.get('host'): params['host'] = config['host']
            if config.get('alpn'): params['alpn'] = config['alpn']
            if config.get('fingerprint'): params['fp'] = config['fingerprint']
            if config.get('headerType'): params['headerType'] = config['headerType']
            if config.get('serviceName'): params['serviceName'] = config['serviceName']
            query_string = urllib.parse.urlencode(params) if params else ''
            fragment = urllib.parse.quote(remarks) if remarks else ''
            url = f"vless://{uuid}@{server}:{port}"
            if query_string:
                url += f"?{query_string}"
            if fragment:
                url += f"#{fragment}"
            return url
        except:
            return None
    def reconstruct_trojan_url(self, config):
        try:
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 443)
            password = config.get('password', '')
            remarks = config.get('remarks', '')
            params = {}
            if config.get('sni'): params['sni'] = config['sni']
            if config.get('alpn'): params['alpn'] = config['alpn']
            if config.get('fingerprint'): params['fp'] = config['fingerprint']
            if config.get('allowInsecure'): params['allowInsecure'] = '1'
            if config.get('network'): params['type'] = config['network']
            if config.get('path'): params['path'] = config['path']
            if config.get('host'): params['host'] = config['host']
            query_string = urllib.parse.urlencode(params) if params else ''
            fragment = urllib.parse.quote(remarks) if remarks else ''
            url = f"trojan://{password}@{server}:{port}"
            if query_string:
                url += f"?{query_string}"
            if fragment:
                url += f"#{fragment}"
            return url
        except:
            return None
    def reconstruct_shadowsocks_url(self, config):
        try:
            import base64
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 8080)
            method = config.get('method', 'aes-256-gcm')
            password = config.get('password', '')
            remarks = config.get('remarks', '')
            auth_string = f"{method}:{password}"
            encoded_auth = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
            url = f"ss://{encoded_auth}@{server}:{port}"
            if remarks:
                url += f"#{urllib.parse.quote(remarks)}"
            return url
        except:
            return None
    def reconstruct_ssr_url(self, config):
        try:
            import base64
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 8080)
            protocol = config.get('protocol', 'origin')
            method = config.get('method', 'aes-256-cfb')
            obfs = config.get('obfs', 'plain')
            password = config.get('password', '')
            password_b64 = base64.b64encode(password.encode('utf-8')).decode('utf-8')
            main_part = f"{server}:{port}:{protocol}:{method}:{obfs}:{password_b64}"
            params = []
            if config.get('obfs_param'):
                obfsparam_b64 = base64.b64encode(config['obfs_param'].encode('utf-8')).decode('utf-8')
                params.append(f"obfsparam={obfsparam_b64}")
            if config.get('protocol_param'):
                protoparam_b64 = base64.b64encode(config['protocol_param'].encode('utf-8')).decode('utf-8')
                params.append(f"protoparam={protoparam_b64}")
            remarks_b64 = base64.b64encode(config.get('remarks', '').encode('utf-8')).decode('utf-8')
            params.append(f"remarks={remarks_b64}")
            if config.get('group'):
                group_b64 = base64.b64encode(config['group'].encode('utf-8')).decode('utf-8')
                params.append(f"group={group_b64}")
            if params:
                full_string = f"{main_part}/?{'&'.join(params)}"
            else:
                full_string = main_part
            encoded = base64.b64encode(full_string.encode('utf-8')).decode('utf-8')
            return f"ssr://{encoded}"
        except:
            return None
    def reconstruct_tuic_url(self, config):
        try:
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 443)
            uuid = config.get('uuid', '')
            password = config.get('password', '')
            remarks = config.get('remarks', '')
            params = {}
            if config.get('version'): params['version'] = config['version']
            if config.get('alpn'): params['alpn'] = config['alpn']
            if config.get('sni'): params['sni'] = config['sni']
            if config.get('allowInsecure'): params['allowInsecure'] = '1'
            if config.get('congestion_control'): params['congestion_control'] = config['congestion_control']
            if config.get('udp_relay_mode'): params['udp_relay_mode'] = config['udp_relay_mode']
            if config.get('reduce_rtt'): params['reduce_rtt'] = '1'
            query_string = urllib.parse.urlencode(params) if params else ''
            fragment = urllib.parse.quote(remarks) if remarks else ''
            auth_part = f"{uuid}:{password}" if password else uuid
            url = f"tuic://{auth_part}@{server}:{port}"
            if query_string:
                url += f"?{query_string}"
            if fragment:
                url += f"#{fragment}"
            return url
        except:
            return None
    def reconstruct_hysteria2_url(self, config):
        try:
            import urllib.parse
            server = config.get('server', '')
            port = config.get('port', 443)
            auth = config.get('auth', '')
            remarks = config.get('remarks', '')
            params = {}
            if config.get('sni'): params['sni'] = config['sni']
            if config.get('insecure'): params['insecure'] = '1'
            if config.get('pinSHA256'): params['pinSHA256'] = config['pinSHA256']
            if config.get('obfs'): params['obfs'] = config['obfs']
            if config.get('obfs_password'): params['obfs-password'] = config['obfs_password']
            if config.get('up'): params['up'] = config['up']
            if config.get('down'): params['down'] = config['down']
            if config.get('alpn'): params['alpn'] = config['alpn']
            query_string = urllib.parse.urlencode(params) if params else ''
            fragment = urllib.parse.quote(remarks) if remarks else ''
            url = f"hysteria2://{auth}@{server}:{port}"
            if query_string:
                url += f"?{query_string}"
            if fragment:
                url += f"#{fragment}"
            return url
        except:
            return None
    def process(self):
        self.logger.info("Starting deduplication process")
        self.logger_manager.start_performance_timer('deduplication_process')
        
        try:
            if not self.load_configs():
                self.logger.error("Failed to load configs - aborting deduplication process")
                self.logger_manager.end_performance_timer('deduplication_process')
                return False
                
            self.find_duplicates()
            self.save_all_configs()
            self.save_by_protocol()
            self.print_final_summary()
            
            # Log overall process completion
            total_duration = self.logger_manager.end_performance_timer('deduplication_process', {
                'total_configs': self.stats['total_configs'],
                'unique_configs': self.stats['unique_configs'],
                'duplicates_removed': self.stats['duplicates_removed'],
                'efficiency': (self.stats['duplicates_removed'] / self.stats['total_configs'] * 100) if self.stats['total_configs'] > 0 else 0
            })
            
            self.logger.info("Deduplication process completed successfully", extra={
                'total_duration': total_duration,
                'final_stats': self.stats
            })
            
            return True
            
        except Exception as e:
            error_msg = f"General process error: {e}"
            print(error_msg)
            self.logger.error("Deduplication process failed", extra={
                'error': str(e),
                'stats_at_failure': self.stats
            })
            self.logger_manager.end_performance_timer('deduplication_process')
            return False
    def print_final_summary(self):
        title = "DUPLICATE REMOVAL - FINAL SUMMARY"
        print(f"\n{title}")
        print("=" * len(title))
        reduction_rate = (self.stats['duplicates_removed'] / self.stats['total_configs']) * 100 if self.stats['total_configs'] > 0 else 0
        print(f"Original configurations: {self.stats['total_configs']:,}")
        print(f"Unique configurations: {self.stats['unique_configs']:,}")
        print(f"Duplicates removed: {self.stats['duplicates_removed']:,}")
        print(f"Duplicate groups found: {self.stats['duplicate_groups']:,}")
        print(f"Size reduction: {reduction_rate:.1f}%")
        print(f"\nBreakdown by protocol:")
        for protocol, count in self.stats['protocols'].items():
            print(f"   {protocol}: {count:,} configs")
        print(f"\nOutput directory: {self.output_dir}")
        print("Files created:")
        print("   • deduplicated.json")
        print("   • deduplicated.txt") 
        print("   • protocols/ (protocol-specific files)")
        print("=" * len("Tests TCP connectivity of proxy configurations"))
def main():
    title = "Remove duplicate configurations"
    print(title)
    print("=" * len(title))
    deduplicator = ConfigDeduplicator()
    success = deduplicator.process()
    if success:
        print("\nProcess completed successfully!")
    else:
        print("\nProcess encountered an error!")
if __name__ == "__main__":
    main()

"""
=============================================================================
                        V2RAY CONFIG DEDUPLICATOR - SUMMARY
=============================================================================

PURPOSE:
--------
این ماژول برای حذف کانفیگ‌های تکراری V2Ray طراحی شده است. هدف آن بهینه‌سازی 
مجموعه کانفیگ‌ها با حذف موارد تکراری بر اساس پارامترهای اساسی است.

CORE FUNCTIONALITY:
------------------
1. بارگذاری کانفیگ‌ها از فایل JSON ورودی
2. تولید هش برای هر کانفیگ بر اساس پارامترهای کلیدی
3. شناسایی و گروه‌بندی کانفیگ‌های تکراری
4. انتخاب بهترین کانفیگ از هر گروه تکراری
5. ذخیره کانفیگ‌های منحصربه‌فرد در فرمت‌های مختلف

DEDUPLICATION LOGIC:
-------------------
کانفیگ‌ها بر اساس این پارامترهای اساسی تکراری تلقی می‌شوند:
✓ آدرس سرور (server) 
✓ شماره پورت (port)

پارامترهای زیر در تشخیص تکراری نادیده گرفته می‌شوند:
✗ نوع پروتکل (type)
✗ اطلاعات احراز هویت (uuid/password)
✗ network, path, host, tls, sni, alpn

SELECTION CRITERIA:
------------------
از میان کانفیگ‌های تکراری، بهترین کانفیگ بر اساس این معیارها انتخاب می‌شود:
- وجود توضیحات (remarks): +10 امتیاز
- تعداد فیلدهای پر شده: +1 امتیاز به ازای هر فیلد
- اولویت بر اساس موقعیت اصلی: +0.01 امتیاز

OUTPUT FORMATS:
--------------
خروجی در فرمت‌های زیر ذخیره می‌شود:
1. deduplicated.json - تمام کانفیگ‌های منحصربه‌فرد با متادیتا
2. deduplicated.txt - URLهای آماده استفاده
3. protocols/ - فایل‌های جداگانه برای هر پروتکل

SUPPORTED PROTOCOLS:
-------------------
- VMess (vmess://)
- VLESS (vless://)
- Trojan (trojan://)
- Shadowsocks (ss://)
- ShadowsocksR (ssr://)
- TUIC (tuic://)
- Hysteria2 (hysteria2://)

PERFORMANCE FEATURES:
--------------------
- پردازش با نوار پیشرفت (tqdm)
- گزارش سرعت پردازش
- آمار تفصیلی کاهش حجم
- مدیریت حافظه بهینه

USAGE:
------
python deduplicator.py
یا
from deduplicator import ConfigDeduplicator
deduplicator = ConfigDeduplicator(input_file, output_dir)
deduplicator.process()

STATISTICS PROVIDED:
-------------------
- تعداد کل کانفیگ‌های اصلی
- تعداد کانفیگ‌های منحصربه‌فرد
- تعداد موارد حذف شده
- درصد کاهش حجم
- توزیع بر اساس پروتکل
- سرعت پردازش

این ماژول به عنوان بخشی از مجموعه ابزارهای v2ray-config-collector عمل می‌کند
و نقش مهمی در بهینه‌سازی و سازماندهی کانفیگ‌های پروکسی ایفا می‌کند.
=============================================================================
"""