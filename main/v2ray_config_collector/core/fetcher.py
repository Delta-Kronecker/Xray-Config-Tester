import requests
import base64
import time
import re
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
import threading
from tqdm import tqdm
from .logger import get_logger_manager, get_logger
class SourceCollector:
    def __init__(self, input_file=None, output_file=None):
        # Initialize logging
        self.logger_manager = get_logger_manager()
        self.logger = get_logger('fetcher')
        
        package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if input_file is None:
            input_file = os.path.join(package_dir, 'data', 'sources', 'proxy_sources.txt')
        if output_file is None:
            output_file = os.path.join(package_dir, 'data', 'raw', 'raw_configs.txt')
        self.input_file = input_file
        self.output_file = output_file
        self.json_output_file = os.path.join(os.path.dirname(output_file), 'raw_json.json')
        self.base64_output_file = os.path.join(os.path.dirname(output_file), 'raw_base64.txt')
        
        # Log initialization
        self.logger.info("SourceCollector initialized", extra={
            'input_file': input_file,
            'output_file': output_file,
            'json_output_file': self.json_output_file,
            'base64_output_file': self.base64_output_file
        })
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.stats = {
            'total_links': 0,
            'original_links': 0,
            'duplicate_urls_removed': 0,
            'successful_links': 0,
            'failed_links': 0,
            'total_configs': 0,
            'json_content_count': 0,
            'base64_content_count': 0,
            'empty_responses': 0,
            'retry_attempts': 0
        }
        self.failed_urls = []
        self.successful_urls = []
        self.json_contents = []
        self.base64_contents = []
        self.stats_lock = threading.Lock()
        self.print_lock = threading.Lock()

    def safe_print(self, message):
        with self.print_lock:
            print(message)
    def read_links(self):
        self.logger.info("Starting to read source links", extra={'input_file': self.input_file})
        self.logger_manager.start_performance_timer('read_links')
        
        try:
            # Get file size for logging
            file_size = os.path.getsize(self.input_file)
            self.logger.info("Source file analysis", extra={
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024
            })
            
            with open(self.input_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
                links = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
            
            # Log source content analysis
            self.logger.info("Source content analysis", extra={
                'total_lines': len(lines),
                'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
                'empty_lines': len([l for l in lines if not l.strip()]),
                'total_characters': len(content)
            })
            
            # Remove duplicate URLs
            original_count = len(links)
            unique_links = []
            seen_urls = set()
            
            for link in links:
                if link not in seen_urls:
                    unique_links.append(link)
                    seen_urls.add(link)
            
            duplicates_removed = original_count - len(unique_links)
            
            self.stats['original_links'] = original_count
            self.stats['duplicate_urls_removed'] = duplicates_removed
            self.stats['total_links'] = len(unique_links)
            
            # Log deduplication results
            self.logger.info("URL deduplication completed", extra={
                'original_count': original_count,
                'duplicates_removed': duplicates_removed,
                'unique_count': len(unique_links),
                'deduplication_rate': (duplicates_removed / original_count * 100) if original_count > 0 else 0
            })
            
            print(f"Number of links read: {original_count}")
            if duplicates_removed > 0:
                print(f"Duplicate URLs removed: {duplicates_removed}")
                print(f"Unique URLs to process: {len(unique_links)}")
                self.logger.warning(f"Found {duplicates_removed} duplicate URLs in source file")
            else:
                print(f"No duplicate URLs found")
                self.logger.info("No duplicate URLs found in source file")
            
            # Log stage transition
            self.logger_manager.log_stage_transition(
                'url_loading', 
                original_count, 
                len(unique_links),
                input_size=file_size,
                metadata={'duplicates_removed': duplicates_removed}
            )
            
            duration = self.logger_manager.end_performance_timer('read_links', {
                'urls_processed': len(unique_links),
                'file_size': file_size
            })
            
            return unique_links
            
        except FileNotFoundError:
            error_msg = f"Source file {self.input_file} not found!"
            print(error_msg)
            self.logger.error(error_msg, extra={'input_file': self.input_file})
            self.logger_manager.end_performance_timer('read_links')
            return []
        except Exception as e:
            error_msg = f"Error reading source file: {str(e)}"
            self.logger.error(error_msg, extra={'input_file': self.input_file, 'error': str(e)})
            self.logger_manager.end_performance_timer('read_links')
            return []
    def is_base64_encoded(self, text):
        try:
            text = re.sub(r'\s', '', text)
            if len(text) % 4 != 0:
                return False
            base64.b64decode(text, validate=True)
            return True
        except:
            return False
    def is_json_content(self, content):
        try:
            json.loads(content)
            return True
        except:
            return False
    def decode_if_base64(self, content):
        if self.is_base64_encoded(content):
            try:
                decoded = base64.b64decode(content).decode('utf-8')
                return decoded
            except:
                return content
        return content
    def extract_configs(self, content):
        if not content:
            return []
        content = self.decode_if_base64(content)
        patterns = [
            r'vmess://[A-Za-z0-9+/=]+',
            r'vless://[^\s\n]+',
            r'trojan://[^\s\n]+',
            r'ss://[A-Za-z0-9+/=]*@?[^\s\n]*(?:\?[^\s\n#]*)?(?:#[^\s\n]*)?',  # Enhanced shadowsocks pattern
            r'ssr://[A-Za-z0-9+/=]+',
            r'tuic://[^\s\n]+',
            r'hysteria2://[^\s\n]+',
            r'hy2://[^\s\n]+',
        ]
        configs = []
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            configs.extend(matches)
        
        # Remove duplicates and return unique configs
        configs = list(set(configs))
        return configs

    def fetch_url_with_retry(self, url, max_retries=3, show_fetching=True, silent=False, timeout=30):
        for attempt in range(max_retries):
            try:
                if show_fetching and attempt == 0 and not silent:
                    self.safe_print(f"Fetching: {url}")
                response = self.session.get(url, timeout=timeout)
                response.raise_for_status()
                content = response.text.strip()
                original_content = response.text
                if not content:
                    if original_content and self.is_base64_encoded(original_content.replace('\n', '').replace('\r', '').replace(' ', '')):
                        return original_content
                    config_patterns = [
                        r'vmess://[A-Za-z0-9+/=]+',
                        r'vless://[^\s\n]+',
                        r'trojan://[^\s\n]+',
                        r'ss://[A-Za-z0-9+/=]+@[^\s\n]+',
                        r'ssr://[A-Za-z0-9+/=]+',
                        r'tuic://[^\s\n]+',
                        r'hysteria2://[^\s\n]+',
                        r'hy2://[^\s\n]+',
                    ]
                    has_configs = False
                    for pattern in config_patterns:
                        if re.search(pattern, original_content, re.IGNORECASE):
                            has_configs = True
                            break
                    if has_configs:
                        return original_content
                    with self.stats_lock:
                        self.stats['empty_responses'] += 1
                    if attempt < max_retries - 1:
                        if not silent:
                            self.safe_print(f"    Empty response")
                            self.safe_print(f"    Retrying ({attempt + 2}/{max_retries})...")
                        with self.stats_lock:
                            self.stats['retry_attempts'] += 1
                        time.sleep(2)
                        continue
                    return None
                return content
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    if not silent:
                        error_type = str(e).split(':')[0] if ':' in str(e) else str(e)[:30]
                        self.safe_print(f"    {error_type} - Retry {attempt + 2}/{max_retries}")
                    with self.stats_lock:
                        self.stats['retry_attempts'] += 1
                    time.sleep(3)
                else:
                    return None
            except Exception as e:
                if not silent:
                    self.safe_print(f"Unexpected error: {str(e)[:100]}")
                return None
        return None
    def fetch_single_url(self, url_data, pbar=None):
        i, url = url_data
        content = self.fetch_url_with_retry(url, show_fetching=False, silent=True)
        if content:
            if self.is_json_content(content):
                with self.stats_lock:
                    self.stats['successful_links'] += 1
                    self.stats['json_content_count'] += 1
                    self.successful_urls.append(url)
                    self.json_contents.append(content)
                if pbar:
                    pbar.set_postfix({"JSON": f"{self.stats['json_content_count']:,}", "Base64": f"{self.stats['base64_content_count']:,}", "Configs": f"{self.stats['total_configs']:,}"})
                return []
            elif self.is_base64_encoded(content):
                with self.stats_lock:
                    self.stats['successful_links'] += 1
                    self.stats['base64_content_count'] += 1
                    self.successful_urls.append(url)
                    self.base64_contents.append(content)
                if pbar:
                    pbar.set_postfix({"JSON": f"{self.stats['json_content_count']:,}", "Base64": f"{self.stats['base64_content_count']:,}", "Configs": f"{self.stats['total_configs']:,}"})
                return []
            else:
                configs = self.extract_configs(content)
                if configs:
                    with self.stats_lock:
                        self.stats['successful_links'] += 1
                        self.stats['total_configs'] += len(configs)
                        self.successful_urls.append(url)
                    if pbar:
                        pbar.set_postfix({"JSON": f"{self.stats['json_content_count']:,}", "Base64": f"{self.stats['base64_content_count']:,}", "Configs": f"{self.stats['total_configs']:,}"})
                    return configs
                else:
                    with self.stats_lock:
                        self.stats['failed_links'] += 1
                        self.failed_urls.append(url)
                    return []
        else:
            with self.stats_lock:
                self.stats['failed_links'] += 1
                self.failed_urls.append(url)
            return []

    def fetch_all_configs(self, max_workers=5):
        self.logger.info("Starting config fetching process", extra={
            'max_workers': max_workers,
            'method': 'fetch_all_configs'
        })
        self.logger_manager.start_performance_timer('fetch_all_configs')
        
        links = self.read_links()
        if not links:
            self.logger.warning("No links found to process")
            self.logger_manager.end_performance_timer('fetch_all_configs')
            return
            
        self.logger.info("Config fetching initialized", extra={
            'total_urls': len(links),
            'max_workers': max_workers,
            'phase_strategy': 'parallel_then_sequential'
        })
        
        all_configs = []
        print(f"\nPhase 1: Parallel processing of {len(links)} links using {max_workers} threads...")
        
        self.logger.info("Phase 1 starting: Parallel processing", extra={
            'urls_count': len(links),
            'workers': max_workers,
            'phase': 'parallel'
        })
        
        phase1_failed = []
        phase1_successful = 0
        url_data = [(i+1, url) for i, url in enumerate(links)]
        
        # Phase 1 with timeout (5 minutes for the entire phase)
        phase1_timeout = 1200  # 5 minutes
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=len(links), desc="Phase 1 - Parallel", unit="url", 
                     bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} {postfix}') as pbar:
                future_to_url = {executor.submit(self.fetch_single_url, data, pbar): data for data in url_data}
                
                # Use wait with timeout for the entire phase
                start_time = time.time()
                completed_futures = set()
                
                while future_to_url and (time.time() - start_time) < phase1_timeout:
                    remaining_futures = set(future_to_url.keys()) - completed_futures
                    if not remaining_futures:
                        break
                        
                    # Wait for at least one future to complete, with remaining timeout
                    remaining_timeout = phase1_timeout - (time.time() - start_time)
                    if remaining_timeout <= 0:
                        break
                        
                    done, _ = wait(remaining_futures, timeout=min(15, remaining_timeout), return_when=FIRST_COMPLETED)
                    
                    for future in done:
                        completed_futures.add(future)
                        try:
                            configs = future.result()
                            if configs:
                                all_configs.extend(configs)
                                phase1_successful += 1
                            else:
                                url_data_item = future_to_url[future]
                                phase1_failed.append(url_data_item[1])
                        except Exception as e:
                            url_data_item = future_to_url[future]
                            phase1_failed.append(url_data_item[1])
                        finally:
                            pbar.update(1)
                
                # Handle any remaining uncompleted futures as failed
                remaining_futures = set(future_to_url.keys()) - completed_futures
                for future in remaining_futures:
                    future.cancel()
                    url_data_item = future_to_url[future]
                    phase1_failed.append(url_data_item[1])
                    pbar.update(1)
                
                if (time.time() - start_time) >= phase1_timeout:
                    print(f"Phase 1 timeout reached after {phase1_timeout} seconds")
                    self.logger.warning("Phase 1 timeout reached", extra={
                        'timeout_seconds': phase1_timeout,
                        'completed_urls': len(completed_futures),
                        'remaining_urls': len(remaining_futures)
                    })
        
        # Log Phase 1 completion
        phase1_duration = time.time() - start_time
        self.logger.info("Phase 1 completed", extra={
            'successful': phase1_successful,
            'failed': len(phase1_failed),
            'duration': phase1_duration,
            'success_rate': (phase1_successful / len(links) * 100) if len(links) > 0 else 0,
            'configs_extracted': len(all_configs)
        })
        
        print(f"Phase 1 completed: {phase1_successful} successful, {len(phase1_failed)} failed")
        
        if phase1_failed:
            print(f"\nPhase 2: Sequential retry of {len(phase1_failed)} failed links...")
            self.logger.info("Phase 2 starting: Sequential retry", extra={
                'failed_urls_count': len(phase1_failed),
                'phase': 'sequential_retry'
            })
            
            phase2_recovered = 0
            phase2_final_failed = []
            time.sleep(0.1)
            with tqdm(total=len(phase1_failed), desc="Phase 2 - Sequential", unit="url") as pbar:
                for url in phase1_failed:
                    # Use shorter timeout (10 seconds) for Phase 2 retry
                    content = self.fetch_url_with_retry(url, show_fetching=False, silent=True, timeout=30)
                    if content:
                        if self.is_json_content(content):
                            phase2_recovered += 1
                            with self.stats_lock:
                                self.stats['successful_links'] += 1
                                self.stats['json_content_count'] += 1
                                if url not in self.successful_urls:
                                    self.successful_urls.append(url)
                                if url in self.failed_urls:
                                    self.failed_urls.remove(url)
                                self.json_contents.append(content)
                        elif self.is_base64_encoded(content):
                            phase2_recovered += 1
                            with self.stats_lock:
                                self.stats['successful_links'] += 1
                                self.stats['base64_content_count'] += 1
                                if url not in self.successful_urls:
                                    self.successful_urls.append(url)
                                if url in self.failed_urls:
                                    self.failed_urls.remove(url)
                                self.base64_contents.append(content)
                        else:
                            configs = self.extract_configs(content)
                            if configs:
                                all_configs.extend(configs)
                                phase2_recovered += 1
                                with self.stats_lock:
                                    self.stats['successful_links'] += 1
                                    self.stats['total_configs'] += len(configs)
                                    if url not in self.successful_urls:
                                        self.successful_urls.append(url)
                                    if url in self.failed_urls:
                                        self.failed_urls.remove(url)
                            else:
                                phase2_final_failed.append(url)
                    else:
                        phase2_final_failed.append(url)
                    pbar.update(1)
            print(f"Phase 2 completed: {phase2_recovered} recovered, {len(phase2_final_failed)} permanently failed")
            self.failed_urls = phase2_final_failed
            
            # Log Phase 2 completion
            self.logger.info("Phase 2 completed", extra={
                'recovered': phase2_recovered,
                'permanently_failed': len(phase2_final_failed),
                'recovery_rate': (phase2_recovered / len(phase1_failed) * 100) if len(phase1_failed) > 0 else 0
            })
        else:
            self.failed_urls = []
            
        # Log overall fetching completion
        total_successful = phase1_successful + (phase2_recovered if phase1_failed else 0)
        total_failed = len(phase2_final_failed) if phase1_failed else 0
        
        self.logger.info("Config fetching completed", extra={
            'total_urls': len(links),
            'total_successful': total_successful,
            'total_failed': total_failed,
            'overall_success_rate': (total_successful / len(links) * 100) if len(links) > 0 else 0,
            'total_configs_extracted': len(all_configs),
            'json_contents': len(self.json_contents),
            'base64_contents': len(self.base64_contents)
        })
        
        # Log stage transition for fetching
        self.logger_manager.log_stage_transition(
            'config_fetching',
            len(links),
            len(all_configs) + len(self.json_contents) + len(self.base64_contents),
            metadata={
                'direct_configs': len(all_configs),
                'json_contents': len(self.json_contents),
                'base64_contents': len(self.base64_contents),
                'successful_urls': total_successful,
                'failed_urls': total_failed
            }
        )
        
        self.save_configs(all_configs)
        self.save_json_content()
        self.save_base64_content()
        
        # End performance timer
        total_duration = self.logger_manager.end_performance_timer('fetch_all_configs', {
            'total_urls': len(links),
            'configs_extracted': len(all_configs),
            'success_rate': (total_successful / len(links) * 100) if len(links) > 0 else 0
        })
        
        self.print_detailed_summary(all_configs, phase1_successful, len(phase1_failed), 
                                   phase2_recovered if phase1_failed else 0, 
                                   len(phase2_final_failed) if phase1_failed else 0)

    def save_configs(self, configs):
        self.logger.info("Starting to save configs", extra={
            'config_count': len(configs),
            'output_file': self.output_file
        })
        
        if not configs:
            print("No configs found to save!")
            self.logger.warning("No configs to save - empty config list")
            return
            
        try:
            output_dir = os.path.dirname(self.output_file)
            os.makedirs(output_dir, exist_ok=True)
            
            # Calculate total content size
            total_chars = sum(len(config) for config in configs)
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for config in configs:
                    f.write(config + '\n')
            
            # Get file size after writing
            file_size = os.path.getsize(self.output_file)
            
            self.logger.info("Configs saved successfully", extra={
                'config_count': len(configs),
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'total_characters': total_chars,
                'output_file': self.output_file
            })
            
            print(f"{len(configs)} configs saved to file {self.output_file}")
            
        except Exception as e:
            error_msg = f"Error saving configs file: {e}"
            print(error_msg)
            self.logger.error("Failed to save configs", extra={
                'error': str(e),
                'config_count': len(configs),
                'output_file': self.output_file
            })
    def save_json_content(self):
        self.logger.info("Starting to save JSON content", extra={
            'json_content_count': len(self.json_contents),
            'output_file': self.json_output_file
        })
        
        if not self.json_contents:
            print("No JSON content found to save!")
            self.logger.warning("No JSON content to save - empty content list")
            return
            
        try:
            output_dir = os.path.dirname(self.json_output_file)
            os.makedirs(output_dir, exist_ok=True)
            parsed_contents = []
            parse_errors = 0
            
            for i, content in enumerate(self.json_contents):
                try:
                    parsed_json = json.loads(content)
                    parsed_contents.append(parsed_json)
                except json.JSONDecodeError as e:
                    parse_errors += 1
                    self.logger.warning(f"Failed to parse JSON content {i+1}", extra={
                        'content_index': i+1,
                        'error': str(e),
                        'content_preview': content[:100] + '...' if len(content) > 100 else content
                    })
                    continue
                    
            with open(self.json_output_file, 'w', encoding='utf-8') as f:
                json.dump(parsed_contents, f, indent=2, ensure_ascii=False)
                
            # Get file size after writing
            file_size = os.path.getsize(self.json_output_file)
            
            self.logger.info("JSON content saved successfully", extra={
                'original_count': len(self.json_contents),
                'parsed_count': len(parsed_contents),
                'parse_errors': parse_errors,
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'output_file': self.json_output_file
            })
            
            print(f"{len(parsed_contents)} JSON contents saved to file {self.json_output_file}")
            
            if parse_errors > 0:
                self.logger.warning(f"{parse_errors} JSON parsing errors occurred during save")
                
        except Exception as e:
            error_msg = f"Error saving JSON file: {e}"
            print(error_msg)
            self.logger.error("Failed to save JSON content", extra={
                'error': str(e),
                'json_content_count': len(self.json_contents),
                'output_file': self.json_output_file
            })
    def save_base64_content(self):
        self.logger.info("Starting to save Base64 content", extra={
            'base64_content_count': len(self.base64_contents),
            'output_file': self.base64_output_file
        })
        
        if not self.base64_contents:
            print("No base64 content found to save!")
            self.logger.warning("No Base64 content to save - empty content list")
            return
            
        try:
            output_dir = os.path.dirname(self.base64_output_file)
            os.makedirs(output_dir, exist_ok=True)
            
            # Calculate total content size
            total_chars = sum(len(content) for content in self.base64_contents)
            
            with open(self.base64_output_file, 'w', encoding='utf-8') as f:
                for content in self.base64_contents:
                    f.write(content + '\n')
                    
            # Get file size after writing
            file_size = os.path.getsize(self.base64_output_file)
            
            self.logger.info("Base64 content saved successfully", extra={
                'content_count': len(self.base64_contents),
                'file_size_bytes': file_size,
                'file_size_kb': file_size / 1024,
                'total_characters': total_chars,
                'output_file': self.base64_output_file
            })
            
            print(f"{len(self.base64_contents)} base64 contents saved to file {self.base64_output_file}")
            
        except Exception as e:
            error_msg = f"Error saving base64 file: {e}"
            print(error_msg)
            self.logger.error("Failed to save Base64 content", extra={
                'error': str(e),
                'base64_content_count': len(self.base64_contents),
                'output_file': self.base64_output_file
            })

    def print_detailed_summary(self, configs, phase1_successful, phase1_failed, phase2_recovered, phase2_final_failed):
        title = "DETAILED RESULTS SUMMARY"
        print(f"\n{title}")
        print("=" * len(title))
        total_successful = phase1_successful + phase2_recovered
        total_failed = phase2_final_failed
        success_rate = (total_successful / self.stats['total_links']) * 100 if self.stats['total_links'] > 0 else 0
        print(f"Original links found: {self.stats['original_links']}")
        if self.stats['duplicate_urls_removed'] > 0:
            print(f"Duplicate URLs removed: {self.stats['duplicate_urls_removed']}")
        print(f"Unique links processed: {self.stats['total_links']}")
        print(f"Total successful: {total_successful}")
        print(f"Total failed: {total_failed}")
        print(f"Overall success rate: {success_rate:.1f}%")
        print(f"Total configs collected: {len(configs):,}")
        print(f"JSON content found: {self.stats['json_content_count']:,}")
        print(f"Base64 content found: {self.stats['base64_content_count']:,}")
        title = "PHASE BREAKDOWN:"
        print(f"\n{title}")
        print("-" * len(title))
        phase1_rate = (phase1_successful / self.stats['total_links']) * 100 if self.stats['total_links'] > 0 else 0
        print(f"Phase 1 (Parallel Processing):")
        print(f"   Successful: {phase1_successful}")
        print(f"   Failed: {phase1_failed}")
        print(f"   Success rate: {phase1_rate:.1f}%")
        if phase1_failed > 0:
            recovery_rate = (phase2_recovered / phase1_failed) * 100 if phase1_failed > 0 else 0
            print(f"\nPhase 2 (Sequential Retry):")
            print(f"   Attempted: {phase1_failed}")
            print(f"   Recovered: {phase2_recovered}")
            print(f"   Permanently failed: {phase2_final_failed}")
            print(f"   Recovery rate: {recovery_rate:.1f}%")
        title = "TECHNICAL DETAILS:"
        print(f"\n{title}")
        print("-" * len(title))
        print(f"Retry attempts: {self.stats['retry_attempts']}")
        print(f"Empty responses: {self.stats['empty_responses']}")
        if self.failed_urls:
            print(f"\nPERMANENTLY FAILED LINKS ({len(self.failed_urls)}):")
            for i, url in enumerate(self.failed_urls, 1):
                print(f"   {i:2d}. {url}")
        if self.stats['empty_responses'] > 0:
            print(f"\nEMPTY RESPONSE LINKS ({self.stats['empty_responses']}):")
            empty_count = 0
            for url in self.successful_urls + self.failed_urls:
                if empty_count < self.stats['empty_responses']:
                    print(f"   {empty_count + 1:2d}. {url} (had empty responses during retries)")
                    empty_count += 1
        print(f"\nOUTPUT FILES:")
        print(f"   Configs file: {self.output_file}")
        if os.path.exists(self.output_file):
            file_size_kb = os.path.getsize(self.output_file) / 1024
            print(f"   Size: {file_size_kb:,.1f} KB")
        print(f"   JSON file: {self.json_output_file}")
        if os.path.exists(self.json_output_file):
            file_size_kb = os.path.getsize(self.json_output_file) / 1024
            print(f"   Size: {file_size_kb:,.1f} KB")
        print(f"   Base64 file: {self.base64_output_file}")
        if os.path.exists(self.base64_output_file):
            file_size_kb = os.path.getsize(self.base64_output_file) / 1024
            print(f"   Size: {file_size_kb:,.1f} KB")
        print("=" * len("Convert proxy configurations to JSON format"))
def main():
    title = "V2Ray Config Collector"
    print(title)
    print("=" * len(title))
    collector = SourceCollector()
    collector.fetch_all_configs()
if __name__ == "__main__":
    main()