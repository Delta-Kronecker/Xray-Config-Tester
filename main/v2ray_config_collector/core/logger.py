"""
Professional Logging Module for V2Ray Config Collector
======================================================

This module provides comprehensive logging capabilities including:
- Multi-level logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- Structured JSON logging for machine readability
- File rotation to prevent log files from growing too large
- Performance metrics tracking
- Data flow tracking
- Error categorization and detailed failure analysis
- Thread-safe logging for concurrent operations
- Custom formatters for different output types
"""

import logging
import logging.handlers
import json
import os
import time
import threading
import traceback
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Union
from pathlib import Path
from collections import defaultdict, deque
import sys


class DataFlowTracker:
    """Track config counts and data sizes throughout the pipeline"""
    
    def __init__(self):
        self.stages = {}
        self.lock = threading.Lock()
        self.stage_order = []
        
    def record_stage(self, stage_name: str, input_count: int, output_count: int, 
                    input_size: int = 0, output_size: int = 0, metadata: Dict = None):
        """Record data flow for a specific stage"""
        with self.lock:
            timestamp = datetime.now().isoformat()
            stage_data = {
                'timestamp': timestamp,
                'input_count': input_count,
                'output_count': output_count,
                'input_size': input_size,
                'output_size': output_size,
                'loss_count': input_count - output_count,
                'loss_percentage': ((input_count - output_count) / input_count * 100) if input_count > 0 else 0,
                'metadata': metadata or {}
            }
            self.stages[stage_name] = stage_data
            if stage_name not in self.stage_order:
                self.stage_order.append(stage_name)
                
    def get_stage_data(self, stage_name: str) -> Optional[Dict]:
        """Get data for a specific stage"""
        with self.lock:
            return self.stages.get(stage_name)
            
    def get_all_stages(self) -> Dict:
        """Get all stage data"""
        with self.lock:
            return self.stages.copy()
            
    def detect_data_loss(self, threshold_percentage: float = 10.0) -> List[Dict]:
        """Detect stages with significant data loss"""
        with self.lock:
            losses = []
            for stage_name in self.stage_order:
                stage_data = self.stages[stage_name]
                if stage_data['loss_percentage'] > threshold_percentage:
                    losses.append({
                        'stage': stage_name,
                        'loss_count': stage_data['loss_count'],
                        'loss_percentage': stage_data['loss_percentage'],
                        'input_count': stage_data['input_count'],
                        'output_count': stage_data['output_count']
                    })
            return losses


class PerformanceMonitor:
    """Monitor execution metrics and performance"""
    
    def __init__(self):
        self.metrics = defaultdict(list)
        self.lock = threading.Lock()
        self.start_times = {}
        
    def start_timer(self, operation: str):
        """Start timing an operation"""
        with self.lock:
            self.start_times[operation] = time.time()
            
    def end_timer(self, operation: str, metadata: Dict = None):
        """End timing an operation and record metrics"""
        with self.lock:
            if operation in self.start_times:
                duration = time.time() - self.start_times[operation]
                del self.start_times[operation]
                
                # Get current memory usage
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                metric_data = {
                    'timestamp': datetime.now().isoformat(),
                    'duration': duration,
                    'memory_mb': memory_mb,
                    'metadata': metadata or {}
                }
                self.metrics[operation].append(metric_data)
                return duration
        return None
        
    def record_metric(self, operation: str, value: float, unit: str = '', metadata: Dict = None):
        """Record a custom metric"""
        with self.lock:
            metric_data = {
                'timestamp': datetime.now().isoformat(),
                'value': value,
                'unit': unit,
                'metadata': metadata or {}
            }
            self.metrics[operation].append(metric_data)
            
    def get_metrics(self, operation: str = None) -> Dict:
        """Get metrics for an operation or all operations"""
        with self.lock:
            if operation:
                return self.metrics.get(operation, [])
            return dict(self.metrics)
            
    def get_summary(self, operation: str) -> Dict:
        """Get summary statistics for an operation"""
        with self.lock:
            metrics = self.metrics.get(operation, [])
            if not metrics:
                return {}
                
            durations = [m.get('duration', 0) for m in metrics if 'duration' in m]
            if durations:
                return {
                    'count': len(durations),
                    'total_duration': sum(durations),
                    'avg_duration': sum(durations) / len(durations),
                    'min_duration': min(durations),
                    'max_duration': max(durations),
                    'last_memory_mb': metrics[-1].get('memory_mb', 0)
                }
            return {'count': len(metrics)}


class ConfigLossDetector:
    """Detect potential config losses between stages"""
    
    def __init__(self, logger):
        self.logger = logger
        self.expected_counts = {}
        self.actual_counts = {}
        self.lock = threading.Lock()
        
    def set_expected_count(self, stage: str, count: int):
        """Set expected config count for a stage"""
        with self.lock:
            self.expected_counts[stage] = count
            
    def set_actual_count(self, stage: str, count: int):
        """Set actual config count for a stage"""
        with self.lock:
            self.actual_counts[stage] = count
            self._check_loss(stage)
            
    def _check_loss(self, stage: str):
        """Check for config loss in a stage"""
        if stage in self.expected_counts and stage in self.actual_counts:
            expected = self.expected_counts[stage]
            actual = self.actual_counts[stage]
            loss = expected - actual
            loss_percentage = (loss / expected * 100) if expected > 0 else 0
            
            if loss > 0:
                if loss_percentage > 20:  # Critical loss
                    self.logger.error(f"CRITICAL CONFIG LOSS in {stage}: {loss} configs lost ({loss_percentage:.1f}%)", 
                                    extra={'stage': stage, 'expected': expected, 'actual': actual, 'loss': loss})
                elif loss_percentage > 5:  # Warning level
                    self.logger.warning(f"Config loss detected in {stage}: {loss} configs lost ({loss_percentage:.1f}%)",
                                      extra={'stage': stage, 'expected': expected, 'actual': actual, 'loss': loss})
                else:  # Info level for minor losses
                    self.logger.info(f"Minor config loss in {stage}: {loss} configs lost ({loss_percentage:.1f}%)",
                                   extra={'stage': stage, 'expected': expected, 'actual': actual, 'loss': loss})


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'thread_name': record.threadName
        }
        
        # Add extra fields if present
        if hasattr(record, '__dict__'):
            for key, value in record.__dict__.items():
                if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                              'filename', 'module', 'lineno', 'funcName', 'created', 
                              'msecs', 'relativeCreated', 'thread', 'threadName', 'processName', 
                              'process', 'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                    log_entry[key] = value
                    
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_entry, ensure_ascii=False, default=str)


class ColoredConsoleFormatter(logging.Formatter):
    """Colored console formatter for better readability"""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        
        # Format message
        message = record.getMessage()
        
        # Add extra context if available
        extras = []
        if hasattr(record, 'stage'):
            extras.append(f"stage={record.stage}")
        if hasattr(record, 'count'):
            extras.append(f"count={record.count}")
        if hasattr(record, 'duration'):
            extras.append(f"duration={record.duration:.2f}s")
            
        extra_str = f" [{', '.join(extras)}]" if extras else ""
        
        return f"{color}[{timestamp}] {record.levelname:8} {record.name:20} {message}{extra_str}{reset}"


class LoggerManager:
    """Central logging coordinator"""
    
    def __init__(self, base_log_dir: str = None):
        self.base_log_dir = Path(base_log_dir) if base_log_dir else Path("logs")
        self.loggers = {}
        self.data_flow_tracker = DataFlowTracker()
        self.performance_monitor = PerformanceMonitor()
        self.config_loss_detector = None
        self.lock = threading.Lock()
        
        # Create log directories
        self._create_log_directories()
        
        # Setup root logger
        self._setup_root_logger()
        
        # Create main logger
        self.logger = self.get_logger('main')
        self.config_loss_detector = ConfigLossDetector(self.logger)
        
    def _create_log_directories(self):
        """Create all necessary log directories"""
        directories = [
            self.base_log_dir,
            self.base_log_dir / "main",
            self.base_log_dir / "fetcher", 
            self.base_log_dir / "parser",
            self.base_log_dir / "deduplicator",
            self.base_log_dir / "performance",
            self.base_log_dir / "data_flow",
            self.base_log_dir / "errors",
            self.base_log_dir / "daily"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
    def _setup_root_logger(self):
        """Setup root logger configuration"""
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            
    def get_logger(self, name: str, log_level: str = 'INFO') -> logging.Logger:
        """Get or create a logger with specified configuration"""
        with self.lock:
            if name in self.loggers:
                return self.loggers[name]
                
            logger = logging.getLogger(name)
            logger.setLevel(getattr(logging, log_level.upper()))
            
            # Clear existing handlers
            logger.handlers.clear()
            logger.propagate = False
            
            # Console handler with colored output
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(ColoredConsoleFormatter())
            logger.addHandler(console_handler)
            
            # File handler for general logs
            log_file = self.base_log_dir / name / f"{name}.log"
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            logger.addHandler(file_handler)
            
            # JSON handler for structured logs
            json_file = self.base_log_dir / name / f"{name}.json"
            json_handler = logging.handlers.RotatingFileHandler(
                json_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
            )
            json_handler.setLevel(logging.DEBUG)
            json_handler.setFormatter(JSONFormatter())
            logger.addHandler(json_handler)
            
            # Error-specific handler
            error_file = self.base_log_dir / "errors" / f"{name}_errors.log"
            error_handler = logging.handlers.RotatingFileHandler(
                error_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
            ))
            logger.addHandler(error_handler)
            
            self.loggers[name] = logger
            return logger
            
    def log_stage_transition(self, stage_name: str, input_count: int, output_count: int,
                           input_size: int = 0, output_size: int = 0, metadata: Dict = None):
        """Log stage transition with data flow tracking"""
        self.data_flow_tracker.record_stage(stage_name, input_count, output_count, 
                                           input_size, output_size, metadata)
        
        loss = input_count - output_count
        loss_percentage = (loss / input_count * 100) if input_count > 0 else 0
        
        self.logger.info(f"Stage '{stage_name}' completed", extra={
            'stage': stage_name,
            'input_count': input_count,
            'output_count': output_count,
            'loss_count': loss,
            'loss_percentage': loss_percentage,
            'input_size': input_size,
            'output_size': output_size,
            'metadata': metadata
        })
        
        # Check for significant data loss
        if loss_percentage > 10:
            self.logger.warning(f"Significant data loss in stage '{stage_name}': {loss} configs lost ({loss_percentage:.1f}%)")
        elif loss_percentage > 20:
            self.logger.error(f"Critical data loss in stage '{stage_name}': {loss} configs lost ({loss_percentage:.1f}%)")
            
    def start_performance_timer(self, operation: str):
        """Start performance timer for an operation"""
        self.performance_monitor.start_timer(operation)
        
    def end_performance_timer(self, operation: str, metadata: Dict = None):
        """End performance timer and log results"""
        duration = self.performance_monitor.end_timer(operation, metadata)
        if duration:
            self.logger.info(f"Operation '{operation}' completed", extra={
                'operation': operation,
                'duration': duration,
                'metadata': metadata
            })
        return duration
        
    def log_performance_metric(self, operation: str, value: float, unit: str = '', metadata: Dict = None):
        """Log a custom performance metric"""
        self.performance_monitor.record_metric(operation, value, unit, metadata)
        self.logger.debug(f"Performance metric: {operation} = {value} {unit}", extra={
            'metric_name': operation,
            'metric_value': value,
            'metric_unit': unit,
            'metadata': metadata
        })
        
    def generate_daily_report(self) -> Dict:
        """Generate comprehensive daily report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'data_flow': self.data_flow_tracker.get_all_stages(),
            'performance_metrics': self.performance_monitor.get_metrics(),
            'data_losses': self.data_flow_tracker.detect_data_loss(),
            'summary': {
                'total_stages': len(self.data_flow_tracker.stages),
                'total_operations': len(self.performance_monitor.metrics),
                'critical_losses': len([l for l in self.data_flow_tracker.detect_data_loss() if l['loss_percentage'] > 20])
            }
        }
        
        # Save daily report
        daily_file = self.base_log_dir / "daily" / f"report_{datetime.now().strftime('%Y%m%d')}.json"
        try:
            with open(daily_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save daily report: {e}")
            
        return report
        
    def log_config_count(self, stage: str, count: int, config_type: str = 'total'):
        """Log config count for tracking"""
        self.logger.info(f"Config count in {stage}: {count} {config_type} configs", extra={
            'stage': stage,
            'count': count,
            'config_type': config_type
        })
        
    def log_error_with_context(self, message: str, error: Exception = None, context: Dict = None):
        """Log error with full context and traceback"""
        extra_data = {
            'error_type': type(error).__name__ if error else 'Unknown',
            'context': context or {}
        }
        
        if error:
            extra_data['error_message'] = str(error)
            extra_data['traceback'] = traceback.format_exc()
            
        self.logger.error(message, extra=extra_data)
        
    def log_data_integrity_check(self, stage: str, expected: int, actual: int):
        """Log data integrity check results"""
        self.config_loss_detector.set_expected_count(stage, expected)
        self.config_loss_detector.set_actual_count(stage, actual)
        
    def get_performance_summary(self) -> Dict:
        """Get performance summary for all operations"""
        summary = {}
        for operation in self.performance_monitor.metrics:
            summary[operation] = self.performance_monitor.get_summary(operation)
        return summary
        
    def cleanup_old_logs(self, days_to_keep: int = 7):
        """Clean up old log files"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        for log_dir in self.base_log_dir.iterdir():
            if log_dir.is_dir():
                for log_file in log_dir.glob("*.log*"):
                    try:
                        file_time = datetime.fromtimestamp(log_file.stat().st_mtime)
                        if file_time < cutoff_date:
                            log_file.unlink()
                            self.logger.debug(f"Cleaned up old log file: {log_file}")
                    except Exception as e:
                        self.logger.warning(f"Failed to clean up log file {log_file}: {e}")


# Global logger manager instance
_logger_manager = None

def get_logger_manager(base_log_dir: str = None) -> LoggerManager:
    """Get the global logger manager instance"""
    global _logger_manager
    if _logger_manager is None:
        _logger_manager = LoggerManager(base_log_dir)
    return _logger_manager

def get_logger(name: str, log_level: str = 'INFO') -> logging.Logger:
    """Convenience function to get a logger"""
    return get_logger_manager().get_logger(name, log_level)