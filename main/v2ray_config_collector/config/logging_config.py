"""
Logging Configuration Module for V2Ray Config Collector
======================================================

This module provides configurable settings for the logging system including:
- Log levels per module
- Output formats and destinations
- File rotation settings
- Performance monitoring thresholds
- Data loss detection sensitivity
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
import json

class LoggingConfig:
    """Configuration class for the logging system"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default logging configuration"""
        return {
            # Global settings
            "global": {
                "base_log_dir": "logs",
                "log_retention_days": 7,
                "enable_console_output": True,
                "enable_file_output": True,
                "enable_json_output": True,
                "enable_error_file": True
            },
            
            # Log levels per module
            "log_levels": {
                "main": "INFO",
                "fetcher": "INFO", 
                "parser": "INFO",
                "deduplicator": "INFO",
                "logger": "WARNING",
                "root": "INFO"
            },
            
            # File rotation settings
            "file_rotation": {
                "max_file_size_mb": 10,
                "backup_count": 5,
                "error_file_size_mb": 5,
                "error_backup_count": 3
            },
            
            # Console output settings
            "console": {
                "level": "INFO",
                "colored_output": True,
                "show_timestamp": True,
                "show_module": True,
                "show_extras": True
            },
            
            # File output settings
            "file_output": {
                "level": "DEBUG",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "date_format": "%Y-%m-%d %H:%M:%S"
            },
            
            # JSON output settings
            "json_output": {
                "level": "DEBUG",
                "pretty_print": True,
                "include_extras": True,
                "include_traceback": True
            },
            
            # Performance monitoring settings
            "performance": {
                "enable_monitoring": True,
                "slow_operation_threshold_seconds": 30.0,
                "memory_warning_threshold_mb": 500.0,
                "log_performance_metrics": True,
                "detailed_timing": True
            },
            
            # Data loss detection settings
            "data_loss_detection": {
                "enable_detection": True,
                "warning_threshold_percentage": 5.0,
                "critical_threshold_percentage": 20.0,
                "log_minor_losses": False,
                "track_protocol_specific_losses": True
            },
            
            # Stage-specific settings
            "stages": {
                "fetcher": {
                    "log_url_details": False,
                    "log_retry_attempts": True,
                    "log_empty_responses": True,
                    "log_phase_statistics": True
                },
                "parser": {
                    "log_conversion_failures": True,
                    "log_filtered_configs": False,
                    "log_protocol_breakdown": True,
                    "detailed_error_logging": True
                },
                "deduplicator": {
                    "log_duplicate_groups": True,
                    "log_large_groups_threshold": 10,
                    "log_selection_criteria": False,
                    "track_hash_collisions": True
                }
            },
            
            # Report generation settings
            "reporting": {
                "generate_daily_reports": True,
                "include_performance_metrics": True,
                "include_data_flow_analysis": True,
                "include_error_summary": True,
                "report_format": "json",
                "compress_old_reports": True
            },
            
            # Advanced settings
            "advanced": {
                "async_logging": False,
                "buffer_size": 1024,
                "flush_interval_seconds": 5.0,
                "enable_debug_mode": False,
                "log_internal_errors": True
            }
        }
    
    def _load_config_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
            
            # Merge with default config
            self._deep_merge(self.config, file_config)
            
        except Exception as e:
            print(f"Warning: Failed to load config file {config_file}: {e}")
            print("Using default configuration")
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'global.base_log_dir')"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config_dict = self.config
        
        for key in keys[:-1]:
            if key not in config_dict:
                config_dict[key] = {}
            config_dict = config_dict[key]
        
        config_dict[keys[-1]] = value
    
    def get_log_level(self, module_name: str) -> str:
        """Get log level for a specific module"""
        return self.get(f'log_levels.{module_name}', self.get('log_levels.root', 'INFO'))
    
    def get_base_log_dir(self) -> Path:
        """Get base log directory as Path object"""
        return Path(self.get('global.base_log_dir', 'logs'))
    
    def is_performance_monitoring_enabled(self) -> bool:
        """Check if performance monitoring is enabled"""
        return self.get('performance.enable_monitoring', True)
    
    def get_slow_operation_threshold(self) -> float:
        """Get threshold for slow operation warnings"""
        return self.get('performance.slow_operation_threshold_seconds', 30.0)
    
    def is_data_loss_detection_enabled(self) -> bool:
        """Check if data loss detection is enabled"""
        return self.get('data_loss_detection.enable_detection', True)
    
    def get_data_loss_thresholds(self) -> Dict[str, float]:
        """Get data loss detection thresholds"""
        return {
            'warning': self.get('data_loss_detection.warning_threshold_percentage', 5.0),
            'critical': self.get('data_loss_detection.critical_threshold_percentage', 20.0)
        }
    
    def should_log_performance_metrics(self) -> bool:
        """Check if performance metrics should be logged"""
        return self.get('performance.log_performance_metrics', True)
    
    def get_file_rotation_settings(self) -> Dict[str, Any]:
        """Get file rotation settings"""
        return {
            'max_bytes': self.get('file_rotation.max_file_size_mb', 10) * 1024 * 1024,
            'backup_count': self.get('file_rotation.backup_count', 5),
            'error_max_bytes': self.get('file_rotation.error_file_size_mb', 5) * 1024 * 1024,
            'error_backup_count': self.get('file_rotation.error_backup_count', 3)
        }
    
    def get_console_settings(self) -> Dict[str, Any]:
        """Get console output settings"""
        return {
            'level': self.get('console.level', 'INFO'),
            'colored': self.get('console.colored_output', True),
            'show_timestamp': self.get('console.show_timestamp', True),
            'show_module': self.get('console.show_module', True),
            'show_extras': self.get('console.show_extras', True)
        }
    
    def save_config(self, output_file: str):
        """Save current configuration to file"""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Failed to save config to {output_file}: {e}")
    
    def validate_config(self) -> Dict[str, Any]:
        """Validate configuration and return validation results"""
        issues = []
        warnings = []
        
        # Validate log levels
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        for module, level in self.get('log_levels', {}).items():
            if level.upper() not in valid_levels:
                issues.append(f"Invalid log level '{level}' for module '{module}'")
        
        # Validate file sizes
        max_size = self.get('file_rotation.max_file_size_mb', 10)
        if max_size <= 0 or max_size > 1000:
            warnings.append(f"File size {max_size}MB may be too small or large")
        
        # Validate thresholds
        warning_threshold = self.get('data_loss_detection.warning_threshold_percentage', 5.0)
        critical_threshold = self.get('data_loss_detection.critical_threshold_percentage', 20.0)
        
        if warning_threshold >= critical_threshold:
            issues.append("Warning threshold must be less than critical threshold")
        
        if warning_threshold < 0 or critical_threshold < 0:
            issues.append("Thresholds must be positive values")
        
        # Validate paths
        base_dir = self.get('global.base_log_dir', 'logs')
        try:
            Path(base_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            issues.append(f"Cannot create log directory '{base_dir}': {e}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
    
    def get_stage_config(self, stage_name: str) -> Dict[str, Any]:
        """Get configuration for a specific stage"""
        return self.get(f'stages.{stage_name}', {})
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return json.dumps(self.config, indent=2, ensure_ascii=False)


# Global configuration instance
_global_config = None

def get_logging_config(config_file: Optional[str] = None) -> LoggingConfig:
    """Get global logging configuration instance"""
    global _global_config
    if _global_config is None:
        _global_config = LoggingConfig(config_file)
    return _global_config

def reload_config(config_file: Optional[str] = None):
    """Reload global configuration"""
    global _global_config
    _global_config = LoggingConfig(config_file)

def create_sample_config(output_file: str):
    """Create a sample configuration file"""
    config = LoggingConfig()
    config.save_config(output_file)
    print(f"Sample configuration saved to: {output_file}")