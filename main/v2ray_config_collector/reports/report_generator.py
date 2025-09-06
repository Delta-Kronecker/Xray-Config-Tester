"""
Comprehensive Reporting Module for V2Ray Config Collector
=========================================================

This module generates detailed reports and analytics including:
- Daily summary reports
- Performance analysis
- Data flow tracking
- Error categorization and analysis
- Quality assurance metrics
- Trend analysis over time
"""

import json
import os
import csv
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import statistics
from dataclasses import dataclass, asdict
# Optional dependencies for advanced reporting
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


@dataclass
class StageMetrics:
    """Metrics for a pipeline stage"""
    stage_name: str
    input_count: int
    output_count: int
    loss_count: int
    loss_percentage: float
    duration: float
    success_rate: float
    error_count: int
    timestamp: str


@dataclass
class PerformanceMetrics:
    """Performance metrics for operations"""
    operation_name: str
    total_executions: int
    avg_duration: float
    min_duration: float
    max_duration: float
    total_duration: float
    avg_memory_mb: float
    max_memory_mb: float
    success_count: int
    failure_count: int


@dataclass
class DataQualityMetrics:
    """Data quality assessment metrics"""
    total_configs: int
    valid_configs: int
    invalid_configs: int
    duplicate_configs: int
    protocol_distribution: Dict[str, int]
    quality_score: float
    issues_found: List[str]


class ReportGenerator:
    """Generate comprehensive reports for the V2Ray Config Collector"""
    
    def __init__(self, logger_manager, output_dir: str = "reports"):
        self.logger_manager = logger_manager
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database for historical data
        self.db_path = self.output_dir / "metrics.db"
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for storing historical metrics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables for different metric types
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS stage_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    stage_name TEXT NOT NULL,
                    input_count INTEGER,
                    output_count INTEGER,
                    loss_count INTEGER,
                    loss_percentage REAL,
                    duration REAL,
                    success_rate REAL,
                    error_count INTEGER
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation_name TEXT NOT NULL,
                    duration REAL,
                    memory_mb REAL,
                    success BOOLEAN,
                    metadata TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS daily_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE NOT NULL,
                    total_configs INTEGER,
                    unique_configs INTEGER,
                    duplicates_removed INTEGER,
                    success_rate REAL,
                    total_duration REAL,
                    quality_score REAL,
                    issues_count INTEGER
                )
            """)
            
            conn.commit()
    
    def store_stage_metrics(self, stage_data: Dict[str, Any]):
        """Store stage metrics in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for stage_name, data in stage_data.items():
                cursor.execute("""
                    INSERT INTO stage_metrics 
                    (timestamp, stage_name, input_count, output_count, loss_count, 
                     loss_percentage, duration, success_rate, error_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data.get('timestamp', datetime.now().isoformat()),
                    stage_name,
                    data.get('input_count', 0),
                    data.get('output_count', 0),
                    data.get('loss_count', 0),
                    data.get('loss_percentage', 0.0),
                    data.get('duration', 0.0),
                    data.get('success_rate', 0.0),
                    data.get('error_count', 0)
                ))
            
            conn.commit()
    
    def store_performance_metrics(self, performance_data: Dict[str, List[Dict]]):
        """Store performance metrics in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            for operation_name, metrics_list in performance_data.items():
                for metric in metrics_list:
                    cursor.execute("""
                        INSERT INTO performance_metrics 
                        (timestamp, operation_name, duration, memory_mb, success, metadata)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        metric.get('timestamp', datetime.now().isoformat()),
                        operation_name,
                        metric.get('duration', 0.0),
                        metric.get('memory_mb', 0.0),
                        metric.get('success', True),
                        json.dumps(metric.get('metadata', {}))
                    ))
            
            conn.commit()
    
    def generate_daily_report(self, date: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive daily report"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
        
        # Get data from logger manager
        data_flow = self.logger_manager.data_flow_tracker.get_all_stages()
        performance_metrics = self.logger_manager.performance_monitor.get_metrics()
        data_losses = self.logger_manager.data_flow_tracker.detect_data_loss()
        
        # Calculate overall statistics
        total_configs = 0
        final_configs = 0
        total_duration = 0.0
        
        if data_flow:
            # Get initial and final counts
            first_stage = list(data_flow.values())[0] if data_flow else {}
            last_stage = list(data_flow.values())[-1] if data_flow else {}
            
            total_configs = first_stage.get('input_count', 0)
            final_configs = last_stage.get('output_count', 0)
        
        # Calculate total duration from performance metrics
        for operation_metrics in performance_metrics.values():
            for metric in operation_metrics:
                total_duration += metric.get('duration', 0)
        
        # Generate quality assessment
        quality_metrics = self._assess_data_quality(data_flow, data_losses)
        
        # Create comprehensive report
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_date': date,
                'report_type': 'daily_summary',
                'version': '1.0.0'
            },
            'summary': {
                'total_configs_processed': total_configs,
                'final_configs_output': final_configs,
                'configs_removed': total_configs - final_configs,
                'removal_rate_percentage': ((total_configs - final_configs) / total_configs * 100) if total_configs > 0 else 0,
                'total_processing_time': total_duration,
                'average_processing_speed': (total_configs / total_duration) if total_duration > 0 else 0,
                'quality_score': quality_metrics.quality_score,
                'critical_issues': len([l for l in data_losses if l.get('loss_percentage', 0) > 20])
            },
            'stage_analysis': self._analyze_stages(data_flow),
            'performance_analysis': self._analyze_performance(performance_metrics),
            'data_flow_analysis': self._analyze_data_flow(data_flow),
            'quality_assessment': asdict(quality_metrics),
            'data_losses': data_losses,
            'recommendations': self._generate_recommendations(data_flow, performance_metrics, data_losses),
            'trends': self._analyze_trends(date)
        }
        
        # Store in database
        self._store_daily_summary(date, report)
        
        # Save report to file
        report_file = self.output_dir / f"daily_report_{date.replace('-', '')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        return report
    
    def _assess_data_quality(self, data_flow: Dict, data_losses: List[Dict]) -> DataQualityMetrics:
        """Assess overall data quality"""
        total_configs = 0
        final_configs = 0
        issues = []
        
        if data_flow:
            first_stage = list(data_flow.values())[0]
            last_stage = list(data_flow.values())[-1]
            
            total_configs = first_stage.get('input_count', 0)
            final_configs = last_stage.get('output_count', 0)
        
        # Calculate quality score (0-100)
        quality_score = 100.0
        
        # Deduct points for data losses
        for loss in data_losses:
            loss_percentage = loss.get('loss_percentage', 0)
            if loss_percentage > 20:
                quality_score -= 30  # Critical loss
                issues.append(f"Critical data loss in {loss.get('stage', 'unknown')}: {loss_percentage:.1f}%")
            elif loss_percentage > 10:
                quality_score -= 15  # Major loss
                issues.append(f"Major data loss in {loss.get('stage', 'unknown')}: {loss_percentage:.1f}%")
            elif loss_percentage > 5:
                quality_score -= 5   # Minor loss
                issues.append(f"Minor data loss in {loss.get('stage', 'unknown')}: {loss_percentage:.1f}%")
        
        # Ensure score doesn't go below 0
        quality_score = max(0.0, quality_score)
        
        return DataQualityMetrics(
            total_configs=total_configs,
            valid_configs=final_configs,
            invalid_configs=total_configs - final_configs,
            duplicate_configs=0,  # Would need additional data
            protocol_distribution={},  # Would need additional data
            quality_score=quality_score,
            issues_found=issues
        )
    
    def _analyze_stages(self, data_flow: Dict) -> Dict[str, Any]:
        """Analyze performance of each pipeline stage"""
        stage_analysis = {}
        
        for stage_name, stage_data in data_flow.items():
            input_count = stage_data.get('input_count', 0)
            output_count = stage_data.get('output_count', 0)
            loss_count = input_count - output_count
            loss_percentage = (loss_count / input_count * 100) if input_count > 0 else 0
            
            analysis = {
                'input_count': input_count,
                'output_count': output_count,
                'loss_count': loss_count,
                'loss_percentage': loss_percentage,
                'efficiency': (output_count / input_count * 100) if input_count > 0 else 0,
                'status': self._get_stage_status(loss_percentage),
                'metadata': stage_data.get('metadata', {})
            }
            
            stage_analysis[stage_name] = analysis
        
        return stage_analysis
    
    def _analyze_performance(self, performance_metrics: Dict) -> Dict[str, Any]:
        """Analyze performance metrics"""
        performance_analysis = {}
        
        for operation_name, metrics_list in performance_metrics.items():
            if not metrics_list:
                continue
                
            durations = [m.get('duration', 0) for m in metrics_list if 'duration' in m]
            memory_usage = [m.get('memory_mb', 0) for m in metrics_list if 'memory_mb' in m]
            
            if durations:
                analysis = {
                    'total_executions': len(durations),
                    'avg_duration': statistics.mean(durations),
                    'min_duration': min(durations),
                    'max_duration': max(durations),
                    'total_duration': sum(durations),
                    'duration_std_dev': statistics.stdev(durations) if len(durations) > 1 else 0,
                    'avg_memory_mb': statistics.mean(memory_usage) if memory_usage else 0,
                    'max_memory_mb': max(memory_usage) if memory_usage else 0,
                    'performance_rating': self._rate_performance(durations, memory_usage)
                }
                
                performance_analysis[operation_name] = analysis
        
        return performance_analysis
    
    def _analyze_data_flow(self, data_flow: Dict) -> Dict[str, Any]:
        """Analyze data flow through the pipeline"""
        if not data_flow:
            return {}
        
        stages = list(data_flow.keys())
        flow_analysis = {
            'total_stages': len(stages),
            'stage_order': stages,
            'flow_efficiency': {},
            'bottlenecks': [],
            'data_retention': {}
        }
        
        # Calculate flow efficiency between stages
        for i in range(len(stages) - 1):
            current_stage = stages[i]
            next_stage = stages[i + 1]
            
            current_output = data_flow[current_stage].get('output_count', 0)
            next_input = data_flow[next_stage].get('input_count', 0)
            
            # Ideally, output of one stage should equal input of next
            efficiency = (min(current_output, next_input) / max(current_output, next_input) * 100) if max(current_output, next_input) > 0 else 0
            flow_analysis['flow_efficiency'][f"{current_stage}_to_{next_stage}"] = efficiency
            
            if efficiency < 95:  # Less than 95% efficiency indicates potential issue
                flow_analysis['bottlenecks'].append({
                    'transition': f"{current_stage} -> {next_stage}",
                    'efficiency': efficiency,
                    'data_loss': max(current_output, next_input) - min(current_output, next_input)
                })
        
        # Calculate overall data retention
        if data_flow:
            first_stage = list(data_flow.values())[0]
            last_stage = list(data_flow.values())[-1]
            
            initial_count = first_stage.get('input_count', 0)
            final_count = last_stage.get('output_count', 0)
            
            flow_analysis['data_retention'] = {
                'initial_count': initial_count,
                'final_count': final_count,
                'retention_rate': (final_count / initial_count * 100) if initial_count > 0 else 0,
                'total_loss': initial_count - final_count
            }
        
        return flow_analysis
    
    def _generate_recommendations(self, data_flow: Dict, performance_metrics: Dict, data_losses: List[Dict]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Check for data loss issues
        critical_losses = [l for l in data_losses if l.get('loss_percentage', 0) > 20]
        if critical_losses:
            recommendations.append("🚨 CRITICAL: Investigate stages with >20% data loss immediately")
            for loss in critical_losses:
                recommendations.append(f"   - {loss.get('stage', 'Unknown')}: {loss.get('loss_percentage', 0):.1f}% loss")
        
        # Check for performance issues
        slow_operations = []
        for op_name, metrics_list in performance_metrics.items():
            if metrics_list:
                avg_duration = statistics.mean([m.get('duration', 0) for m in metrics_list if 'duration' in m])
                if avg_duration > 30:  # More than 30 seconds
                    slow_operations.append((op_name, avg_duration))
        
        if slow_operations:
            recommendations.append("⚡ PERFORMANCE: Consider optimizing slow operations:")
            for op_name, duration in slow_operations:
                recommendations.append(f"   - {op_name}: {duration:.1f}s average")
        
        # Check for memory usage
        high_memory_ops = []
        for op_name, metrics_list in performance_metrics.items():
            if metrics_list:
                memory_usage = [m.get('memory_mb', 0) for m in metrics_list if 'memory_mb' in m]
                if memory_usage and max(memory_usage) > 500:  # More than 500MB
                    high_memory_ops.append((op_name, max(memory_usage)))
        
        if high_memory_ops:
            recommendations.append("💾 MEMORY: Monitor high memory usage operations:")
            for op_name, memory in high_memory_ops:
                recommendations.append(f"   - {op_name}: {memory:.1f}MB peak")
        
        # Check data flow efficiency
        if data_flow and len(data_flow) > 1:
            stages = list(data_flow.keys())
            for i in range(len(stages) - 1):
                current_output = data_flow[stages[i]].get('output_count', 0)
                next_input = data_flow[stages[i + 1]].get('input_count', 0)
                
                if abs(current_output - next_input) > current_output * 0.05:  # More than 5% difference
                    recommendations.append(f"🔄 DATA FLOW: Check data transfer between {stages[i]} and {stages[i + 1]}")
        
        # General recommendations
        if not recommendations:
            recommendations.append("✅ All systems operating within normal parameters")
            recommendations.append("💡 Consider implementing automated monitoring alerts")
            recommendations.append("📊 Review trends over time for optimization opportunities")
        
        return recommendations
    
    def _analyze_trends(self, current_date: str) -> Dict[str, Any]:
        """Analyze trends over the past week/month"""
        trends = {
            'weekly_trend': self._get_weekly_trend(current_date),
            'monthly_trend': self._get_monthly_trend(current_date),
            'performance_trend': self._get_performance_trend(current_date)
        }
        
        return trends
    
    def _get_weekly_trend(self, current_date: str) -> Dict[str, Any]:
        """Get weekly trend analysis"""
        end_date = datetime.strptime(current_date, '%Y-%m-%d')
        start_date = end_date - timedelta(days=7)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT date, total_configs, unique_configs, success_rate, quality_score
                FROM daily_summaries 
                WHERE date BETWEEN ? AND ?
                ORDER BY date
            """, (start_date.strftime('%Y-%m-%d'), current_date))
            
            results = cursor.fetchall()
        
        if not results:
            return {'status': 'insufficient_data', 'days_available': 0}
        
        # Calculate trends
        configs_trend = [row[1] for row in results]
        quality_trend = [row[4] for row in results]
        
        return {
            'days_available': len(results),
            'avg_configs_per_day': statistics.mean(configs_trend) if configs_trend else 0,
            'avg_quality_score': statistics.mean(quality_trend) if quality_trend else 0,
            'config_trend': 'increasing' if len(configs_trend) > 1 and configs_trend[-1] > configs_trend[0] else 'stable',
            'quality_trend': 'improving' if len(quality_trend) > 1 and quality_trend[-1] > quality_trend[0] else 'stable'
        }
    
    def _get_monthly_trend(self, current_date: str) -> Dict[str, Any]:
        """Get monthly trend analysis"""
        # Similar to weekly but for 30 days
        end_date = datetime.strptime(current_date, '%Y-%m-%d')
        start_date = end_date - timedelta(days=30)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT AVG(total_configs), AVG(success_rate), AVG(quality_score), COUNT(*)
                FROM daily_summaries 
                WHERE date BETWEEN ? AND ?
            """, (start_date.strftime('%Y-%m-%d'), current_date))
            
            result = cursor.fetchone()
        
        if not result or result[3] == 0:
            return {'status': 'insufficient_data'}
        
        return {
            'days_available': result[3],
            'avg_configs_per_day': result[0] or 0,
            'avg_success_rate': result[1] or 0,
            'avg_quality_score': result[2] or 0,
            'data_completeness': (result[3] / 30) * 100  # Percentage of days with data
        }
    
    def _get_performance_trend(self, current_date: str) -> Dict[str, Any]:
        """Get performance trend analysis"""
        end_date = datetime.strptime(current_date, '%Y-%m-%d')
        start_date = end_date - timedelta(days=7)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT operation_name, AVG(duration), AVG(memory_mb), COUNT(*)
                FROM performance_metrics 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY operation_name
            """, (start_date.isoformat(), end_date.isoformat()))
            
            results = cursor.fetchall()
        
        performance_summary = {}
        for row in results:
            performance_summary[row[0]] = {
                'avg_duration': row[1],
                'avg_memory_mb': row[2],
                'execution_count': row[3]
            }
        
        return performance_summary
    
    def _store_daily_summary(self, date: str, report: Dict[str, Any]):
        """Store daily summary in database"""
        summary = report.get('summary', {})
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO daily_summaries 
                (date, total_configs, unique_configs, duplicates_removed, 
                 success_rate, total_duration, quality_score, issues_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                date,
                summary.get('total_configs_processed', 0),
                summary.get('final_configs_output', 0),
                summary.get('configs_removed', 0),
                100.0,  # Default success rate
                summary.get('total_processing_time', 0),
                summary.get('quality_score', 0),
                summary.get('critical_issues', 0)
            ))
            
            conn.commit()
    
    def _get_stage_status(self, loss_percentage: float) -> str:
        """Get status based on loss percentage"""
        if loss_percentage > 20:
            return "CRITICAL"
        elif loss_percentage > 10:
            return "WARNING"
        elif loss_percentage > 5:
            return "ATTENTION"
        else:
            return "HEALTHY"
    
    def _rate_performance(self, durations: List[float], memory_usage: List[float]) -> str:
        """Rate performance based on duration and memory usage"""
        if not durations:
            return "UNKNOWN"
        
        avg_duration = statistics.mean(durations)
        max_memory = max(memory_usage) if memory_usage else 0
        
        if avg_duration < 5 and max_memory < 100:
            return "EXCELLENT"
        elif avg_duration < 15 and max_memory < 250:
            return "GOOD"
        elif avg_duration < 30 and max_memory < 500:
            return "FAIR"
        else:
            return "POOR"
    
    def generate_csv_report(self, date: Optional[str] = None) -> str:
        """Generate CSV report for easy analysis"""
        if date is None:
            date = datetime.now().strftime('%Y-%m-%d')
        
        csv_file = self.output_dir / f"summary_report_{date.replace('-', '')}.csv"
        
        # Get data from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Stage metrics
            cursor.execute("""
                SELECT * FROM stage_metrics 
                WHERE date(timestamp) = ?
                ORDER BY timestamp
            """, [date])
            stage_data = cursor.fetchall()
            stage_columns = [description[0] for description in cursor.description]
            
            # Performance metrics
            cursor.execute("""
                SELECT operation_name, AVG(duration) as avg_duration, 
                       AVG(memory_mb) as avg_memory, COUNT(*) as executions
                FROM performance_metrics 
                WHERE date(timestamp) = ?
                GROUP BY operation_name
            """, [date])
            perf_data = cursor.fetchall()
            perf_columns = [description[0] for description in cursor.description]
        
        # Write to CSV
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write stage metrics
            writer.writerow(['=== STAGE METRICS ==='])
            if stage_data:
                writer.writerow(stage_columns)
                writer.writerows(stage_data)
            else:
                writer.writerow(['No stage metrics data available for this date'])
            
            writer.writerow([])
            writer.writerow(['=== PERFORMANCE METRICS ==='])
            if perf_data:
                writer.writerow(perf_columns)
                writer.writerows(perf_data)
            else:
                writer.writerow(['No performance metrics data available for this date'])
        
        return str(csv_file)
    
    def cleanup_old_reports(self, days_to_keep: int = 30):
        """Clean up old report files"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        for report_file in self.output_dir.glob("*.json"):
            try:
                file_time = datetime.fromtimestamp(report_file.stat().st_mtime)
                if file_time < cutoff_date:
                    report_file.unlink()
            except Exception:
                pass  # Ignore errors during cleanup