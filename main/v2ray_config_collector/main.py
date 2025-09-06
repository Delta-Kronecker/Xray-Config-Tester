from core.fetcher import SourceCollector
from core.parser import FormatConverter
from core.deduplicator import ConfigDeduplicator
from core.logger import get_logger_manager, get_logger
import time
from datetime import datetime

def main():
    # Initialize logging system
    logger_manager = get_logger_manager()
    logger = get_logger('main')
    
    # Log application start
    logger.info("V2Ray Config Collector application started", extra={
        'version': '1.0.0',
        'start_time': datetime.now().isoformat(),
        'pipeline_stages': ['fetching', 'parsing', 'deduplication']
    })


    logger_manager.start_performance_timer('total_application')
    
    try:
        # Stage 1: Config Fetching
        title1 = "V2Ray Config Collector"
        print(title1)
        print("=" * len(title1))
        
        logger.info("Starting Stage 1: Config Fetching")
        logger_manager.start_performance_timer('stage_1_fetching')
        
        collector = SourceCollector()
        collector.fetch_all_configs()
        
        stage1_duration = logger_manager.end_performance_timer('stage_1_fetching')
        logger.info("Stage 1 completed: Config Fetching", extra={
            'duration': stage1_duration,
            'stage': 'fetching'
        })


        # Stage 2: Config Parsing
        title2 = "Convert proxy configurations to JSON format"
        print(title2)
        print("=" * len(title2))
        
        logger.info("Starting Stage 2: Config Parsing")
        logger_manager.start_performance_timer('stage_2_parsing')
        
        converter = FormatConverter()
        converter.convert_configs()
        
        stage2_duration = logger_manager.end_performance_timer('stage_2_parsing')
        logger.info("Stage 2 completed: Config Parsing", extra={
            'duration': stage2_duration,
            'stage': 'parsing'
        })
        
        # Stage 3: Deduplication
        title3 = "Remove duplicate configurations"
        print(title3)
        print("=" * len(title3))
        
        logger.info("Starting Stage 3: Deduplication")
        logger_manager.start_performance_timer('stage_3_deduplication')
        
        deduplicator = ConfigDeduplicator()
        success = deduplicator.process()
        
        stage3_duration = logger_manager.end_performance_timer('stage_3_deduplication')
        logger.info("Stage 3 completed: Deduplication", extra={
            'duration': stage3_duration,
            'success': success,
            'stage': 'deduplication'
        })
        
        # Log overall completion
        total_duration = logger_manager.end_performance_timer('total_application')
        
        if success:
            logger.info("V2Ray Config Collector completed successfully", extra={
                'total_duration': total_duration,
                'stage_1_duration': stage1_duration,
                'stage_2_duration': stage2_duration,
                'stage_3_duration': stage3_duration,
                'end_time': datetime.now().isoformat()
            })
            
            # Generate daily report
            report = logger_manager.generate_daily_report()
            logger.info("Daily report generated", extra={
                'report_summary': report.get('summary', {}),
                'data_losses': len(report.get('data_losses', [])),
                'critical_losses': report.get('summary', {}).get('critical_losses', 0)
            })
            
            print(f"\n🎉 Application completed successfully in {total_duration:.2f} seconds!")
        else:
            logger.error("V2Ray Config Collector completed with errors", extra={
                'total_duration': total_duration,
                'failed_stage': 'deduplication'
            })
            print(f"\n❌ Application completed with errors after {total_duration:.2f} seconds!")
            
    except Exception as e:
        total_duration = logger_manager.end_performance_timer('total_application')
        logger.error("V2Ray Config Collector failed with exception", extra={
            'error': str(e),
            'total_duration': total_duration,
            'end_time': datetime.now().isoformat()
        })
        print(f"\n💥 Application failed with error: {str(e)}")
        raise
    
    finally:
        # Cleanup old logs (keep last 7 days)
        try:
            logger_manager.cleanup_old_logs(days_to_keep=7)
        except Exception as e:
            logger.warning(f"Failed to cleanup old logs: {e}")

if __name__ == "__main__":
    main()


