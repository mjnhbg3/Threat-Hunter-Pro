#!/usr/bin/env python3
"""
Thunker CLI - Command-line interface for Threat Hunter Pro hierarchical summarization.

This CLI provides easy access to hierarchical summarization features including:
- Running ad-hoc summarization jobs
- Querying existing summaries
- System status and performance monitoring
- Configuration management
- Maintenance operations

Usage examples:
    python thunker_cli.py status
    python thunker_cli.py summarise --since 7d
    python thunker_cli.py query "show me this week's security trends"
    python thunker_cli.py run-nightly --date 2025-01-15
"""

import asyncio
import argparse
import json
import sys
import logging
from datetime import datetime, date, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from hierarchical_summary import HierarchicalSummarizer, SummaryConfig, SummaryLevel
from hierarchical_summary.models import SummaryQuery
from config import DEFAULT_SETTINGS


class ThunkerCLI:
    """Command-line interface for Threat Hunter Pro hierarchical summarization."""
    
    def __init__(self):
        self.summarizer: Optional[HierarchicalSummarizer] = None
        self.config = SummaryConfig()
        
    async def initialize(self):
        """Initialize the hierarchical summarizer."""
        try:
            self.summarizer = HierarchicalSummarizer(self.config)
            await self.summarizer.initialize()
            print("✓ Hierarchical summarizer initialized successfully")
        except Exception as e:
            print(f"✗ Failed to initialize hierarchical summarizer: {e}")
            sys.exit(1)
    
    async def cmd_status(self, args):
        """Show system status and health metrics."""
        print("🔍 Checking hierarchical summarization system status...\n")
        
        if not self.summarizer:
            await self.initialize()
            
        try:
            status = await self.summarizer.get_system_status()
            
            # Print formatted status
            print("📊 SYSTEM STATUS")
            print("=" * 50)
            print(f"Status: {'🟢 Online' if status['status'] == 'initialized' else '🔴 Offline'}")
            print(f"Initialized: {'Yes' if status['initialized'] else 'No'}")
            
            if 'storage_stats' in status:
                storage = status['storage_stats']
                print(f"\n📁 STORAGE STATISTICS")
                print(f"Total summaries: {storage.get('total_summaries', 0):,}")
                print(f"Storage size: {storage.get('storage_size_mb', 0):.2f} MB")
                print(f"Cache hit rate: {storage.get('cache_hit_rate', 0)*100:.1f}%")
                
                if 'by_level' in storage:
                    print(f"\nSummaries by level:")
                    for level, count in storage['by_level'].items():
                        print(f"  {level}: {count:,}")
            
            if 'performance_metrics' in status:
                perf = status['performance_metrics']
                print(f"\n⚡ PERFORMANCE METRICS")
                print(f"Summaries generated: {perf.get('summaries_generated', 0):,}")
                print(f"Queries executed: {perf.get('queries_executed', 0):,}")
                print(f"Cache hits: {perf.get('cache_hits', 0):,}")
                print(f"Avg generation time: {perf.get('avg_generation_time_ms', 0):.0f}ms")
                print(f"Avg query time: {perf.get('avg_query_time_ms', 0):.0f}ms")
                print(f"Est. token reduction: {perf.get('estimated_token_reduction', 0)*100:.1f}%")
            
            if 'job_scheduler' in status:
                jobs = status['job_scheduler']
                print(f"\n🔄 JOB SCHEDULER")
                print(f"Running: {'Yes' if jobs.get('is_running', False) else 'No'}")
                print(f"Last run: {jobs.get('last_run_summary', 'Never')}")
            
            if 'config' in status:
                config = status['config']
                print(f"\n⚙️  CONFIGURATION")
                print(f"Clustering algorithm: {config.get('clustering_algorithm', 'unknown')}")
                print(f"Summary model: {config.get('summary_model', 'unknown')}")
                print(f"Compression: {'Enabled' if config.get('compression_enabled', False) else 'Disabled'}")
                print(f"Redis caching: {'Enabled' if config.get('redis_caching', False) else 'Disabled'}")
                print(f"Parallel processing: {'Enabled' if config.get('parallel_processing', False) else 'Disabled'}")
                
        except Exception as e:
            print(f"✗ Failed to get system status: {e}")
            sys.exit(1)
    
    async def cmd_summarise(self, args):
        """Run ad-hoc summarization for recent time period."""
        print(f"📝 Running summarization for last {args.since}...\n")
        
        if not self.summarizer:
            await self.initialize()
            
        try:
            # Parse time period
            target_date = self._parse_time_period(args.since)
            
            print(f"Target date: {target_date}")
            result = await self.summarizer.run_nightly_summarization(target_date)
            
            if result.get('success', False):
                print(f"✓ Summarization completed successfully")
                print(f"  • {result.get('summaries_created', 0)} summaries created")
                print(f"  • {result.get('jobs', {}).get('successful', 0)}/{result.get('jobs', {}).get('total', 0)} jobs successful")
                print(f"  • Processing time: {result.get('processing_time_ms', 0)/1000:.1f}s")
                print(f"  • {result.get('cleanup_count', 0)} expired summaries cleaned up")
                
                if args.verbose and 'job_details' in result:
                    print(f"\n📋 JOB DETAILS:")
                    for job in result['job_details']:
                        status_icon = "✓" if job['status'] == 'completed' else "✗"
                        print(f"  {status_icon} {job['job_type']}: {job['status']} ({job.get('processing_time_ms', 0)}ms)")
                        
            else:
                print(f"✗ Summarization failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"✗ Failed to run summarization: {e}")
            sys.exit(1)
    
    async def cmd_query(self, args):
        """Query existing summaries."""
        print(f"🔍 Querying summaries: '{args.query}'\n")
        
        if not self.summarizer:
            await self.initialize()
            
        try:
            # Parse filters
            level = SummaryLevel(args.level) if args.level else None
            start_date = datetime.fromisoformat(args.start_date) if args.start_date else None
            end_date = datetime.fromisoformat(args.end_date) if args.end_date else None
            
            response = await self.summarizer.query_summaries(
                query=args.query,
                level=level,
                start_date=start_date,
                end_date=end_date,
                limit=args.limit
            )
            
            print(f"📊 QUERY RESULTS ({response.total_count} total, showing {len(response.summaries)})")
            print(f"Query time: {response.query_time_ms}ms | Cache hit: {'Yes' if response.cache_hit else 'No'}")
            print("=" * 80)
            
            if not response.summaries:
                print("No summaries found matching your query.")
                return
                
            for i, summary in enumerate(response.summaries, 1):
                metadata = summary.metadata
                print(f"\n{i}. {metadata.summary_id}")
                print(f"   Level: {metadata.level.value} | Time: {metadata.time_range_start.strftime('%Y-%m-%d %H:%M')}")
                print(f"   Sources: {metadata.source_count} | Quality: {metadata.quality_score:.1f}")
                
                # Print summary text
                if hasattr(summary, 'summary_text'):
                    text = summary.summary_text
                elif hasattr(summary, 'executive_summary'):
                    text = summary.executive_summary
                else:
                    text = "No summary text available"
                    
                # Truncate if needed
                if len(text) > 200 and not args.verbose:
                    text = text[:200] + "..."
                    
                print(f"   Summary: {text}")
                
                # Show key insights if available
                if hasattr(summary, 'key_insights') and summary.key_insights:
                    insights = summary.key_insights[:3] if not args.verbose else summary.key_insights
                    print(f"   Insights: {'; '.join(insights)}")
                    
        except Exception as e:
            print(f"✗ Failed to query summaries: {e}")
            sys.exit(1)
    
    async def cmd_run_nightly(self, args):
        """Run the nightly summarization process."""
        target_date = args.date
        if target_date:
            try:
                target_date = datetime.fromisoformat(args.date).date()
            except ValueError:
                print(f"✗ Invalid date format: {args.date} (use YYYY-MM-DD)")
                sys.exit(1)
        
        print(f"🌙 Running nightly summarization for {target_date or 'yesterday'}...")
        
        if not self.summarizer:
            await self.initialize()
            
        try:
            result = await self.summarizer.run_nightly_summarization(target_date)
            
            if result.get('success', False):
                print(f"✓ Nightly summarization completed")
                print(f"Summary: {result.get('summary', 'No summary available')}")
            else:
                print(f"✗ Nightly summarization failed: {result.get('error', 'Unknown error')}")
                sys.exit(1)
                
        except Exception as e:
            print(f"✗ Failed to run nightly summarization: {e}")
            sys.exit(1)
    
    async def cmd_optimize(self, args):
        """Run performance optimization."""
        print("⚡ Running performance optimization...\n")
        
        if not self.summarizer:
            await self.initialize()
            
        try:
            result = await self.summarizer.optimize_performance()
            
            print("✓ Optimization completed:")
            print(f"  • Cache entries cleared: {result.get('cache_cleared', 0)}")
            print(f"  • Summaries cleaned up: {result.get('summaries_cleaned', 0)}")
            print(f"  • Database optimized: {'Yes' if result.get('database_optimized', False) else 'No'}")
            
        except Exception as e:
            print(f"✗ Failed to run optimization: {e}")
            sys.exit(1)
    
    async def cmd_levels(self, args):
        """Show available summary levels."""
        print("📊 AVAILABLE SUMMARY LEVELS\n")
        
        levels_info = {
            "cluster": "Groups of related logs (5-50 logs) - Basic patterns and anomalies",
            "daily": "Daily security summary aggregating cluster summaries",
            "weekly": "Weekly trends and major incidents analysis", 
            "monthly": "Monthly security posture assessment",
            "quarterly": "Quarterly executive reporting and strategic analysis"
        }
        
        for level, description in levels_info.items():
            print(f"• {level.upper()}")
            print(f"  {description}\n")
    
    def _parse_time_period(self, period: str) -> date:
        """Parse time period string like '7d', '1w', '1m' into target date."""
        if not period:
            return date.today() - timedelta(days=1)
            
        try:
            if period.endswith('d'):
                days = int(period[:-1])
                return date.today() - timedelta(days=days)
            elif period.endswith('w'):
                weeks = int(period[:-1]) 
                return date.today() - timedelta(weeks=weeks)
            elif period.endswith('m'):
                months = int(period[:-1])
                return date.today() - timedelta(days=months * 30)
            else:
                # Try parsing as ISO date
                return datetime.fromisoformat(period).date()
        except (ValueError, TypeError):
            print(f"✗ Invalid time period format: {period}")
            print("  Examples: 7d (7 days), 1w (1 week), 1m (1 month), 2025-01-15")
            sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Thunker CLI - Threat Hunter Pro hierarchical summarization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s status                           # Show system status 
  %(prog)s summarise --since 7d             # Summarize last 7 days
  %(prog)s query "brute force attacks"      # Query summaries
  %(prog)s run-nightly --date 2025-01-15   # Run nightly job for specific date
  %(prog)s optimize                         # Run performance optimization
        """
    )
    
    # Global options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show system status')
    
    # Summarise command
    summarise_parser = subparsers.add_parser('summarise', help='Run ad-hoc summarization')
    summarise_parser.add_argument('--since', default='1d', 
                                help='Time period to summarize (e.g., 7d, 1w, 2025-01-15)')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query existing summaries')
    query_parser.add_argument('query', help='Natural language query')
    query_parser.add_argument('--level', choices=['cluster', 'daily', 'weekly', 'monthly', 'quarterly'],
                             help='Filter by summary level')
    query_parser.add_argument('--start-date', help='Start date filter (YYYY-MM-DD)')
    query_parser.add_argument('--end-date', help='End date filter (YYYY-MM-DD)')
    query_parser.add_argument('--limit', type=int, default=10, help='Maximum results (default: 10)')
    
    # Run nightly command
    nightly_parser = subparsers.add_parser('run-nightly', help='Run nightly summarization')
    nightly_parser.add_argument('--date', help='Target date (YYYY-MM-DD, default: yesterday)')
    
    # Optimize command
    optimize_parser = subparsers.add_parser('optimize', help='Run performance optimization')
    
    # Levels command
    levels_parser = subparsers.add_parser('levels', help='Show available summary levels')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    # Configure logging
    if args.quiet:
        logging.basicConfig(level=logging.ERROR)
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        logging.basicConfig(level=logging.WARNING)
    
    # Create CLI instance and run command
    cli = ThunkerCLI()
    
    try:
        if args.command == 'status':
            asyncio.run(cli.cmd_status(args))
        elif args.command == 'summarise':
            asyncio.run(cli.cmd_summarise(args))
        elif args.command == 'query':
            asyncio.run(cli.cmd_query(args))
        elif args.command == 'run-nightly':
            asyncio.run(cli.cmd_run_nightly(args))
        elif args.command == 'optimize':
            asyncio.run(cli.cmd_optimize(args))
        elif args.command == 'levels':
            asyncio.run(cli.cmd_levels(args))
        else:
            print(f"Unknown command: {args.command}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()