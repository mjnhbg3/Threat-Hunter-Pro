#!/usr/bin/env python3
"""
Reset Vector Database Script for Threat Hunter Pro

This script completely clears the vector database, metadata, and dashboard data,
allowing the application to start fresh with a clean slate.

Usage:
    python reset_database.py [--confirm]
    
Options:
    --confirm    Skip confirmation prompt and reset immediately
"""

import os
import shutil
import json
import argparse
import sys
from pathlib import Path
from typing import Optional

def get_database_paths() -> dict:
    """Get all database-related paths."""
    # Default paths
    base_dir = Path(__file__).parent
    
    paths = {
        "vector_db": base_dir / "data" / "threat_hunter_db",
        "dashboard_data": base_dir / "dashboard_data.json",
        "settings": base_dir / "settings.json", 
        "ignored_issues": base_dir / "ignored_issues.json",
        "log_position": base_dir / "log_position.txt",
        "logs_dir": base_dir / "logs",
        "backups_dir": base_dir / "backups",
        "cache_dir": base_dir / "cache"
    }
    
    # Check for environment variable overrides
    env_db_dir = os.getenv("DB_DIR")
    if env_db_dir:
        paths["vector_db"] = Path(env_db_dir)
    
    return paths

def backup_current_data(paths: dict, backup_dir: Optional[Path] = None) -> Path:
    """Create a backup of current data before reset."""
    if backup_dir is None:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = paths["backups_dir"] / f"reset_backup_{timestamp}"
    
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Creating backup in: {backup_dir}")
    
    # Backup vector database
    if paths["vector_db"].exists():
        backup_vector_db = backup_dir / "vector_db"
        shutil.copytree(paths["vector_db"], backup_vector_db)
        print(f"✅ Backed up vector database")
    
    # Backup JSON files
    json_files = ["dashboard_data", "settings", "ignored_issues"]
    for file_key in json_files:
        file_path = paths[file_key]
        if file_path.exists():
            shutil.copy2(file_path, backup_dir / file_path.name)
            print(f"✅ Backed up {file_path.name}")
    
    # Backup log position
    if paths["log_position"].exists():
        shutil.copy2(paths["log_position"], backup_dir / "log_position.txt")
        print(f"✅ Backed up log position")
    
    # Backup application logs
    if paths["logs_dir"].exists() and any(paths["logs_dir"].iterdir()):
        backup_logs = backup_dir / "logs"
        shutil.copytree(paths["logs_dir"], backup_logs)
        print(f"✅ Backed up application logs")
    
    return backup_dir

def reset_vector_database(paths: dict) -> None:
    """Remove vector database and related files."""
    print("\n🗑️  Resetting vector database...")
    
    # Remove vector database directory
    if paths["vector_db"].exists():
        shutil.rmtree(paths["vector_db"])
        print(f"✅ Removed vector database: {paths['vector_db']}")
    
    # Reset dashboard data
    if paths["dashboard_data"].exists():
        os.remove(paths["dashboard_data"])
        print(f"✅ Removed dashboard data: {paths['dashboard_data']}")
    
    # Reset ignored issues
    if paths["ignored_issues"].exists():
        os.remove(paths["ignored_issues"])
        print(f"✅ Removed ignored issues: {paths['ignored_issues']}")
    
    # Reset log position (will cause full re-scan)
    if paths["log_position"].exists():
        os.remove(paths["log_position"])
        print(f"✅ Removed log position: {paths['log_position']}")
    
    # Clear cache directory
    if paths["cache_dir"].exists():
        shutil.rmtree(paths["cache_dir"])
        print(f"✅ Cleared cache directory: {paths['cache_dir']}")
    
    # Recreate essential directories
    paths["vector_db"].mkdir(parents=True, exist_ok=True)
    paths["logs_dir"].mkdir(parents=True, exist_ok=True)
    paths["cache_dir"].mkdir(parents=True, exist_ok=True)
    
    print("✅ Recreated essential directories")

def reset_settings_only(paths: dict) -> None:
    """Reset only settings, keeping vector data intact."""
    print("\n⚙️  Resetting settings only...")
    
    files_to_reset = ["dashboard_data", "ignored_issues", "log_position"]
    
    for file_key in files_to_reset:
        file_path = paths[file_key]
        if file_path.exists():
            os.remove(file_path)
            print(f"✅ Removed {file_path.name}")
    
    # Clear cache but keep vector DB
    if paths["cache_dir"].exists():
        shutil.rmtree(paths["cache_dir"])
        paths["cache_dir"].mkdir(parents=True, exist_ok=True)
        print(f"✅ Cleared cache directory")

def show_database_info(paths: dict) -> None:
    """Show current database information."""
    print("\n📊 Current Database Information:")
    print("=" * 50)
    
    # Vector database info
    vector_db_path = paths["vector_db"]
    if vector_db_path.exists():
        try:
            # Count files in vector DB
            files = list(vector_db_path.rglob("*"))
            file_count = len([f for f in files if f.is_file()])
            total_size = sum(f.stat().st_size for f in files if f.is_file())
            
            print(f"Vector Database: {vector_db_path}")
            print(f"  Files: {file_count}")
            print(f"  Total Size: {total_size / (1024*1024):.2f} MB")
        except Exception as e:
            print(f"Vector Database: {vector_db_path} (Error reading: {e})")
    else:
        print("Vector Database: Not found")
    
    # Dashboard data info
    dashboard_file = paths["dashboard_data"]
    if dashboard_file.exists():
        try:
            with open(dashboard_file, 'r') as f:
                data = json.load(f)
            
            issues_count = len(data.get('issues', []))
            print(f"Dashboard Data: {dashboard_file}")
            print(f"  Issues: {issues_count}")
            print(f"  Last Updated: {data.get('last_run', 'Unknown')}")
        except Exception as e:
            print(f"Dashboard Data: {dashboard_file} (Error reading: {e})")
    else:
        print("Dashboard Data: Not found")
    
    # Log position info
    log_pos_file = paths["log_position"]
    if log_pos_file.exists():
        try:
            with open(log_pos_file, 'r') as f:
                position = f.read().strip()
            print(f"Log Position: {position}")
        except Exception as e:
            print(f"Log Position: Error reading ({e})")
    else:
        print("Log Position: Not found (will start from beginning)")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Reset Threat Hunter Pro vector database and related data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python reset_database.py                    # Interactive reset with backup
  python reset_database.py --confirm          # Skip confirmation
  python reset_database.py --info             # Show database information
  python reset_database.py --settings-only    # Reset only settings, keep vector data
  python reset_database.py --no-backup        # Reset without creating backup
        """
    )
    
    parser.add_argument('--confirm', action='store_true',
                       help='Skip confirmation prompt and reset immediately')
    parser.add_argument('--info', action='store_true',
                       help='Show database information and exit')
    parser.add_argument('--settings-only', action='store_true',
                       help='Reset only settings, keep vector database intact')
    parser.add_argument('--no-backup', action='store_true',
                       help='Skip creating backup before reset')
    
    args = parser.parse_args()
    
    # Get database paths
    paths = get_database_paths()
    
    print("🔍 Threat Hunter Pro - Database Reset Tool")
    print("=" * 50)
    
    # Show info and exit if requested
    if args.info:
        show_database_info(paths)
        return
    
    # Show current status
    show_database_info(paths)
    
    # Confirm reset
    if not args.confirm:
        print(f"\n⚠️  WARNING: This will {'reset settings only' if args.settings_only else 'completely reset the database'}!")
        
        if not args.settings_only:
            print("   - All vector embeddings will be deleted")
            print("   - All security issues will be cleared")
            print("   - Log processing will start from the beginning")
        else:
            print("   - Dashboard data and settings will be cleared")
            print("   - Vector database will be preserved")
            print("   - Log processing will start from the beginning")
        
        if not args.no_backup:
            print("   - A backup will be created first")
        
        response = input("\nDo you want to continue? [y/N]: ").strip().lower()
        if response not in ['y', 'yes']:
            print("❌ Reset cancelled.")
            return
    
    try:
        # Create backup unless --no-backup is specified
        backup_dir = None
        if not args.no_backup:
            backup_dir = backup_current_data(paths)
            print(f"✅ Backup created: {backup_dir}")
        
        # Perform reset
        if args.settings_only:
            reset_settings_only(paths)
        else:
            reset_vector_database(paths)
        
        print("\n✅ Database reset completed successfully!")
        
        if backup_dir:
            print(f"📦 Backup available at: {backup_dir}")
        
        print("\n🚀 You can now restart Threat Hunter Pro to begin fresh analysis.")
        print("   The application will process all logs from the beginning.")
        
    except Exception as e:
        print(f"\n❌ Error during reset: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()