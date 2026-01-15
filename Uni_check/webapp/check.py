#!/usr/bin/env python3

import os
import sys
import hashlib
import subprocess
import json
import logging
from datetime import datetime
from pathlib import Path

WEBAPP_DIR = "./"
VALID_FILES = ["Uni_check", "check.py"]
LOG_FILE = "/tmp/integrity_check.log"
MANIFEST_FILE = ".manifest.json"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


class IntegrityChecker:
    
    def __init__(self, base_dir=WEBAPP_DIR):
        self.base_dir = base_dir
        self.valid_files = VALID_FILES
        self.scan_results = {
            'timestamp': datetime.now().isoformat(),
            'total_files': 0,
            'valid_files': 0,
            'illegal_files': 0,
            'missing_files': [],
            'illegal_file_list': []
        }
    
    def calculate_checksum(self, filepath):
        try:
            md5_hash = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            return md5_hash.hexdigest()
        except Exception as e:
            logger.error(f"Checksum calculation failed for {filepath}: {e}")
            return None
    
    def scan_directory(self):
        logger.info("=" * 60)
        logger.info("Starting integrity verification process...")
        logger.info("=" * 60)
        
        discovered_files = []
        
        for root, dirs, files in os.walk(self.base_dir):
            if 'cookies' in root:
                continue
            
            for filename in files:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, self.base_dir)
                discovered_files.append(rel_path)
        
        self.scan_results['total_files'] = len(discovered_files)
        return discovered_files
    
    def validate_manifest(self, file_list):
        logger.info("[Phase 1] Manifest Validation")
        
        for required_file in self.valid_files:
            if required_file not in file_list:
                logger.warning(f"⚠️  Missing required file: {required_file}")
                self.scan_results['missing_files'].append(required_file)
            else:
                self.scan_results['valid_files'] += 1
        
        illegal_files = [f for f in file_list if f not in self.valid_files]
        
        if illegal_files:
            self.scan_results['illegal_files'] = len(illegal_files)
            self.scan_results['illegal_file_list'] = illegal_files
            
            logger.warning(f"⚠️  ALERT: Detected {len(illegal_files)} unauthorized file(s):")
            for idx, fname in enumerate(illegal_files, 1):
                logger.warning(f"  [{idx}] {fname}")
        
        if not illegal_files and not self.scan_results['missing_files']:
             logger.info("✓ All files validated successfully")

    def cleanup_illegal_files(self):
        if not self.scan_results['illegal_file_list']:
            return
        
        logger.info("[Phase 2] Cleanup Operations")
        
        for fname in self.scan_results['illegal_file_list']:
            try:
                delete_cmd = f"rm -f {self.base_dir}/{fname}"
                
                
                subprocess.run(
                    delete_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                
            except subprocess.TimeoutExpired:
                logger.error(f"Cleanup timeout for: {fname}", extra={'file_only': True})
            except Exception as e:
                logger.error(f"Unexpected error removing {fname}: {e}", extra={'file_only': True})
        
        logger.info("✓ Cleanup process completed.")

    def generate_report(self):
        logger.info("=" * 60)
        logger.info("INTEGRITY CHECK REPORT")
        logger.info("=" * 60)
        logger.info(f"Timestamp: {self.scan_results['timestamp']}")
        logger.info(f"Total files scanned: {self.scan_results['total_files']}")
        logger.info(f"Valid files: {self.scan_results['valid_files']}")
        logger.info(f"Illegal files: {self.scan_results['illegal_files']}")
        
        if self.scan_results['missing_files']:
            logger.warning(f"Missing files: {', '.join(self.scan_results['missing_files'])}")
        
        logger.info("=" * 60)
        
        try:
            report_file = f"/tmp/integrity_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(report_file, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            logger.info(f"Detailed report saved to: {report_file}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def run_full_check(self):
        discovered_files = self.scan_directory()
        self.validate_manifest(discovered_files)
        self.cleanup_illegal_files()
        self.generate_report()


def main():
    try:
        checker = IntegrityChecker()
        checker.run_full_check()
        
        if checker.scan_results['illegal_files'] > 0:
            sys.exit(1)
        elif checker.scan_results['missing_files']:
            sys.exit(2)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        logger.warning("Integrity check interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Fatal error during integrity check: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()