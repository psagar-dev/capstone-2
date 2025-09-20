import schedule
import time
import threading
from typing import Dict, List, Callable
from datetime import datetime, timedelta
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RescanScheduler:
    """Schedule automatic rescans of container images"""
    
    def __init__(self, scanner, notifier=None):
        self.scanner = scanner
        self.notifier = notifier
        self.scheduled_jobs = {}
        self.scan_history = []
        self.running = False
        self.thread = None
    
    def schedule_rescan(self, image: str, interval_hours: int = 24, 
                       callback: Callable = None):
        """Schedule periodic rescan of an image"""
        
        job_id = f"{image}_{interval_hours}h"
        
        def scan_job():
            logger.info(f"Running scheduled scan for {image}")
            try:
                # Parse image and tag
                if ':' in image:
                    image_name, tag = image.rsplit(':', 1)
                else:
                    image_name = image
                    tag = 'latest'
                
                # Run scan
                scan_results = self.scanner.scan_image(image_name, tag)
                
                # Record in history
                self.scan_history.append({
                    'image': image,
                    'timestamp': datetime.now().isoformat(),
                    'results': scan_results
                })
                
                # Send notification if configured
                if self.notifier:
                    self.notifier.send_scan_summary(scan_results)
                
                # Call callback if provided
                if callback:
                    callback(scan_results)
                
                logger.info(f"Scheduled scan completed for {image}")
                
            except Exception as e:
                logger.error(f"Error in scheduled scan for {image}: {str(e)}")
        
        # Schedule the job
        schedule.every(interval_hours).hours.do(scan_job).tag(job_id)
        self.scheduled_jobs[job_id] = {
            'image': image,
            'interval_hours': interval_hours,
            'next_run': schedule.jobs[-1].next_run
        }
        
        logger.info(f"Scheduled rescan for {image} every {interval_hours} hours")
        
        return job_id
    
    def schedule_patch_check(self, image: str, cve_list: List[str]):
        """Schedule check for patches for specific CVEs"""
        
        def patch_check_job():
            logger.info(f"Checking for patches for {image}")
            
            # Parse image and tag
            if ':' in image:
                image_name, tag = image.rsplit(':', 1)
            else:
                image_name = image
                tag = 'latest'
            
            # Run scan
            scan_results = self.scanner.scan_image(image_name, tag)
            
            # Check if CVEs are still present
            current_cves = {cve['id'] for cve in scan_results.get('cve_list', [])}
            patched_cves = set(cve_list) - current_cves
            
            if patched_cves:
                logger.info(f"Patches detected for {image}: {patched_cves}")
                
                if self.notifier:
                    # Send patch notification
                    message = f"✅ Patches applied for {image}:\n" + \
                             "\n".join([f"- {cve}" for cve in patched_cves])
                    # self.notifier.send_message(message)
        
        # Schedule daily patch check
        schedule.every().day.at("09:00").do(patch_check_job).tag(f"patch_check_{image}")
    
    def cancel_rescan(self, job_id: str):
        """Cancel a scheduled rescan"""
        
        schedule.clear(job_id)
        if job_id in self.scheduled_jobs:
            del self.scheduled_jobs[job_id]
            logger.info(f"Cancelled scheduled scan: {job_id}")
    
    def start(self):
        """Start the scheduler in a background thread"""
        
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        self.running = True
        
        def run_scheduler():
            while self.running:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        
        self.thread = threading.Thread(target=run_scheduler, daemon=True)
        self.thread.start()
        logger.info("Rescan scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Rescan scheduler stopped")
    
    def get_schedule_status(self) -> Dict:
        """Get current schedule status"""
        
        return {
            'running': self.running,
            'scheduled_jobs': self.scheduled_jobs,
            'pending_jobs': [
                {
                    'job': str(job),
                    'next_run': job.next_run.isoformat() if job.next_run else None
                }
                for job in schedule.jobs
            ],
            'scan_history_count': len(self.scan_history)
        }