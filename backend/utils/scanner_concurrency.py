import asyncio
import logging
from typing import Dict, List, Any, Callable, Awaitable, Optional
from dataclasses import dataclass
from enum import Enum
import time
from concurrent.futures import ThreadPoolExecutor
import psutil

logger = logging.getLogger(__name__)

class ScannerPriority(Enum):
    """Priority levels for scanner execution."""
    CRITICAL = 1    # Security headers, authentication
    HIGH = 2        # XSS, SQL injection, CSRF
    MEDIUM = 3      # Directory enumeration, file finders
    LOW = 4         # Technology fingerprinting, reporting
    BACKGROUND = 5  # Non-critical scans

@dataclass
class ScannerTask:
    """Represents a scanner task with metadata."""
    scanner_id: str
    scanner_name: str
    priority: ScannerPriority
    coro: Callable[[], Awaitable[Any]]
    options: Dict[str, Any]
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[Exception] = None
    memory_usage: Optional[float] = None

class ScannerConcurrencyManager:
    """Manages concurrent execution of scanners with resource monitoring."""
    
    def __init__(self, 
                 max_concurrent_scanners: int = 50,  # Increased from 30 to 50 for higher parallelism
                 max_memory_percent: float = 95.0,  # Increased from 90.0 to 95.0 for better resource utilization
                 priority_queues: bool = True,
                 enable_circuit_breaker: bool = True,
                 per_host_max_concurrency: int = 25):  # Increased from 15 to 25 for faster scanning
        
        self.max_concurrent_scanners = max_concurrent_scanners
        self.max_memory_percent = max_memory_percent
        self.priority_queues = priority_queues
        self.enable_circuit_breaker = enable_circuit_breaker
        
        # Task management
        self._active_tasks: Dict[str, ScannerTask] = {}
        self._task_queue: asyncio.Queue = asyncio.Queue()
        self._completed_tasks: List[ScannerTask] = []
        self._failed_tasks: List[ScannerTask] = []
        
        # Resource monitoring - more lenient settings
        self._memory_monitor = psutil.Process()
        self._circuit_breaker_failures = 0
        self._circuit_breaker_threshold = 15  # Increased from 5 to 15
        self._circuit_breaker_cooldown = 30  # Reduced from 60 to 30 seconds
        self._last_circuit_breaker_trip = 0
        
        # Statistics
        self._total_tasks_processed = 0
        self._total_execution_time = 0.0
        self._peak_memory_usage = 0.0
        
        # Control flags
        self._running = False
        self._shutdown_event = asyncio.Event()
        
        # Thread pool for CPU-bound operations - increased worker count
        self._thread_pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="ScannerWorker")  # Increased from 4 to 12

        # Per-scanner circuit breaker - more lenient settings
        self._per_scanner_failures: Dict[str, int] = {}
        self._per_scanner_open_until: Dict[str, float] = {}
        self._per_scanner_threshold = 10  # Increased from 3 to 10
        self._per_scanner_cooldown = 60.0  # Reduced from 120.0 to 60.0 seconds
        # Per-host concurrency caps
        self._per_host_max = max(1, int(per_host_max_concurrency))
        self._per_host_active: Dict[str, int] = {}
    
    async def start(self):
        """Start the concurrency manager."""
        if self._running:
            return
        
        self._running = True
        self._shutdown_event.clear()
        
        # Start the task processor
        asyncio.create_task(self._process_task_queue())
        
        # Start the resource monitor
        asyncio.create_task(self._monitor_resources())
        
        logger.info(f"Scanner concurrency manager started with max {self.max_concurrent_scanners} concurrent scanners")
    
    async def stop(self):
        """Stop the concurrency manager gracefully."""
        if not self._running:
            return
        
        self._running = False
        self._shutdown_event.set()
        
        # Wait for active tasks to complete
        if self._active_tasks:
            logger.info(f"Waiting for {len(self._active_tasks)} active tasks to complete...")
            await asyncio.gather(*[task.coro() for task in self._active_tasks.values()], return_exceptions=True)
        
        # Shutdown thread pool
        self._thread_pool.shutdown(wait=True)
        
        logger.info("Scanner concurrency manager stopped")
    
    async def submit_scanner(self, 
                           scanner_id: str,
                           scanner_name: str,
                           coro: Callable[[], Awaitable[Any]],
                           options: Dict[str, Any],
                           priority: ScannerPriority = ScannerPriority.MEDIUM) -> str:
        """Submit a scanner task for execution."""
        
        if not self._running:
            raise RuntimeError("Concurrency manager is not running")
        
        # Check circuit breaker
        if self._is_circuit_breaker_open():
            raise RuntimeError("Circuit breaker is open - too many failures")

        # Per-scanner circuit breaker: skip scanners that are temporarily open
        now = time.time()
        open_until = self._per_scanner_open_until.get(scanner_name)
        if open_until and now < open_until:
            raise RuntimeError(f"Circuit breaker open for scanner {scanner_name}")
        
        # Create scanner task
        task = ScannerTask(
            scanner_id=scanner_id,
            scanner_name=scanner_name,
            priority=priority,
            coro=coro,
            options=options,
            created_at=time.time()
        )
        # If capacity is available, start immediately to avoid queue pauses
        try:
            if len(self._active_tasks) < self.max_concurrent_scanners and self._check_resource_limits():
                await self._start_task(task)
            else:
                # Add to queue
                await self._task_queue.put(task)
            logger.debug(f"Submitted scanner {scanner_name} with priority {priority.name}")
        except Exception:
            # Fallback to queue on any error starting immediately
            await self._task_queue.put(task)
            logger.debug(f"Enqueued scanner {scanner_name} with priority {priority.name}")
        
        return scanner_id
    
    async def _process_task_queue(self):
        """Process tasks from the queue with priority handling."""
        while self._running and not self._shutdown_event.is_set():
            try:
                # Process high-priority tasks first
                if self.priority_queues:
                    # Check for high-priority tasks
                    high_priority_tasks = [
                        task for task in self._active_tasks.values()
                        if task.priority in [ScannerPriority.CRITICAL, ScannerPriority.HIGH]
                        and task.started_at is None
                    ]
                    
                    if high_priority_tasks:
                        # Start high-priority tasks immediately - increased from 2 to 4
                        for task in high_priority_tasks[:4]:  # Start up to 4 high-priority tasks
                            if len(self._active_tasks) < self.max_concurrent_scanners:
                                await self._start_task(task)
                                continue
                # Process regular queue greedily until capacity is filled
                while (not self._task_queue.empty()) and (len(self._active_tasks) < self.max_concurrent_scanners):
                    try:
                        # If priority queues are enabled, attempt to pick a higher-priority task opportunistically
                        task = None
                        if self.priority_queues:
                            task = await self._get_next_priority_task()
                        if task is None:
                            task = self._task_queue.get_nowait()
                        await self._start_task(task)
                    except asyncio.QueueEmpty:
                        break
                
                # Check for completed tasks
                await self._check_completed_tasks()
                
                # Reduced sleep time for faster response (avoid visible pauses)
                await asyncio.sleep(0.01)  # Reduced from 0.02 to 0.01 for faster task processing
                
            except Exception as e:
                logger.error(f"Error in task queue processor: {e}")
                await asyncio.sleep(1)  # Brief pause on error
    
    async def _get_next_priority_task(self) -> Optional[ScannerTask]:
        """Get the next highest priority task from the queue."""
        # This is a simplified implementation - in practice, you might want
        # a proper priority queue data structure
        tasks = []
        while not self._task_queue.empty():
            try:
                task = self._task_queue.get_nowait()
                tasks.append(task)
            except asyncio.QueueEmpty:
                break
        
        if not tasks:
            return None
        
        # Sort by priority and return highest
        tasks.sort(key=lambda t: t.priority.value)
        highest_task = tasks[0]
        
        # Put the rest back in the queue
        for task in tasks[1:]:
            await self._task_queue.put(task)
        
        return highest_task
    
    async def _execute_scanner(self, task: ScannerTask):
        """Execute a scanner task with monitoring."""
        try:
            # Mark as started
            task.started_at = time.time()
            self._active_tasks[task.scanner_id] = task
            
            # Record memory usage
            task.memory_usage = self._memory_monitor.memory_percent()
            self._peak_memory_usage = max(self._peak_memory_usage, task.memory_usage)
            
            logger.debug(f"Starting scanner {task.scanner_name} (ID: {task.scanner_id})")
            
            # Execute the scanner with timeout protection; ensure per-task cap well below global 180s
            start_time = time.time()
            try:
                # Cap each scanner to 90s max so the whole run can finish within 180s
                result = await asyncio.wait_for(task.coro(), timeout=90)
                execution_time = time.time() - start_time
                
                # Mark as completed
                task.completed_at = time.time()
                task.result = result
                
                # Update statistics
                self._total_tasks_processed += 1
                self._total_execution_time += execution_time
                
                logger.info(f"Scanner {task.scanner_name} completed in {execution_time:.2f}s")
                
            except asyncio.TimeoutError:
                # Handle timeout specifically - don't let it block other scanners
                task.completed_at = time.time()
                task.error = Exception(f"Scanner {task.scanner_name} timed out after 90 seconds")
                logger.warning(f"Scanner {task.scanner_name} timed out at 90s cap - continuing with other scanners")
                
                # Only update circuit breaker for repeated failures, not single timeouts
                self._per_scanner_failures[task.scanner_name] = self._per_scanner_failures.get(task.scanner_name, 0) + 1
                if self._per_scanner_failures[task.scanner_name] >= self._per_scanner_threshold:
                    self._per_scanner_open_until[task.scanner_name] = time.time() + self._per_scanner_cooldown
                    logger.warning(f"Per-scanner circuit opened for {task.scanner_name} for {self._per_scanner_cooldown}s")
                    # Only then update global circuit breaker
                    self._circuit_breaker_failures += 1
                    if self._circuit_breaker_failures >= self._circuit_breaker_threshold:
                        self._last_circuit_breaker_trip = time.time()
                        logger.warning(f"Circuit breaker opened after {self._circuit_breaker_failures} failures")
            
        except Exception as e:
            # Mark as failed
            task.completed_at = time.time()
            task.error = e
            
            # Update circuit breaker
            self._circuit_breaker_failures += 1
            if self._circuit_breaker_failures >= self._circuit_breaker_threshold:
                self._last_circuit_breaker_trip = time.time()
                logger.warning(f"Circuit breaker opened after {self._circuit_breaker_failures} failures")

            # Per-scanner failure tracking
            self._per_scanner_failures[task.scanner_name] = self._per_scanner_failures.get(task.scanner_name, 0) + 1
            if self._per_scanner_failures[task.scanner_name] >= self._per_scanner_threshold:
                self._per_scanner_open_until[task.scanner_name] = time.time() + self._per_scanner_cooldown
                logger.warning(f"Per-scanner circuit opened for {task.scanner_name} for {self._per_scanner_cooldown}s")
            
            logger.error(f"Scanner {task.scanner_name} failed: {e}")
            
        finally:
            # Remove from active tasks immediately to free up concurrency slots
            if task.scanner_id in self._active_tasks:
                del self._active_tasks[task.scanner_id]
            
            # Add to completed/failed lists
            if task.error:
                self._failed_tasks.append(task)
            else:
                self._completed_tasks.append(task)
            # Decrement per-host active
            try:
                target_url = (task.options or {}).get('target') or ''
                from urllib.parse import urlparse
                host = urlparse(target_url).netloc if target_url else ''
                if host and host in self._per_host_active:
                    self._per_host_active[host] = max(0, self._per_host_active.get(host, 1) - 1)
            except Exception:
                pass
    
    async def _start_task(self, task: ScannerTask):
        """Start a scanner task."""
        try:
            # Enforce per-host concurrency cap based on target host if provided in options
            target_url = (task.options or {}).get('target') or ''
            host = ''
            try:
                from urllib.parse import urlparse
                host = urlparse(target_url).netloc
            except Exception:
                host = ''
            if host:
                active_for_host = self._per_host_active.get(host, 0)
                if active_for_host >= self._per_host_max:
                    # Requeue to avoid exceeding per-host concurrency
                    await self._task_queue.put(task)
                    return

            task.started_at = time.time()
            self._active_tasks[task.scanner_id] = task
            if host:
                self._per_host_active[host] = self._per_host_active.get(host, 0) + 1
            
            # Execute the task
            asyncio.create_task(self._execute_scanner(task))
            
        except Exception as e:
            logger.error(f"Failed to start task {task.scanner_id}: {e}")
            task.error = e
            task.completed_at = time.time()
            self._failed_tasks.append(task)
            if task.scanner_id in self._active_tasks:
                del self._active_tasks[task.scanner_id]

    async def _check_completed_tasks(self):
        """Check for and handle completed tasks."""
        completed_tasks = []
        
        for scanner_id, task in list(self._active_tasks.items()):
            if task.completed_at is not None:
                completed_tasks.append(scanner_id)
                
                # Move to completed list
                self._completed_tasks.append(task)
                self._total_tasks_processed += 1
                
                if task.completed_at and task.started_at:
                    execution_time = task.completed_at - task.started_at
                    self._total_execution_time += execution_time
        
        # Remove completed tasks from active list
        for scanner_id in completed_tasks:
            del self._active_tasks[scanner_id]
    
    def _check_resource_limits(self) -> bool:
        """Check if we have resources available to start new tasks."""
        try:
            memory_percent = self._memory_monitor.memory_percent()
            return memory_percent < self.max_memory_percent
        except Exception:
            # If we can't check memory, assume it's OK
            return True
    
    def _is_circuit_breaker_open(self) -> bool:
        """Check if the circuit breaker is open."""
        if not self.enable_circuit_breaker:
            return False
        
        if self._circuit_breaker_failures >= self._circuit_breaker_threshold:
            # Check if cooldown period has passed
            if time.time() - self._last_circuit_breaker_trip > self._circuit_breaker_cooldown:
                # Reset circuit breaker
                self._circuit_breaker_failures = 0
                logger.info("Circuit breaker reset after cooldown period")
                return False
            return True
        
        return False
    
    async def _monitor_resources(self):
        """Monitor system resources and adjust limits if needed."""
        while self._running and not self._shutdown_event.is_set():
            try:
                # Check memory usage
                memory_percent = self._memory_monitor.memory_percent()
                
                # Adjust concurrency based on memory pressure with less aggressive thresholds
                if memory_percent > self.max_memory_percent * 0.95:
                    # Only reduce concurrency under very high memory pressure
                    new_limit = max(10, self.max_concurrent_scanners - 5)
                    if new_limit != self.max_concurrent_scanners:
                        self.max_concurrent_scanners = new_limit
                        logger.warning(f"Reduced max concurrent scanners to {self.max_concurrent_scanners} due to high memory pressure ({memory_percent:.1f}%)")
                elif memory_percent < self.max_memory_percent * 0.7:
                    # Increase concurrency when memory is available - allow higher limit
                    new_limit = min(100, self.max_concurrent_scanners + 5)
                    if new_limit != self.max_concurrent_scanners:
                        self.max_concurrent_scanners = new_limit
                        logger.debug(f"Increased max concurrent scanners to {self.max_concurrent_scanners} (memory: {memory_percent:.1f}%)")
                
                # More frequent monitoring for better responsiveness
                await asyncio.sleep(0.5)  # Check twice per second for faster adaptation
                
            except Exception as e:
                logger.error(f"Error in resource monitor: {e}")
                await asyncio.sleep(2)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics and status."""
        return {
            "running": self._running,
            "active_tasks": len(self._active_tasks),
            "queued_tasks": self._task_queue.qsize(),
            "completed_tasks": len(self._completed_tasks),
            "failed_tasks": len(self._failed_tasks),
            "total_processed": self._total_tasks_processed,
            "avg_execution_time": (self._total_execution_time / max(1, self._total_tasks_processed)),
            "peak_memory_usage": self._peak_memory_usage,
            "current_memory_usage": self._memory_monitor.memory_percent(),
            "max_concurrent_scanners": self.max_concurrent_scanners,
            "circuit_breaker_failures": self._circuit_breaker_failures,
            "circuit_breaker_open": self._is_circuit_breaker_open(),
            "per_scanner_open": {k: (time.time() < v) for k, v in self._per_scanner_open_until.items()}
        }
    
    def get_task_status(self, scanner_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task."""
        if scanner_id in self._active_tasks:
            task = self._active_tasks[scanner_id]
            return {
                "status": "running",
                "scanner_name": task.scanner_name,
                "started_at": task.started_at,
                "memory_usage": task.memory_usage
            }
        
        # Check completed tasks
        for task in self._completed_tasks:
            if task.scanner_id == scanner_id:
                return {
                    "status": "completed",
                    "scanner_name": task.scanner_name,
                    "started_at": task.started_at,
                    "completed_at": task.completed_at,
                    "execution_time": task.completed_at - task.started_at if task.started_at else None
                }
        
        # Check failed tasks
        for task in self._failed_tasks:
            if task.scanner_id == scanner_id:
                return {
                    "status": "failed",
                    "scanner_name": task.scanner_name,
                    "started_at": task.started_at,
                    "completed_at": task.completed_at,
                    "error": str(task.error) if task.error else None
                }
        
        return None

# Global concurrency manager instance
_concurrency_manager: Optional[ScannerConcurrencyManager] = None

def get_scanner_concurrency_manager() -> ScannerConcurrencyManager:
    """Get or create the global scanner concurrency manager."""
    global _concurrency_manager
    if _concurrency_manager is None:
        try:
            from backend.config import settings as _settings
            # Increase default concurrency for faster scanning
            configured_max = int(getattr(_settings, 'MAX_CONCURRENT_SCANS', 75) or 75)
            max_scanners = max(30, min(100, configured_max))
            per_host_max = int(getattr(_settings, 'PER_HOST_MAX_CONCURRENCY', 12) or 12)
        except Exception:
            max_scanners = 30
            per_host_max = 12
        _concurrency_manager = ScannerConcurrencyManager(
            max_concurrent_scanners=max_scanners,
            max_memory_percent=85.0,  # Allow slightly higher memory usage
            priority_queues=True,
            enable_circuit_breaker=True,
            per_host_max_concurrency=per_host_max,
        )
    return _concurrency_manager
