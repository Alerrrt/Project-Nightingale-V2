import asyncio
import logging
import time
from enum import Enum
from typing import Optional, Callable, Any, Dict
from functools import wraps

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"      # Failing, rejecting requests
    HALF_OPEN = "half_open"  # Testing if service is recovered

class CircuitBreaker:
    """
    Circuit breaker implementation for handling failures gracefully.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_timeout: float = 5.0,
        name: str = "default"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_timeout = half_open_timeout
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_start_time: Optional[float] = None
        self._success_count = 0
        self._lock = asyncio.Lock()
        
        # Statistics
        self._total_requests = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejections = 0

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count

    @property
    def success_count(self) -> int:
        """Get current success count."""
        return self._success_count

    @property
    def statistics(self) -> Dict[str, int]:
        """Get circuit breaker statistics."""
        return {
            "total_requests": self._total_requests,
            "total_failures": self._total_failures,
            "total_successes": self._total_successes,
            "total_rejections": self._total_rejections,
            "current_failures": self._failure_count,
            "current_successes": self._success_count
        }

    async def execute(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function with circuit breaker protection.
        
        Args:
            func: The async function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            The result of the function execution
            
        Raises:
            CircuitBreakerOpenError: If the circuit is open
            Exception: The original exception from the function
        """
        self._total_requests += 1
        
        if not await self._allow_request():
            self._total_rejections += 1
            raise CircuitBreakerOpenError(
                f"Circuit breaker '{self.name}' is open. "
                f"Last failure: {self._last_failure_time}"
            )

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise

    async def _allow_request(self) -> bool:
        """Check if a request should be allowed based on circuit state."""
        async with self._lock:
            current_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                return True
                
            if self._state == CircuitState.OPEN:
                if current_time - self._last_failure_time >= self.recovery_timeout:
                    logger.info(f"Circuit '{self.name}' transitioning to half-open")
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_start_time = current_time
                    return True
                return False
                
            if self._state == CircuitState.HALF_OPEN:
                if current_time - self._half_open_start_time >= self.half_open_timeout:
                    logger.info(f"Circuit '{self.name}' transitioning to closed")
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    return True
                return True

    async def _on_success(self):
        """Handle successful execution."""
        async with self._lock:
            self._total_successes += 1
            self._success_count += 1
            
            if self._state == CircuitState.HALF_OPEN:
                if self._success_count >= self.failure_threshold:
                    logger.info(f"Circuit '{self.name}' transitioning to closed")
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0

    async def _on_failure(self):
        """Handle execution failure."""
        async with self._lock:
            self._total_failures += 1
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    logger.warning(f"Circuit '{self.name}' transitioning to open")
                    self._state = CircuitState.OPEN
            elif self._state == CircuitState.HALF_OPEN:
                logger.warning(f"Circuit '{self.name}' transitioning back to open")
                self._state = CircuitState.OPEN
                self._success_count = 0

    def reset(self):
        """Reset the circuit breaker to initial state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._half_open_start_time = None
        self._total_requests = 0
        self._total_failures = 0
        self._total_successes = 0
        self._total_rejections = 0

def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: float = 30.0,
    half_open_timeout: float = 5.0,
    name: Optional[str] = None
):
    """
    Decorator for applying circuit breaker pattern to async functions.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time in seconds before attempting recovery
        half_open_timeout: Time in seconds to test recovery
        name: Optional name for the circuit breaker
    """
    def decorator(func):
        cb = CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            half_open_timeout=half_open_timeout,
            name=name or func.__name__
        )
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await cb.execute(func, *args, **kwargs)
            
        wrapper.circuit_breaker = cb
        return wrapper
    return decorator

class CircuitBreakerOpenError(Exception):
    """Raised when a circuit breaker is open and rejecting requests."""
    pass 