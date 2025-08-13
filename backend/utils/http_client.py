import asyncio
import hashlib
import json
import time
from typing import AsyncIterator, Optional, Dict, Any, Tuple
from contextlib import asynccontextmanager
import httpx
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)

class HTTPResponseCache:
    """Simple in-memory cache for HTTP responses with TTL."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._lock = asyncio.Lock()
    
    def _make_key(self, method: str, url: str, headers: Dict, body: Optional[str] = None) -> str:
        """Create a cache key from request parameters."""
        key_data = {
            'method': method.upper(),
            'url': url,
            'headers': sorted(headers.items()),
            'body': body or ''
        }
        return hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
    
    async def get(self, method: str, url: str, headers: Dict, body: Optional[str] = None) -> Optional[Any]:
        """Get cached response if available and not expired."""
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            if key in self.cache:
                response, timestamp = self.cache[key]
                if time.time() - timestamp < self.default_ttl:
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    logger.debug(f"Cache hit for {method} {url}")
                    return response
                else:
                    # Expired, remove
                    del self.cache[key]
            return None
    
    async def set(self, method: str, url: str, headers: Dict, body: Optional[str] = None, 
                  response: Any = None, ttl: Optional[int] = None) -> None:
        """Cache a response with optional custom TTL."""
        async with self._lock:
            key = self._make_key(method, url, headers, body)
            ttl = ttl or self.default_ttl
            
            # Remove oldest if at capacity
            if len(self.cache) >= self.max_size:
                self.cache.popitem(last=False)
            
            self.cache[key] = (response, time.time())
            logger.debug(f"Cached response for {method} {url}")

class SharedHTTPClient:
    """Shared HTTP client with connection pooling, caching, and request deduplication."""
    
    def __init__(self, 
                 max_connections: int = 100,
                 max_keepalive_connections: int = 20,
                 keepalive_expiry: float = 30.0,
                 cache_max_size: int = 1000,
                 cache_default_ttl: int = 300):
        
        self.max_connections = max_connections
        self.max_keepalive_connections = max_keepalive_connections
        self.keepalive_expiry = keepalive_expiry
        self.cache = HTTPResponseCache(cache_max_size, cache_default_ttl)
        self._active_requests: Dict[str, asyncio.Task] = {}
        self._request_lock = asyncio.Lock()
        
        # Connection pool limits
        self._limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry
        )
    
    def _get_client_config(self, 
                          timeout: float = 30.0,
                          verify: bool = False,
                          follow_redirects: bool = True,
                          headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Get client configuration with defaults."""
        default_headers = {
            "User-Agent": "NightingaleScanner/2.0 (+https://project-nightingale.dev)"
        }
        
        merged_headers = {**default_headers, **(headers or {})}
        
        return {
            "timeout": timeout,
            "verify": verify,
            "follow_redirects": follow_redirects,
            "headers": merged_headers,
            "limits": self._limits
        }
    
    async def _deduplicate_request(self, method: str, url: str, headers: Dict, 
                                  body: Optional[str] = None) -> Optional[Any]:
        """Check if identical request is already in progress and wait for result."""
        request_id = f"{method}:{url}:{hash(frozenset(headers.items()))}:{hash(body)}"
        
        async with self._request_lock:
            if request_id in self._active_requests:
                # Wait for existing request to complete
                existing_task = self._active_requests[request_id]
                logger.debug(f"Deduplicating request {method} {url}")
                try:
                    return await existing_task
                except Exception as e:
                    logger.warning(f"Deduplicated request failed: {e}")
                    return None
            return None
    
    async def _mark_request_complete(self, method: str, url: str, headers: Dict, 
                                    body: Optional[str] = None) -> None:
        """Mark request as complete and remove from active requests."""
        request_id = f"{method}:{url}:{hash(frozenset(headers.items()))}:{hash(body)}"
        async with self._request_lock:
            if request_id in self._active_requests:
                del self._active_requests[request_id]
    
    async def request(self, 
                     method: str,
                     url: str,
                     headers: Optional[Dict[str, str]] = None,
                     body: Optional[str] = None,
                     timeout: float = 30.0,
                     verify: bool = False,
                     follow_redirects: bool = True,
                     use_cache: bool = True,
                     cache_ttl: Optional[int] = None) -> httpx.Response:
        """Make an HTTP request with caching and deduplication."""
        
        # Check cache first
        if use_cache and method.upper() in ['GET', 'HEAD']:
            cached_response = await self.cache.get(method, url, headers or {}, body)
            if cached_response:
                return cached_response
        
        # Check for duplicate requests
        dedup_result = await self._deduplicate_request(method, url, headers or {}, body)
        if dedup_result:
            return dedup_result
        
        # Create new request task
        async def _make_request():
            try:
                config = self._get_client_config(timeout, verify, follow_redirects, headers)
                async with httpx.AsyncClient(**config) as client:
                    response = await client.request(method, url, headers=config['headers'], content=body)
                    
                    # Cache successful GET/HEAD responses
                    if use_cache and method.upper() in ['GET', 'HEAD'] and response.status_code < 400:
                        await self.cache.set(method, url, headers or {}, body, response, cache_ttl)
                    
                    return response
            finally:
                await self._mark_request_complete(method, url, headers or {}, body)
        
        # Create and track the task
        task = asyncio.create_task(_make_request())
        request_id = f"{method}:{url}:{hash(frozenset((headers or {}).items()))}:{hash(body)}"
        
        async with self._request_lock:
            self._active_requests[request_id] = task
        
        return await task
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for GET requests."""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for POST requests."""
        return await self.request('POST', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for HEAD requests."""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> httpx.Response:
        """Convenience method for OPTIONS requests."""
        return await self.request('OPTIONS', url, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics for monitoring."""
        return {
            "cache_size": len(self.cache.cache),
            "active_requests": len(self._active_requests),
            "max_connections": self.max_connections,
            "max_keepalive": self.max_keepalive_connections
        }

# Global shared client instance
_shared_client: Optional[SharedHTTPClient] = None

def get_shared_http_client() -> SharedHTTPClient:
    """Get or create the global shared HTTP client instance."""
    global _shared_client
    if _shared_client is None:
        _shared_client = SharedHTTPClient()
    return _shared_client

@asynccontextmanager
async def get_http_client(
    *,
    timeout: float = 30.0,
    verify: bool = False,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
    use_cache: bool = True,
    cache_ttl: Optional[int] = None
) -> AsyncIterator[httpx.AsyncClient]:
    """Enhanced HTTP client context manager with caching and pooling.
    
    This maintains backward compatibility while providing access to the shared client.
    """
    # For backward compatibility, still yield an httpx.AsyncClient
    # but use the shared client internally for actual requests
    config = {
        "timeout": timeout,
        "verify": verify,
        "follow_redirects": follow_redirects,
        "headers": headers or {}
    }
    
    # Create a wrapper client that delegates to shared client
    class WrappedClient:
        def __init__(self, shared_client: SharedHTTPClient, config: Dict):
            self.shared_client = shared_client
            self.config = config
        
        async def get(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.get(url, headers=merged_headers, **kwargs)
        
        async def post(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.post(url, headers=merged_headers, **kwargs)
        
        async def head(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.head(url, headers=merged_headers, **kwargs)
        
        async def options(self, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.options(url, headers=merged_headers, **kwargs)
        
        async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
            merged_headers = {**self.config.get('headers', {}), **kwargs.get('headers', {})}
            return await self.shared_client.request(method, url, headers=merged_headers, **kwargs)
    
    shared_client = get_shared_http_client()
    wrapped_client = WrappedClient(shared_client, config)
    
    try:
        yield wrapped_client
    finally:
        # Cleanup handled by shared client
        pass
