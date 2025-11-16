"""
Selenium-based login helper for complex websites with advanced authentication.
Handles JavaScript-heavy sites, dynamic forms, and complex login flows.
"""

import time
import logging
from typing import Optional, Dict, Tuple
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

logger = logging.getLogger(__name__)


class SeleniumLoginHelper:
    """Helper class for Selenium-based login automation"""
    
    def __init__(self, headless: bool = True, proxy: Optional[str] = None):
        """
        Initialize Selenium helper
        
        Args:
            headless: Run browser in headless mode
            proxy: Proxy string in format 'host:port:username:password' or 'host:port'
        """
        self.headless = headless
        self.proxy = proxy
        self.driver = None
        
    def _setup_driver(self) -> webdriver.Chrome:
        """Setup Chrome driver with options"""
        options = Options()
        
        if self.headless:
            options.add_argument('--headless=new')
        
        # Standard options for stability
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        
        # User agent
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        # Proxy configuration
        if self.proxy:
            proxy_formatted = self._format_proxy(self.proxy)
            if proxy_formatted:
                options.add_argument(f'--proxy-server={proxy_formatted}')
        
        try:
            driver = webdriver.Chrome(options=options)
            driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            return driver
        except Exception as e:
            logger.error(f"Failed to initialize Chrome driver: {e}")
            raise
    
    def _format_proxy(self, proxy: str) -> Optional[str]:
        """Format proxy string for Selenium"""
        try:
            # Parse format: host:port:username:password or host:port
            parts = proxy.split(':')
            
            if len(parts) >= 2:
                host = parts[0]
                port = parts[1]
                
                # Basic format without auth
                if len(parts) == 2:
                    return f"http://{host}:{port}"
                
                # Format with authentication (requires extension)
                # For now, return basic format and log warning
                if len(parts) >= 4:
                    logger.warning("Proxy authentication in Selenium requires Chrome extension. Using basic proxy.")
                    return f"http://{host}:{port}"
                    
        except Exception as e:
            logger.error(f"Error formatting proxy: {e}")
        
        return None
    
    def login(self, url: str, email: str, password: str, 
              username_selectors: Optional[list] = None,
              password_selectors: Optional[list] = None,
              submit_selectors: Optional[list] = None,
              timeout: int = 30) -> Tuple[bool, str]:
        """
        Attempt login on a site using Selenium
        
        Args:
            url: Login page URL
            email: Email/username
            password: Password
            username_selectors: List of CSS selectors for username field
            password_selectors: List of CSS selectors for password field
            submit_selectors: List of CSS selectors for submit button
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        # Default selectors
        if not username_selectors:
            username_selectors = [
                'input[type="email"]',
                'input[name*="email"]',
                'input[name*="username"]',
                'input[name*="user"]',
                'input[id*="email"]',
                'input[id*="username"]',
                'input[placeholder*="email" i]',
                'input[placeholder*="username" i]'
            ]
        
        if not password_selectors:
            password_selectors = [
                'input[type="password"]',
                'input[name*="password"]',
                'input[name*="pass"]',
                'input[id*="password"]',
                'input[id*="pass"]'
            ]
        
        if not submit_selectors:
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button[name*="submit"]',
                'button[name*="login"]',
                'button[name*="signin"]',
                'button:contains("Sign in")',
                'button:contains("Log in")',
                'button:contains("Login")'
            ]
        
        try:
            # Setup driver
            self.driver = self._setup_driver()
            wait = WebDriverWait(self.driver, timeout)
            
            # Navigate to login page
            logger.info(f"Navigating to {url}")
            self.driver.get(url)
            time.sleep(2)  # Wait for page load
            
            # Find and fill username field
            username_field = None
            for selector in username_selectors:
                try:
                    username_field = wait.until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, selector))
                    )
                    if username_field and username_field.is_displayed():
                        break
                except:
                    continue
            
            if not username_field:
                return False, "Could not find username/email field"
            
            # Fill username
            username_field.clear()
            username_field.send_keys(email)
            logger.info("Username field filled")
            time.sleep(0.5)
            
            # Find and fill password field
            password_field = None
            for selector in password_selectors:
                try:
                    password_field = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if password_field and password_field.is_displayed():
                        break
                except:
                    continue
            
            if not password_field:
                return False, "Could not find password field"
            
            # Fill password
            password_field.clear()
            password_field.send_keys(password)
            logger.info("Password field filled")
            time.sleep(0.5)
            
            # Find and click submit button
            submitted = False
            for selector in submit_selectors:
                try:
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if submit_button and submit_button.is_displayed():
                        submit_button.click()
                        submitted = True
                        logger.info(f"Submit button clicked: {selector}")
                        break
                except:
                    continue
            
            # If no submit button found, try pressing Enter
            if not submitted:
                password_field.send_keys(Keys.RETURN)
                logger.info("Pressed Enter key")
            
            # Wait for navigation or response
            time.sleep(3)
            
            # Check for success indicators
            current_url = self.driver.current_url
            page_source = self.driver.page_source.lower()
            
            # Success indicators
            success_keywords = ['dashboard', 'account', 'welcome', 'logout', 'sign out', 'profile']
            failure_keywords = ['invalid', 'incorrect', 'wrong', 'error', 'failed', 'denied']
            
            # Check for success
            if any(keyword in current_url.lower() for keyword in success_keywords):
                return True, f"Login successful - redirected to {current_url}"
            
            if any(keyword in page_source for keyword in success_keywords):
                return True, "Login successful - success indicators found"
            
            # Check for failure
            if any(keyword in page_source for keyword in failure_keywords):
                return False, "Login failed - error message detected"
            
            # Check if URL changed (might indicate success)
            if current_url != url and 'login' not in current_url.lower():
                return True, f"Login possibly successful - URL changed to {current_url}"
            
            return False, "Login result unclear - no clear success or failure indicators"
            
        except TimeoutException:
            return False, "Timeout waiting for page elements"
        except Exception as e:
            logger.error(f"Error during Selenium login: {e}")
            return False, f"Error: {str(e)}"
        finally:
            if self.driver:
                try:
                    self.driver.quit()
                except:
                    pass
    
    def close(self):
        """Close the browser"""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
