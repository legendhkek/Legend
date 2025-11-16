"""
Local CAPTCHA solver for hCaptcha and reCAPTCHA using audio challenge method.
This module provides a way to solve CAPTCHAs without external APIs for basic cases.
"""

import time
import logging
import requests
from typing import Optional, Tuple
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException

logger = logging.getLogger(__name__)


class LocalCaptchaSolver:
    """
    Local CAPTCHA solver that attempts to solve CAPTCHAs without external APIs.
    
    Note: This is a basic implementation. For production use, consider using
    a proper CAPTCHA solving service like 2captcha or Anti-Captcha.
    """
    
    def __init__(self, driver: Optional[webdriver.Chrome] = None):
        """
        Initialize the local CAPTCHA solver
        
        Args:
            driver: Selenium WebDriver instance (optional)
        """
        self.driver = driver
        self.audio_solver_available = False
        
        # Check if speech recognition is available
        try:
            import speech_recognition as sr
            self.audio_solver_available = True
            self.recognizer = sr.Recognizer()
            logger.info("Audio CAPTCHA solver available (speech_recognition installed)")
        except ImportError:
            logger.warning("speech_recognition not installed - audio CAPTCHA solving disabled")
            self.recognizer = None
    
    def detect_captcha_type(self, page_source: str) -> Optional[str]:
        """
        Detect the type of CAPTCHA on the page
        
        Args:
            page_source: HTML source of the page
            
        Returns:
            CAPTCHA type ('hcaptcha', 'recaptcha', 'recaptcha_v3', 'turnstile', etc.) or None
        """
        page_lower = page_source.lower()
        
        if 'hcaptcha.com' in page_lower or 'h-captcha' in page_lower:
            return 'hcaptcha'
        elif 'recaptcha/api.js' in page_lower or 'g-recaptcha' in page_lower:
            if 'recaptcha/api.js?render=' in page_lower:
                return 'recaptcha_v3'
            return 'recaptcha_v2'
        elif 'challenges.cloudflare.com' in page_lower or 'cf-turnstile' in page_lower:
            return 'turnstile'
        elif 'funcaptcha.com' in page_lower or 'arkoselabs.com' in page_lower:
            return 'funcaptcha'
        
        return None
    
    def is_captcha_present(self) -> bool:
        """
        Check if a CAPTCHA is present on the current page
        
        Returns:
            True if CAPTCHA detected, False otherwise
        """
        if not self.driver:
            return False
        
        try:
            page_source = self.driver.page_source
            captcha_type = self.detect_captcha_type(page_source)
            return captcha_type is not None
        except:
            return False
    
    def solve_hcaptcha_audio(self, timeout: int = 30) -> Tuple[bool, str]:
        """
        Attempt to solve hCaptcha using the audio challenge method
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.driver:
            return False, "No WebDriver instance available"
        
        if not self.audio_solver_available:
            return False, "Audio solver not available (install speech_recognition and pydub)"
        
        try:
            wait = WebDriverWait(self.driver, timeout)
            
            # Find hCaptcha iframe
            captcha_iframe = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'iframe[src*="hcaptcha.com"]'))
            )
            
            # Switch to iframe
            self.driver.switch_to.frame(captcha_iframe)
            
            # Click the checkbox
            checkbox = wait.until(
                EC.element_to_be_clickable((By.ID, 'checkbox'))
            )
            checkbox.click()
            
            # Wait a bit for challenge to appear
            time.sleep(2)
            
            # Switch back to default content
            self.driver.switch_to.default_content()
            
            # Find challenge iframe
            challenge_iframe = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'iframe[src*="hcaptcha.com"][src*="challenge"]'))
            )
            
            # Switch to challenge iframe
            self.driver.switch_to.frame(challenge_iframe)
            
            # Look for audio button
            try:
                audio_button = wait.until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, 'button[aria-label*="audio"]'))
                )
                audio_button.click()
                time.sleep(1)
                
                # Get audio source URL
                audio_source = self.driver.find_element(By.TAG_NAME, 'audio').get_attribute('src')
                
                if audio_source:
                    # Download and solve audio
                    audio_text = self._solve_audio_challenge(audio_source)
                    
                    if audio_text:
                        # Enter the solved text
                        answer_input = self.driver.find_element(By.CSS_SELECTOR, 'input[type="text"]')
                        answer_input.send_keys(audio_text)
                        
                        # Submit
                        submit_button = self.driver.find_element(By.CSS_SELECTOR, 'button[type="submit"]')
                        submit_button.click()
                        
                        time.sleep(2)
                        
                        # Switch back to default content
                        self.driver.switch_to.default_content()
                        
                        return True, "hCaptcha audio challenge solved"
                    else:
                        return False, "Could not transcribe audio"
                else:
                    return False, "Could not get audio source"
                    
            except:
                # Audio button not found or not clickable
                return False, "Audio challenge not available"
            
        except TimeoutException:
            return False, "Timeout waiting for CAPTCHA elements"
        except Exception as e:
            logger.error(f"Error solving hCaptcha: {e}")
            return False, f"Error: {str(e)}"
        finally:
            try:
                self.driver.switch_to.default_content()
            except:
                pass
    
    def _solve_audio_challenge(self, audio_url: str) -> Optional[str]:
        """
        Download and transcribe audio challenge
        
        Args:
            audio_url: URL of the audio file
            
        Returns:
            Transcribed text or None
        """
        if not self.audio_solver_available:
            return None
        
        try:
            import speech_recognition as sr
            from pydub import AudioSegment
            import io
            
            # Download audio
            response = requests.get(audio_url, timeout=10)
            response.raise_for_status()
            
            # Convert to WAV format
            audio = AudioSegment.from_mp3(io.BytesIO(response.content))
            wav_data = io.BytesIO()
            audio.export(wav_data, format='wav')
            wav_data.seek(0)
            
            # Transcribe
            with sr.AudioFile(wav_data) as source:
                audio_data = self.recognizer.record(source)
                text = self.recognizer.recognize_google(audio_data)
                return text.strip()
                
        except Exception as e:
            logger.error(f"Error transcribing audio: {e}")
            return None
    
    def solve_recaptcha_v2_audio(self, timeout: int = 30) -> Tuple[bool, str]:
        """
        Attempt to solve reCAPTCHA v2 using the audio challenge method
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if not self.driver:
            return False, "No WebDriver instance available"
        
        if not self.audio_solver_available:
            return False, "Audio solver not available"
        
        try:
            wait = WebDriverWait(self.driver, timeout)
            
            # Find reCAPTCHA iframe
            captcha_iframe = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'iframe[src*="google.com/recaptcha"]'))
            )
            
            # Switch to iframe
            self.driver.switch_to.frame(captcha_iframe)
            
            # Click the checkbox
            checkbox = wait.until(
                EC.element_to_be_clickable((By.CLASS_NAME, 'recaptcha-checkbox-border'))
            )
            checkbox.click()
            
            # Wait for challenge
            time.sleep(2)
            
            # Switch back to default content
            self.driver.switch_to.default_content()
            
            # Find challenge iframe
            challenge_iframe = wait.until(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'iframe[src*="google.com/recaptcha"][src*="bframe"]'))
            )
            
            # Switch to challenge iframe
            self.driver.switch_to.frame(challenge_iframe)
            
            # Click audio button
            audio_button = wait.until(
                EC.element_to_be_clickable((By.ID, 'recaptcha-audio-button'))
            )
            audio_button.click()
            time.sleep(1)
            
            # Get audio source
            audio_source = self.driver.find_element(By.ID, 'audio-source').get_attribute('src')
            
            if audio_source:
                # Solve audio
                audio_text = self._solve_audio_challenge(audio_source)
                
                if audio_text:
                    # Enter answer
                    answer_input = self.driver.find_element(By.ID, 'audio-response')
                    answer_input.send_keys(audio_text)
                    
                    # Submit
                    verify_button = self.driver.find_element(By.ID, 'recaptcha-verify-button')
                    verify_button.click()
                    
                    time.sleep(2)
                    
                    # Switch back
                    self.driver.switch_to.default_content()
                    
                    return True, "reCAPTCHA v2 audio challenge solved"
                else:
                    return False, "Could not transcribe audio"
            else:
                return False, "Could not get audio source"
                
        except TimeoutException:
            return False, "Timeout waiting for CAPTCHA elements"
        except Exception as e:
            logger.error(f"Error solving reCAPTCHA: {e}")
            return False, f"Error: {str(e)}"
        finally:
            try:
                self.driver.switch_to.default_content()
            except:
                pass
    
    def wait_for_manual_solve(self, timeout: int = 120) -> bool:
        """
        Wait for user to manually solve the CAPTCHA
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if CAPTCHA appears to be solved, False otherwise
        """
        if not self.driver:
            return False
        
        logger.info(f"Waiting for manual CAPTCHA solve (timeout: {timeout}s)...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Check if CAPTCHA is still present
                if not self.is_captcha_present():
                    logger.info("CAPTCHA appears to be solved")
                    return True
                
                time.sleep(1)
            except:
                pass
        
        logger.warning("Timeout waiting for manual CAPTCHA solve")
        return False
