# Universal Account Checker v5.0 Advanced Edition

A powerful, multi-threaded account checker with advanced site detection, proxy support, and CAPTCHA handling capabilities.

## Features

### ✨ Core Features
- **Universal Site Support**: Automatically detects login forms and authentication methods
- **Multi-threaded Processing**: Fast concurrent checking with configurable thread pools
- **Advanced Proxy Support**: HTTP, HTTPS, SOCKS4, SOCKS5, residential, and datacenter proxies
- **CAPTCHA Detection & Solving**: Detects hCaptcha, reCAPTCHA, Turnstile, and FunCAPTCHA
- **Site-Specific Handlers**: Optimized configurations for popular sites
- **GUI & CLI Modes**: User-friendly interface or command-line operation
- **Selenium Integration**: Handles JavaScript-heavy sites and complex authentication flows

### 🎯 Supported Sites (with optimized handlers)
- IHG Hotels (ihg.com)
- Frontier Airlines (flyfrontier.com)
- Accor Hotels (all.accor.com)
- Virgin Media O2 (virginmediao2.co.uk)
- Sky (sky.com)
- Any other site with standard login forms

### 🔒 Security Features
- SSL/TLS support
- CSRF token detection and handling
- Rate limiting protection
- Proxy rotation
- User-Agent rotation

## Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/legendhkek/Legend.git
cd Legend

# Install dependencies
pip install -r requirements.txt

# For Selenium support (Chrome browser automation)
pip install selenium webdriver-manager

# Optional: For local audio CAPTCHA solving
# pip install SpeechRecognition pydub ffmpeg-python
```

### Dependencies
- `requests` - HTTP library
- `beautifulsoup4` - HTML parsing
- `PySocks` - SOCKS proxy support
- `selenium` - Browser automation for complex sites
- `tkinter` - GUI (usually included with Python)

## Usage

### GUI Mode (Recommended)

Simply run the script without arguments:

```bash
python3 advancedchecker.py
```

The GUI provides:
1. **Site Analysis** - Detect login pages and authentication methods
2. **Account Checking** - Test credentials from files
3. **Proxy Management** - Load and manage multiple proxy types
4. **CAPTCHA Configuration** - Set up 2captcha or other solving services
5. **Real-time Logging** - Monitor progress and results

### CLI Mode (Headless)

#### Check Sites for Login Detection

```bash
# Check specific sites
python3 advancedchecker.py --check-sites ihg.com flyfrontier.com sky.com

# Check default sites
python3 advancedchecker.py --check-sites
```

#### Check Credentials

```bash
# Basic usage
python3 advancedchecker.py --check-creds accounts.txt --site https://example.com

# With advanced options
python3 advancedchecker.py --check-creds accounts.txt \
    --site https://example.com \
    --threads 20 \
    --timeout 30 \
    --delay-min 1.0 \
    --delay-max 3.0 \
    --proxies \
    --proxy-file proxies.txt
```

### Testing Tools

#### Test Proxy Formats

```bash
# Test proxy parsing
python3 test_proxies.py

# Test specific proxy connectivity
python3 test_proxies.py "p1.arealproxy.com:9000:user:pass"
```

#### Test Site Detection

```bash
# Test all required sites
python3 test_sites.py

# Test specific site
python3 test_sites.py "https://www.ihg.com"
```

## File Formats

### Account File Format

Supported formats:
```
# Format 1: site:email:password
https://example.com:user@example.com:password123

# Format 2: email:password (uses default site)
user@example.com:password123

# Comments and blank lines are ignored
# This is a comment
```

### Proxy File Format

Supported formats:
```
# Format 1: host:port (no authentication)
1.2.3.4:8080

# Format 2: host:port:username:password
1.2.3.4:8080:user:pass

# Format 3: username:password@host:port
user:pass@1.2.3.4:8080

# Format 4: With protocol
http://1.2.3.4:8080
socks5://1.2.3.4:1080

# Format 5: Complex credentials (residential proxies)
p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e
```

## Configuration

### CAPTCHA Solving

The tool supports multiple CAPTCHA solving methods:

#### 1. API-Based Solving (Recommended)
Configure in the GUI or programmatically:

```python
from advancedchecker import UniversalAccountChecker

checker = UniversalAccountChecker()

# Configure 2captcha
checker.configure_captcha_solver([
    ('2captcha', 'your-api-key-here')
])
```

Supported providers:
- 2captcha.com
- clearcaptcha.com

#### 2. Local Audio Solving (Experimental)
Requires additional dependencies:
```bash
pip install SpeechRecognition pydub ffmpeg-python
```

#### 3. Selenium Manual Solving
For development/testing, the tool can wait for manual CAPTCHA solving.

### Proxy Configuration

#### Single Proxy Type
```bash
python3 advancedchecker.py --check-creds accounts.txt \
    --site https://example.com \
    --proxies \
    --proxy-file http_proxies.txt
```

#### Multiple Proxy Types
Use the GUI to configure:
- HTTP proxies
- HTTPS proxies
- SOCKS4 proxies
- SOCKS5 proxies
- Residential proxies
- Datacenter proxies

## Examples

### Example 1: Basic Account Checking

```bash
# Create an accounts file
echo "user1@example.com:password123" > accounts.txt
echo "user2@example.com:password456" >> accounts.txt

# Check accounts
python3 advancedchecker.py --check-creds accounts.txt --site https://example.com
```

### Example 2: With Proxies

```bash
# Create a proxy file
echo "p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e" > proxies.txt

# Check with proxies
python3 advancedchecker.py --check-creds accounts.txt \
    --site https://example.com \
    --proxies \
    --proxy-file proxies.txt
```

### Example 3: Site Analysis

```python
from advancedchecker import UniversalAccountChecker

checker = UniversalAccountChecker()

# Analyze a site
config = checker.analyze_site('https://www.ihg.com')

print(f"Login URL: {config.login_url}")
print(f"Auth Method: {config.auth_method.value}")
print(f"CAPTCHA Present: {config.captcha_present}")
```

### Example 4: Using Selenium for Complex Sites

```python
from selenium_login_helper import SeleniumLoginHelper

helper = SeleniumLoginHelper(headless=True)
success, message = helper.login(
    url='https://example.com/login',
    email='user@example.com',
    password='password123'
)

print(f"Login {'successful' if success else 'failed'}: {message}")
```

## Advanced Features

### Custom Site Handlers

You can add custom handlers for specific sites:

```python
from advancedchecker import UniversalSiteAnalyzer, LoginConfig, AuthMethod

analyzer = UniversalSiteAnalyzer()

# Add custom site configuration
analyzer.site_specific_configs['mysite.com'] = {
    'login_paths': ['/auth/login', '/signin'],
    'username_fields': ['email', 'username'],
    'password_fields': ['password', 'pass'],
    'api_endpoints': ['/api/auth'],
    'working_url': 'https://mysite.com/login'
}
```

### Rate Limiting

The tool includes built-in rate limiting:
- Configurable delays between requests
- Automatic retry with exponential backoff
- Rate limit detection

### Error Handling

Comprehensive error handling for:
- Network timeouts
- Proxy errors
- CAPTCHA challenges
- 2FA requirements
- Rate limiting
- Invalid credentials

## Troubleshooting

### Common Issues

#### 1. Selenium Not Working
```bash
# Install Chrome driver
pip install webdriver-manager

# Or manually download ChromeDriver from:
# https://chromedriver.chromium.org/
```

#### 2. SOCKS Proxy Errors
```bash
# Install SOCKS support
pip install PySocks
pip install requests[socks]
```

#### 3. GUI Not Available
```bash
# Install tkinter (Ubuntu/Debian)
sudo apt-get install python3-tk

# Install tkinter (Fedora)
sudo dnf install python3-tkinter

# Install tkinter (macOS)
brew install python-tk
```

#### 4. SSL Certificate Errors
The tool disables SSL verification by default for testing. For production:
```python
# Enable SSL verification in code
session.verify = True
```

### Logging

Enable detailed logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Logs are saved to `universal_checker_debug.log`

## Performance Tips

1. **Thread Count**: Start with 10 threads, increase if needed (max 50)
2. **Timeouts**: Use 20-30 seconds for slow sites
3. **Delays**: Use 1-3 seconds to avoid rate limiting
4. **Proxies**: Rotate proxies to distribute load
5. **CAPTCHA**: Use API solving services for best results

## Security Notice

This tool is for educational and authorized testing purposes only. Always:
- Obtain permission before testing
- Respect rate limits
- Follow terms of service
- Secure credentials properly
- Use responsibly

## Support

For issues, questions, or custom development:
- **Telegram**: @legend_bl
- **Email**: sarthakgrid1@gmail.com
- **Instagram**: sar_thak106

## License

This project is provided as-is for educational purposes.

## Credits

**Developer**: Sarthak (@LEGEND_BL)
**Version**: 5.0 Advanced Edition

---

Made with ❤️ by @LEGEND_BL
