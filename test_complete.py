#!/usr/bin/env python3
"""
Complete test suite for Universal Account Checker
Validates all components and functionality
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported"""
    print("="*80)
    print("TESTING MODULE IMPORTS")
    print("="*80)
    
    # Required modules (must pass)
    required_tests = {
        'Core Module': ('advancedchecker', ['UniversalAccountChecker', 'AdvancedProxyManager', 'UniversalSiteAnalyzer']),
    }
    
    # Optional modules (can fail without affecting test result)
    optional_tests = {
        'Selenium Helper': ('selenium_login_helper', ['SeleniumLoginHelper']),
        'CAPTCHA Solver': ('selenium_captcha_solver', ['LocalCaptchaSolver']),
    }
    
    results = []
    
    # Test required modules
    for name, (module_name, classes) in required_tests.items():
        try:
            module = __import__(module_name)
            for cls in classes:
                if not hasattr(module, cls):
                    print(f"✗ {name}: Class {cls} not found")
                    results.append(False)
                else:
                    print(f"✓ {name}: {cls} imported successfully")
                    results.append(True)
        except Exception as e:
            print(f"✗ {name}: Import failed - {e}")
            results.append(False)
    
    # Test optional modules (don't affect results)
    print("\nOptional modules (Selenium-based):")
    for name, (module_name, classes) in optional_tests.items():
        try:
            module = __import__(module_name)
            for cls in classes:
                if not hasattr(module, cls):
                    print(f"⚠ {name}: Class {cls} not found (optional)")
                else:
                    print(f"✓ {name}: {cls} imported successfully")
        except Exception as e:
            print(f"⚠ {name}: Not available - {e} (optional)")
    
    return all(results)


def test_proxy_formats():
    """Test proxy format validation and parsing"""
    print("\n" + "="*80)
    print("TESTING PROXY FORMAT PARSING")
    print("="*80)
    
    from advancedchecker import AdvancedProxyManager, ProxyType
    
    manager = AdvancedProxyManager()
    
    test_cases = [
        ("1.2.3.4:8080", True),
        ("1.2.3.4:8080:user:pass", True),
        ("user:pass@1.2.3.4:8080", True),
        ("http://1.2.3.4:8080", True),
        ("socks5://1.2.3.4:1080", True),
        ("p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e", True),
        ("invalid", False),
        ("1.2.3.4", False),
    ]
    
    results = []
    for proxy, expected_valid in test_cases:
        is_valid = manager.validate_proxy_format(proxy)
        passed = is_valid == expected_valid
        
        if passed:
            print(f"✓ '{proxy[:50]}...' - Valid: {is_valid}")
            results.append(True)
        else:
            print(f"✗ '{proxy[:50]}...' - Expected {expected_valid}, got {is_valid}")
            results.append(False)
    
    # Test formatting
    print("\nTesting proxy formatting:")
    test_proxy = "p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e"
    formatted = manager.format_proxy_url(test_proxy, ProxyType.HTTP)
    expected_format = "http://zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e@p1.arealproxy.com:9000"
    
    if formatted == expected_format:
        print(f"✓ Complex proxy formatted correctly")
        results.append(True)
    else:
        print(f"✗ Formatting failed")
        print(f"  Expected: {expected_format}")
        print(f"  Got: {formatted}")
        results.append(False)
    
    return all(results)


def test_site_configs():
    """Test site-specific configurations"""
    print("\n" + "="*80)
    print("TESTING SITE CONFIGURATIONS")
    print("="*80)
    
    from advancedchecker import UniversalSiteAnalyzer
    
    analyzer = UniversalSiteAnalyzer()
    
    required_sites = [
        'ihg.com',
        'flyfrontier.com',
        'accor.com',
        'virginmediao2.co.uk',
        'sky.com'
    ]
    
    results = []
    for site in required_sites:
        if site in analyzer.site_specific_configs:
            config = analyzer.site_specific_configs[site]
            has_login_paths = 'login_paths' in config
            has_working_url = 'working_url' in config
            
            if has_login_paths and has_working_url:
                print(f"✓ {site}: Configuration complete")
                results.append(True)
            else:
                print(f"⚠ {site}: Configuration incomplete")
                results.append(False)
        else:
            print(f"✗ {site}: No configuration found")
            results.append(False)
    
    return all(results)


def test_captcha_detection():
    """Test CAPTCHA detection"""
    print("\n" + "="*80)
    print("TESTING CAPTCHA DETECTION")
    print("="*80)
    
    try:
        from selenium_captcha_solver import LocalCaptchaSolver
        solver = LocalCaptchaSolver()
    except ImportError as e:
        print(f"⚠ CAPTCHA solver not available (optional): {e}")
        print("  Install Selenium to enable: pip install selenium")
        return True  # Don't fail test for optional feature
    
    test_cases = [
        ('<script src="https://hcaptcha.com/1/api.js"></script>', 'hcaptcha'),
        ('<script src="https://www.google.com/recaptcha/api.js"></script>', 'recaptcha_v2'),
        ('<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>', 'turnstile'),
        ('<div class="g-recaptcha"></div>', 'recaptcha_v2'),
        ('<div>No CAPTCHA here</div>', None),
    ]
    
    results = []
    for html, expected_type in test_cases:
        detected = solver.detect_captcha_type(html)
        passed = detected == expected_type
        
        if passed:
            print(f"✓ Detected: {detected or 'None'}")
            results.append(True)
        else:
            print(f"✗ Expected {expected_type}, got {detected}")
            results.append(False)
    
    return all(results)


def test_file_structure():
    """Test that all required files exist"""
    print("\n" + "="*80)
    print("TESTING FILE STRUCTURE")
    print("="*80)
    
    required_files = [
        'advancedchecker.py',
        'selenium_login_helper.py',
        'selenium_captcha_solver.py',
        'test_proxies.py',
        'test_sites.py',
        'requirements.txt',
        'README.md',
        'QUICKSTART.md',
        'SECURITY.md',
        '.gitignore',
        'example_accounts.txt',
        'example_proxies.txt',
    ]
    
    results = []
    for filename in required_files:
        filepath = Path(filename)
        if filepath.exists():
            print(f"✓ {filename}")
            results.append(True)
        else:
            print(f"✗ {filename} - Not found")
            results.append(False)
    
    return all(results)


def test_dependencies():
    """Test that required dependencies are available"""
    print("\n" + "="*80)
    print("TESTING DEPENDENCIES")
    print("="*80)
    
    dependencies = [
        ('requests', 'HTTP library'),
        ('bs4', 'BeautifulSoup (HTML parsing)'),
        ('urllib3', 'HTTP client'),
        ('socks', 'SOCKS proxy support'),
    ]
    
    results = []
    for module, description in dependencies:
        try:
            __import__(module)
            print(f"✓ {description} ({module})")
            results.append(True)
        except ImportError:
            print(f"✗ {description} ({module}) - Not installed")
            results.append(False)
    
    # Optional dependencies
    print("\nOptional dependencies:")
    optional = [
        ('selenium', 'Selenium (browser automation)'),
        ('tkinter', 'GUI support'),
    ]
    
    for module, description in optional:
        try:
            __import__(module)
            print(f"✓ {description} ({module})")
        except ImportError:
            print(f"⚠ {description} ({module}) - Not installed (optional)")
    
    return all(results)


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("UNIVERSAL ACCOUNT CHECKER - COMPLETE TEST SUITE")
    print("="*80)
    print()
    
    tests = [
        ("Dependencies", test_dependencies),
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("Proxy Formats", test_proxy_formats),
        ("Site Configurations", test_site_configs),
        ("CAPTCHA Detection", test_captcha_detection),
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            result = test_func()
            results[name] = result
        except Exception as e:
            print(f"\n✗ {name} test failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Final summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    total = len(results)
    passed = sum(1 for r in results.values() if r)
    failed = total - passed
    
    for name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status} - {name}")
    
    print("\n" + "-"*80)
    print(f"Total: {total} | Passed: {passed} | Failed: {failed}")
    print("-"*80)
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("\nThe Universal Account Checker is ready to use!")
        print("\nQuick start:")
        print("  1. Review QUICKSTART.md for usage instructions")
        print("  2. Run: python3 advancedchecker.py (GUI mode)")
        print("  3. Or: python3 advancedchecker.py --check-sites (CLI mode)")
        return 0
    else:
        print(f"\n⚠ {failed} test(s) failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
