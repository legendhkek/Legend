#!/usr/bin/env python3
"""
Test script to verify site login detection for all requested sites
"""

import sys
import time
from advancedchecker import UniversalAccountChecker, UniversalSiteAnalyzer

# Sites requested in the problem statement
REQUIRED_SITES = [
    'https://www.ihg.com',
    'https://www.flyfrontier.com', 
    'https://all.accor.com',
    'https://www.virginmediao2.co.uk',
    'https://www.sky.com'
]

def test_site_detection():
    """Test login detection for all required sites"""
    print("="*80)
    print("SITE LOGIN DETECTION TEST")
    print("="*80)
    print(f"\nTesting {len(REQUIRED_SITES)} required sites...\n")
    
    checker = UniversalAccountChecker()
    results = []
    
    for i, site in enumerate(REQUIRED_SITES, 1):
        print(f"\n[{i}/{len(REQUIRED_SITES)}] Testing: {site}")
        print("-" * 80)
        
        try:
            start_time = time.time()
            config = checker.analyze_site(site, use_proxies=False)
            elapsed = time.time() - start_time
            
            print(f"✓ Analysis completed in {elapsed:.2f}s")
            print(f"  Login URL: {config.login_url}")
            print(f"  Auth Method: {config.auth_method.value}")
            print(f"  Username Field: {config.username_field}")
            print(f"  Password Field: {config.password_field}")
            
            if config.captcha_present:
                captcha_info = f"Yes ({config.captcha_type or 'unknown'})"
                if config.captcha_site_key:
                    short_key = config.captcha_site_key[:16] + "..." if len(config.captcha_site_key) > 16 else config.captcha_site_key
                    captcha_info += f" | key: {short_key}"
                print(f"  CAPTCHA: {captcha_info}")
            else:
                print(f"  CAPTCHA: No")
            
            if config.csrf_tokens:
                print(f"  CSRF Tokens: {len(config.csrf_tokens)}")
            
            if config.additional_fields:
                print(f"  Additional Fields: {', '.join(config.additional_fields.keys())}")
            
            results.append({
                'site': site,
                'success': True,
                'config': config,
                'time': elapsed
            })
            
        except Exception as e:
            print(f"✗ Error: {e}")
            results.append({
                'site': site,
                'success': False,
                'error': str(e)
            })
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    successful = sum(1 for r in results if r['success'])
    failed = len(results) - successful
    
    print(f"\nTotal Sites: {len(results)}")
    print(f"✓ Successful: {successful}")
    print(f"✗ Failed: {failed}")
    
    if successful > 0:
        print(f"\n✓ Successfully detected login for:")
        for r in results:
            if r['success']:
                print(f"  • {r['site']} ({r['config'].auth_method.value})")
    
    if failed > 0:
        print(f"\n✗ Failed to detect login for:")
        for r in results:
            if not r['success']:
                print(f"  • {r['site']}: {r.get('error', 'Unknown error')}")
    
    print("\n" + "="*80)
    
    return successful == len(results)


def test_single_site(site_url: str):
    """Test a single site in detail"""
    print("="*80)
    print("DETAILED SITE ANALYSIS")
    print("="*80)
    
    if not site_url.startswith(('http://', 'https://')):
        site_url = 'https://' + site_url
    
    print(f"\nAnalyzing: {site_url}\n")
    
    checker = UniversalAccountChecker()
    
    try:
        config = checker.analyze_site(site_url, use_proxies=False)
        
        print("Analysis Results:")
        print("-" * 80)
        print(f"Login URL: {config.login_url}")
        print(f"Auth Method: {config.auth_method.value}")
        print(f"Username Field: {config.username_field}")
        print(f"Password Field: {config.password_field}")
        
        if config.captcha_present:
            print(f"\nCAPTCHA Detected:")
            print(f"  Type: {config.captcha_type or 'unknown'}")
            if config.captcha_site_key:
                print(f"  Site Key: {config.captcha_site_key}")
            if config.captcha_response_field:
                print(f"  Response Field: {config.captcha_response_field}")
        
        if config.csrf_tokens:
            print(f"\nCSRF Tokens Found: {len(config.csrf_tokens)}")
            for name, value in config.csrf_tokens.items():
                short_value = value[:50] + "..." if len(value) > 50 else value
                print(f"  {name}: {short_value}")
        
        if config.additional_fields:
            print(f"\nAdditional Form Fields:")
            for name, value in config.additional_fields.items():
                print(f"  {name}: {value}")
        
        if config.headers:
            print(f"\nRequired Headers:")
            for name, value in config.headers.items():
                if name.lower() not in ['user-agent']:
                    print(f"  {name}: {value}")
        
        print("\n✓ Site analysis completed successfully")
        return True
        
    except Exception as e:
        print(f"\n✗ Error analyzing site: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main test function"""
    print("\nUniversal Account Checker - Site Testing Tool\n")
    
    if len(sys.argv) > 1:
        # Test specific site
        site = sys.argv[1]
        success = test_single_site(site)
    else:
        # Test all required sites
        success = test_site_detection()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
