#!/usr/bin/env python3
"""
Test script to validate proxy formats and test connectivity
"""

import sys
import requests
from advancedchecker import AdvancedProxyManager, ProxyType

def test_proxy_parsing():
    """Test proxy format parsing"""
    print("="*80)
    print("PROXY FORMAT PARSING TEST")
    print("="*80)
    
    manager = AdvancedProxyManager()
    
    test_proxies = [
        # Simple formats
        "1.2.3.4:8080",
        "http://1.2.3.4:8080",
        "socks5://1.2.3.4:1080",
        
        # With authentication
        "1.2.3.4:8080:user:pass",
        "user:pass@1.2.3.4:8080",
        "http://user:pass@1.2.3.4:8080",
        
        # Complex format from requirements (residential proxy with dashes and special chars)
        "p1.arealproxy.com:9000:zaym246-type-residential-country-gb:fd86cea5-501a-401e-a1d4-b372c33ced0e",
    ]
    
    for proxy in test_proxies:
        print(f"\nTesting proxy: {proxy}")
        
        # Validate format
        is_valid = manager.validate_proxy_format(proxy)
        print(f"  Valid format: {is_valid}")
        
        if is_valid:
            # Detect type
            proxy_type = manager.detect_proxy_type(proxy)
            print(f"  Detected type: {proxy_type.value}")
            
            # Format URL
            formatted = manager.format_proxy_url(proxy, proxy_type)
            print(f"  Formatted URL: {formatted}")


def test_proxy_connectivity(proxy_string: str):
    """Test actual proxy connectivity"""
    print("\n" + "="*80)
    print("PROXY CONNECTIVITY TEST")
    print("="*80)
    
    manager = AdvancedProxyManager()
    
    # Validate and format proxy
    if not manager.validate_proxy_format(proxy_string):
        print(f"ERROR: Invalid proxy format: {proxy_string}")
        return False
    
    proxy_type = manager.detect_proxy_type(proxy_string)
    formatted_proxy = manager.format_proxy_url(proxy_string, proxy_type)
    
    print(f"\nProxy: {proxy_string}")
    print(f"Type: {proxy_type.value}")
    print(f"Formatted: {formatted_proxy}")
    
    # Create proxy dict for requests
    proxy_dict = {
        'http': formatted_proxy,
        'https': formatted_proxy
    }
    
    # Test URLs
    test_urls = [
        'http://httpbin.org/ip',
        'https://api.ipify.org?format=json',
        'http://ip-api.com/json/'
    ]
    
    print("\nTesting connectivity...")
    for url in test_urls:
        try:
            print(f"\n  Testing {url}...")
            response = requests.get(
                url,
                proxies=proxy_dict,
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                print(f"  ✓ Success (HTTP {response.status_code})")
                print(f"  Response: {response.text[:200]}")
            else:
                print(f"  ✗ Failed (HTTP {response.status_code})")
                
        except requests.exceptions.ProxyError as e:
            print(f"  ✗ Proxy Error: {e}")
        except requests.exceptions.Timeout:
            print(f"  ✗ Timeout")
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    return True


def main():
    """Main test function"""
    print(__file__)
    print("\nProxy Format and Connectivity Tester\n")
    
    # Test parsing
    test_proxy_parsing()
    
    # Test connectivity with provided proxy if available
    if len(sys.argv) > 1:
        test_proxy = sys.argv[1]
        test_proxy_connectivity(test_proxy)
    else:
        print("\n" + "="*80)
        print("To test a specific proxy, run:")
        print(f"  python3 {sys.argv[0]} <proxy>")
        print("\nExample:")
        print(f"  python3 {sys.argv[0]} 'p1.arealproxy.com:9000:user:pass'")
        print("="*80)


if __name__ == "__main__":
    main()
