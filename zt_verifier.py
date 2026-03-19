#!/usr/bin/env python3
"""
Zero Trust Verifier - Phase 1
Tests if web applications properly implement Zero Trust authentication principles.

Usage:
    python zt_verifier.py --url https://target.com --username user@example.com --password pass
"""

import argparse
import sys
import json
from datetime import datetime
from core.auth_tester import AuthenticationTester
from core.reporter import Reporter


def print_banner():
    """Display the tool banner"""
    banner = """
    ╔══════════════════════════════════════════════╗
    ║     Zero Trust Verifier - Phase 1            ║
    ║     Authentication & Session Testing         ║
    ╚══════════════════════════════════════════════╝
    """
    print(banner)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Zero Trust Verifier - Test authentication implementations',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Target URL to test (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '--username',
        required=True,
        help='Username for authentication'
    )
    
    parser.add_argument(
        '--password',
        required=True,
        help='Password for authentication'
    )
    
    parser.add_argument(
        '--full',
        action='store_true',
        help='Run full test suite (takes longer)'
    )
    
    parser.add_argument(
        '--report',
        help='Output report file (JSON format)',
        default=None
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    return parser.parse_args()


def main():
    """Main execution function"""
    print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    print(f"Target: {args.url}")
    print(f"Username: {args.username}")
    print("=" * 50)
    print()
    
    # Initialize tester
    tester = AuthenticationTester(
        url=args.url,
        username=args.username,
        password=args.password,
        verbose=args.verbose
    )
    
    # Run tests
    results = {
        'target': args.url,
        'timestamp': datetime.now().isoformat(),
        'tests': [],
        'score': 0,
        'total_tests': 0,
        'passed': 0,
        'failed': 0
    }
    
    try:
        # Test 1: Authentication
        print("[+] Testing authentication...")
        auth_result = tester.test_authentication()
        results['tests'].append(auth_result)
        
        if not auth_result['passed']:
            print("[✗] Authentication failed. Cannot continue testing.")
            sys.exit(1)
        
        print("[✓] Authentication successful\n")
        
        # Test 2: Session token lifespan
        print("[+] Testing session token lifespan...")
        token_result = tester.test_token_lifespan()
        results['tests'].append(token_result)
        
        if token_result['passed']:
            print("[✓] PASS: Token properly expires")
        else:
            print(f"[✗] FAIL: {token_result['message']}")
        print(f"    Risk: {token_result['risk']}")
        print()
        
        # Test 3: Authentication bypass
        print("[+] Testing authentication bypass...")
        bypass_result = tester.test_auth_bypass()
        results['tests'].append(bypass_result)
        
        if bypass_result['passed']:
            print("[✓] PASS: Cannot bypass authentication")
        else:
            print(f"[✗] FAIL: {bypass_result['message']}")
        print(f"    Risk: {bypass_result['risk']}")
        print()
        
        # Test 4: Privilege escalation
        print("[+] Testing privilege escalation...")
        priv_result = tester.test_privilege_escalation()
        results['tests'].append(priv_result)
        
        if priv_result['passed']:
            print("[✓] PASS: Proper role enforcement")
        else:
            print(f"[✗] FAIL: {priv_result['message']}")
        print(f"    Risk: {priv_result['risk']}")
        print()
        
        if args.full:
            # Test 5: Multi-session detection
            print("[+] Testing multi-session detection...")
            session_result = tester.test_multi_session()
            results['tests'].append(session_result)
            
            if session_result['passed']:
                print("[✓] PASS: Multi-session detected")
            else:
                print(f"[✗] FAIL: {session_result['message']}")
            print(f"    Risk: {session_result['risk']}")
            print()
        
        # Calculate score
        results['total_tests'] = len(results['tests'])
        results['passed'] = sum(1 for t in results['tests'] if t['passed'])
        results['failed'] = results['total_tests'] - results['passed']
        results['score'] = int((results['passed'] / results['total_tests']) * 10)
        
        # Generate report
        reporter = Reporter(results)
        reporter.print_summary()
        
        # Save report if requested
        if args.report:
            with open(args.report, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Report saved to: {args.report}")
    
    except KeyboardInterrupt:
        print("\n[!] Testing interrupted by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n[✗] Error during testing: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
