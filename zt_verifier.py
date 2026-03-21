#!/usr/bin/env python3
import argparse
import sys
import json
from core.auth_tester import AuthenticationTester
from core.reporter import generate_report

def main():
    parser = argparse.ArgumentParser(description='Zero Trust Verifier')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--username', required=True, help='Username')
    parser.add_argument('--password', required=True, help='Password')
    parser.add_argument('--full', action='store_true', help='Run full test suite')
    parser.add_argument('--report', help='Save report to JSON file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Zero Trust Verifier - Authentication Testing")
    print("=" * 60)
    print(f"\nTarget: {args.url}")
    print(f"Username: {args.username}")
    print("-" * 60)
    
    tester = AuthenticationTester(
        base_url=args.url,
        username=args.username,
        password=args.password,
        verbose=args.verbose
    )
    
    print("\n[+] Running authentication tests...\n")
    
    results = {}
    
    print("[TEST 1] Session Token Expiration")
    results['token_expiration'] = tester.test_token_expiration()
    print()
    
    print("[TEST 2] Rate Limiting")
    results['rate_limiting'] = tester.test_rate_limiting()
    print()
    
    print("[TEST 3] Token Invalidation After Logout")
    results['token_invalidation'] = tester.test_token_invalidation()
    print()
    
    if args.full:
        print("[TEST 4] Re-authentication Requirements")
        results['reauth_required'] = tester.test_reauth_requirements()
        print()
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    
    report = generate_report(results)
    print(report)
    
    if args.report:
        with open(args.report, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Report saved to: {args.report}")
    
    print("\n" + "=" * 60)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        sys.exit(1)
