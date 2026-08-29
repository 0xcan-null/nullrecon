#!/usr/bin/env python3
"""
nullrecon - Fast CLI Subdomain Enumerator & DNS Recon Tool
Author: 0xcan
"""

import sys
import time
import argparse
from queue import Queue
from threading import Thread, Lock
import requests
import dns.resolver
from colorama import init, Fore, Style

init(autoreset=True)
print_lock = Lock()

BANNER = f"""{Fore.MAGENTA}
               _ _                            
              | | |                           
  _ __  _   _ | | |_ __ ___  ___ ___  _ __    
 | '_ \| | | || | | '__/ _ \/ __/ _ \| '_ \   
 | | | | |_| || | | | |  __/ (_| (_) | | | |  
 |_| |_|\__,_||_|_|_|  \___|\___\___/|_| |_|  
{Fore.CYAN}  [ Fast Subdomain Enumerator & DNS Recon ]
{Style.RESET_ALL}"""

def get_crtsh_subdomains(domain):
    """crt.sh SSL sertifika şeffaflık loglarından pasif subdomain çeker."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    found = set()
    try:
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'nullrecon/1.0'})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                sub = entry.get('name_value', '').lower()
                for s in sub.split('\n'):
                    if domain in s and not s.startswith('*.'):
                        found.add(s.strip())
    except Exception:
        pass
    return found

def resolve_worker(domain, q, results):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    while not q.empty():
        sub = q.get()
        full_domain = f"{sub}.{domain}" if not sub.endswith(domain) else sub

        try:
            answers = resolver.resolve(full_domain, 'A')
            ips = [rdata.to_text() for rdata in answers]
            with print_lock:
                print(f"[{Fore.GREEN}FOUND{Style.RESET_ALL}] {full_domain.ljust(35)} -> {Fore.YELLOW}{', '.join(ips)}{Style.RESET_ALL}")
                results.append((full_domain, ips))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            pass
        finally:
            q.task_done()

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="nullrecon - Fast CLI Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for active bruteforce")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads (Default: 30)")
    parser.add_argument("--passive-only", action="store_true", help="Only perform passive OSINT (crt.sh)")

    args = parser.parse_args()
    domain = args.domain.lower().strip()

    print(f"{Fore.GREEN}[*] Target Domain: {Style.RESET_ALL}{domain}")
    print(f"{Fore.GREEN}[*] Threads:       {Style.RESET_ALL}{args.threads}")
    print(f"{Fore.CYAN}[*] Fetching passive OSINT data from crt.sh...{Style.RESET_ALL}")

    passive_subs = get_crtsh_subdomains(domain)
    print(f"{Fore.GREEN}[+] Found {len(passive_subs)} unique subdomains from Certificate Transparency logs.{Style.RESET_ALL}\n")

    targets_to_scan = set(passive_subs)

    if not args.passive_only and args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    word = line.strip()
                    if word:
                        targets_to_scan.add(word)
        except FileNotFoundError:
            print(f"{Fore.RED}[!] Wordlist file not found: {args.wordlist}{Style.RESET_ALL}")
            sys.exit(1)

    q = Queue()
    for item in targets_to_scan:
        q.put(item)

    print(f"{Fore.YELLOW}{'-' * 65}{Style.RESET_ALL}")
    start_time = time.time()
    results = []

    for _ in range(min(args.threads, len(targets_to_scan) if len(targets_to_scan) > 0 else 1)):
        t = Thread(target=resolve_worker, args=(domain, q, results))
        t.daemon = True
        t.start()

    try:
        while not q.empty():
            time.sleep(0.5)
        q.join()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Aborted by user.{Style.RESET_ALL}")
        sys.exit(0)

    elapsed = round(time.time() - start_time, 2)
    print(f"{Fore.YELLOW}{'-' * 65}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan completed in {elapsed}s | Resolved Live Hosts: {len(results)}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
                  
