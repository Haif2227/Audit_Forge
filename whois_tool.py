#!/usr/bin/env python3
import whois
import argparse

def perform_whois_lookup(query):
    try:
        w = whois.whois(query)
        print(w)
    except Exception as e:
        print(f"Error performing WHOIS lookup: {e}")

def main():
    parser = argparse.ArgumentParser(description="WHOIS Lookup Tool")
    parser.add_argument("query", help="Domain or IP address to perform WHOIS lookup on")
    args = parser.parse_args()

    perform_whois_lookup(args.query)

if __name__ == "__main__":
    main()
