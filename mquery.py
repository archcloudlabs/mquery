#!/usr/bin/python3
'''
MQuery CLI Utility
'''
from providers.libquery import MalQuery
import sys
import argparse

if __name__ == "__main__":

    print("[================[ >MQuery< ]==================]\n")
    parser = argparse.ArgumentParser()

    parser.add_argument("--provider", help="Specify provider (malshare, hba, " \
                        "vt, caesar).", choices=['caesar', 'virustotal', 'malshare', 'hba'],
                        required=False, default="all")

    parser.add_argument("--hash", help="Specify hash (MD5, SHA128, SHA256).",
                        required=False)

    parser.add_argument("--action", choices=['download', 'search', 'list', 'info', 'daily-download'],
                        help="specify request type.", required=True)

    args = parser.parse_args()

    if (args.action == "search" or args.action == "download") and args.hash is None:
        print("\t[!] Hash not specified!\n")
        sys.exit(1)

    query = MalQuery(args.provider.lower(), args.action, args.hash)
