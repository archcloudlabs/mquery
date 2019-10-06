#!/usr/bin/python3
from libs.libquery import MalQuery
import argparse

if __name__ == "__main__":
    print("[================[>MQuery<==================]")
    parser = argparse.ArgumentParser()

    parser.add_argument("--provider", help="Specify provider \
            malshare, hba)", required=False, default="all")

    parser.add_argument("--hash", help="Specify hash (MD5, SHA128, SHA256)",
            required=False)

    parser.add_argument("--action", choices=['download','search','list','info'], 
            help="(download, lookup, list, info)", required=True)

    args = parser.parse_args()
    query = MalQuery(args.provider, args.action, args.hash)
