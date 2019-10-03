#!/usr/bin/python3
from libs.libquery import MalQuery
import argparse

if __name__ == "__main__":

    print("===[> MalQuery <]===")
    parser = argparse.ArgumentParser()

    parser.add_argument("--provider", help="Specify provider \
            Malshare, Malwr)", required=False, default="all")

    parser.add_argument("--hash", help="Specify hash (MD5, SHA128, SHA256)",
            required=False)

    parser.add_argument("--action", help="(download, lookup, api_info)",
            required=False)

    args = parser.parse_args()
    query = MalQuery(args.provider, args.action, args.action)
