#! /bin/python3

import argparse
import subprocess
import sys

def run_file_detect(file_args):
    subprocess.run(["python3", "./file/filedetect.py"] + file_args)

def run_cmd_detect(exec_args):
    subprocess.run(["python3", "./exec/cmddetect.py"] + exec_args)

def run_net_detect(net_args):
    subprocess.run(["python3", "./net/mygod.py"] + net_args)


def main():
    parser = argparse.ArgumentParser(description="File, network, and process behavior detection")
    parser.add_argument('--file', action='store_true', help="File opening operation detection")
    parser.add_argument('--exec', action='store_true', help="Process behavior operation detection")
    parser.add_argument('--net', action='store_true', help="Network request operation detection")
    args, unknown = parser.parse_known_args()

    if args.file:
        run_file_detect(unknown)
    elif args.exec:
        run_cmd_detect(unknown)
    elif args.net:
        run_net_detect(unknown)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()

