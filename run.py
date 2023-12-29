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
    parser = argparse.ArgumentParser(description="运行文件或命令检测。")
    parser.add_argument('--file', action='store_true', help="运行文件检测")
    parser.add_argument('--exec', action='store_true', help="运行命令检测")
    parser.add_argument('--net', action='store_true', help="运行网络检测")
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

