#!/usr/bin/env python3

from __future__ import print_function
import builtins
import concurrent.futures
import os
import argparse
from urllib.parse import urlparse

from core.colors import bad, info
from core.config import (
    blindPayload, globalVariables, payloads, threadCount, delay, timeout
)
from core.encoders import base64
from core.log import setup_logger, console_log_level, file_log_level, log_file, log_config
from core.photon import photon
from core.prompt import prompt
from core.updater import updater
from core.utils import extractHeaders, reader, converter
from modes.bruteforcer import bruteforcer
from modes.crawl import crawl
from modes.scan import scan
from modes.singleFuzz import singleFuzz
from plugins import webug

import core.config

import pyfiglet
from termcolor import colored

def print_logo():
    ascii_art = pyfiglet.figlet_format("XSSpider", font="poison")
    colored_ascii = colored(ascii_art, 'magenta')
    print(colored_ascii)

VERSION = "0.1"
HEADER = '----------------------\nXSSpider v{} // webug\n----------------------\n\n:wake'.format(VERSION)

def install_fuzzywuzzy():
    print(f'{info} fuzzywuzzy isn\'t installed, installing now.')
    ret_code = os.system('pip3 install fuzzywuzzy')
    if ret_code != 0:
        print(f'{bad} fuzzywuzzy installation failed.')
        webug.quitline()
    print(f'{info} fuzzywuzzy has been installed, restart XSSpider.')
    webug.quitline()

def check_python_version():
    try:
        import fuzzywuzzy
    except ImportError:
        install_fuzzywuzzy()
    except ImportError:
        print(f'{bad} XSSpider isn\'t compatible with python2.\n Use python > 3.4 to run XSSpider.')
        webug.quitline()

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='url', dest='target')
    parser.add_argument('--data', help='post data', dest='paramData')
    parser.add_argument('-e', '--encode', help='encode payloads', dest='encode')
    parser.add_argument('--fuzzer', help='fuzzer', dest='fuzz', action='store_true')
    parser.add_argument('--update', help='update', dest='update', action='store_true')
    parser.add_argument('--timeout', help='timeout', dest='timeout', type=int, default=timeout)
    parser.add_argument('--proxy', help='use prox(y|ies)', dest='proxy', action='store_true')
    parser.add_argument('--crawl', help='crawl', dest='recursive', action='store_true')
    parser.add_argument('--json', help='treat post data as json', dest='jsonData', action='store_true')
    parser.add_argument('--path', help='inject payloads in the path', dest='path', action='store_true')
    parser.add_argument('--seeds', help='load crawling seeds from a file', dest='args_seeds')
    parser.add_argument('-f', '--file', help='load payloads from a file', dest='args_file')
    parser.add_argument('-l', '--level', help='level of crawling', dest='level', type=int, default=2)
    parser.add_argument('--headers', help='add headers', dest='add_headers', nargs='?', const=True)
    parser.add_argument('-t', '--threads', help='number of threads', dest='threadCount', type=int, default=threadCount)
    parser.add_argument('-d', '--delay', help='delay between requests', dest='delay', type=int, default=delay)
    parser.add_argument('--skip', help='don\'t ask to continue', dest='skip', action='store_true')
    parser.add_argument('--skip-dom', help='skip dom checking', dest='skipDOM', action='store_true')
    parser.add_argument('--blind', help='inject blind XSS payload while crawling', dest='blindXSS', action='store_true')
    parser.add_argument('--console-log-level', help='Console logging level', dest='console_log_level', default=console_log_level, choices=log_config.keys())
    parser.add_argument('--file-log-level', help='File logging level', dest='file_log_level', choices=log_config.keys(), default=None)
    parser.add_argument('--log-file', help='Name of the file to log', dest='log_file', default=log_file)
    return parser.parse_args()

def setup_headers(args):
    if isinstance(args.add_headers, bool):
        return extractHeaders(prompt())
    elif isinstance(args.add_headers, str):
        return extractHeaders(args.add_headers)
    else:
        from core.config import headers
        return headers

def main():
    print_logo()
    print(HEADER)
    setattr(builtins, 'quitline', webug.quitline)
    check_python_version()

    args = parse_arguments()

    core.log.file_log_level = args.file_log_level
    
    logger = setup_logger()

    globalVariables.update(vars(args))
    headers = setup_headers(args)

    if args.path:
        args.paramData = converter(args.target, args.target)
    elif args.jsonData:
        headers['Content-type'] = 'application/json'
        args.paramData = converter(args.paramData)

    if args.args_file:
        payloadList = payloads if args.args_file == 'default' else list(filter(None, reader(args.args_file)))
    else:
        payloadList = []

    seedList = list(filter(None, reader(args.args_seeds))) if args.args_seeds else []

    encoding = base64 if args.encode and args.encode == 'base64' else False

    if not args.proxy:
        webug.crawl_and_identify_xss('https://' + args.target)
        core.config.proxies = {}

    if args.update:
        updater()
        webug.quitline()

    if not args.target and not args.args_seeds:
        print('\n<< Spider need a target to crawl. >>')
        webug.quitline()

    if args.fuzz:
        singleFuzz(args.target, args.paramData, encoding, headers, args.delay, args.timeout)
    elif not args.recursive and not args.args_seeds:
        if args.args_file:
            bruteforcer(args.target, args.paramData, payloadList, encoding, headers, args.delay, args.timeout)
       # else:
            # scan(args.target, args.paramData, encoding, headers, args.delay, args.timeout, args.skipDOM, args.skip)
    else:
        if args.target:
            seedList.append(args.target)
        for target in seedList:
            logger.run('Crawling the target')
            scheme = urlparse(target).scheme
            logger.debug('Target scheme: {}'.format(scheme))
            host = urlparse(target).netloc
            main_url = scheme + '://' + host
            crawlingResult = photon(target, headers, args.level, args.threadCount, args.delay, args.timeout, args.skipDOM)
            forms, domURLs = crawlingResult[0], list(crawlingResult[1])
            difference = abs(len(domURLs) - len(forms))
            forms.extend([0] * difference) if len(domURLs) > len(forms) else domURLs.extend([0] * difference)
            threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=args.threadCount)
            futures = (threadpool.submit(crawl, scheme, host, main_url, form, args.blindXSS, blindPayload, headers, args.delay, args.timeout, encoding) for form, domURL in zip(forms, domURLs))
            for i, _ in enumerate(concurrent.futures.as_completed(futures)):
                if i + 1 == len(forms) or (i + 1) % args.threadCount == 0:
                    logger.info('Progress: %i/%i\r' % (i + 1, len(forms)))
            logger.no_format('')

if __name__ == "__main__":
    main()