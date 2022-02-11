#!/usr/bin/python3

# (c) 2022 Oskar Kossuth
# This script will receive a one liner SSL cert and will output to console a multiline SSL cert, each line
# 64 characters long.


import os
import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Convert certificate one liner into a multiline SSL cert.')
    parser.add_argument('-cert','--cert', help='SSL certificate', required=True)
    args = vars(parser.parse_args())

if args['cert']:
    with open(args['cert'], "r") as f:
        cert = f.read()
        print("-----BEGIN CERTIFICATE-----")
        for i in range(0,len(cert),64):
            if i == 1984:
                data = cert[i:i+52]
            else:
                data = cert[i:i+64]
            print(data)
        print("-----END CERTIFICATE-----")
    exit(0)    

