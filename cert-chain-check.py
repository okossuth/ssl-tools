#!/usr/bin/python3 

# (c) Oskar Kossuth 2022.
# This script verifies an SSL certificate chain to see if its valid. 
# It can process separated ssl certs or all of them into one file.

import OpenSSL
import os
import argparse
from OpenSSL import crypto


def verify_cert_chain(main_cert, store, *argv):
    try:
        # Create a certificate context using the store and the main certificate
        store_ctx = crypto.X509StoreContext(store, main_cert)

        # Verify the certificate, returns None if it can validate the certificate
        result=store_ctx.verify_certificate()
     

        print("                 ")
        print("Certificate chain verified successfully!")
        print("                 ")
        print("The Certificate chain structure should be: \n")
        print("-------------------------")

        if len(argv) == 4:
           
            print("Main Cert: %s" % argv[0])
            print("Intermediate1 Cert: %s" % argv[1])
            print("Intermediate2 Cert: %s" % argv[2])
            print("RootCA Cert: %s" % argv[3])
        else:

            print("Main Cert: %s" % argv[0])
            print("Intermediate1 Cert: %s" % argv[1])
            print("RootCA Cert: %s" % argv[2])


        print("-------------------------")

        return True

    except Exception as e:
        print(e)
        print("Certificate chain provided failed verification!")
        print("Eiher intermediates certs are missing or order is incorrect")
        return False

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Process certificate chain order for some SSL certs.')
    parser.add_argument('-mcert','--mcert', help='Main network cert', required=False)
    parser.add_argument('-interm1','--interm1', help='Intermediate 1 cert', required=False)
    parser.add_argument('-interm2','--interm2', help='Intermediate 2 cert - Optional', required=False)
    parser.add_argument('-rootca','--rootca', help='RootCA cert', required=False)
    parser.add_argument('-fullchain','--fullchain', help='Full certificate chain', required=False)
    args = vars(parser.parse_args())
    
    if args['fullchain'] and args['mcert']:
        print("Main certificate and full certificate chain cannot be given at the same time. Exiting...")
        exit(1)

    if args['fullchain'] and not args['mcert']:
        with open(args['fullchain'], "rb") as f:
            bytes_read = f.read()

        start_line = b'-----BEGIN CERTIFICATE-----'
        result = []
        cert_slots = bytes_read.split(start_line)
        store = crypto.X509Store()
        for single_pem_cert in cert_slots[1:]:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, start_line+single_pem_cert)
            store.add_cert(cert)
            store_ctx = crypto.X509StoreContext(store, cert)
            try:
                result=store_ctx.verify_certificate()
                print("\n")
                print("Certificate chain verified successfully!")
                print("                 ")
                print("The Certificate chain structure should be: \n")
                print("------------------------------------------\n")
                if len(cert_slots[1:]) == 4:
                    print("Main Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[4].decode())
                    print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[3].decode())
                    print("Intermediate2 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[2].decode())
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s" % cert_slots[1].decode())
                else:

                    print("Main Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[3].decode())
                    print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[2].decode())
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s\n" % cert_slots[1].decode())


                print("-------------------------")

                exit(0)
            except Exception as e:
                print(e)
                print("Certificate chain provided failed verification!")
                print("Eiher intermediates certs are missing or order is incorrect in %s " % args['fullchain'])
                exit(1)
        
    if not args['mcert']:       
        print("Neither main certificate nor full certificate chain given. Exiting...")
        exit(1)

    if not args['rootca']:       
        print("RootCA certificate not given. Exiting...")
        exit(1)

    if not args['interm1']:       
        print("Intermediate1 certificate not given. Exiting...")
        exit(1)

    if args['rootca'] == args['interm2'] or args['rootca'] == args['interm1'] or args['interm2'] == args['interm1']:
        print("Certificates can be passed as arguments for one paramater only at a time, they can't be duplicated!")
        exit(1)
        
    f = open(args['mcert'])
    main_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
    print(main_cert.get_issuer())
        
    store = crypto.X509Store()

    if args['rootca']:
        f = open(args['rootca'])
        rootca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        issuer = rootca_cert.get_issuer()
        print(issuer)
        #print(rootca_cert)
        store.add_cert(rootca_cert)
        store_ctx = crypto.X509StoreContext(store, rootca_cert)
        try:
            store_ctx.verify_certificate()
            print("Verify Root CA Cert - OK")
            #store.add_cert(interm2_cert)
        except OpenSSL.crypto.X509StoreContextError:
            print("Verify Root CA Cert - Failed!")
            print("Probably the certificate %s passed as Root CA is not a rootCA cert or its expired!" % args['rootca'])
            exit(1)

    if args['interm2']:
        f = open(args['interm2'])
        interm2_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        #print(interm2_cert)
        store_ctx = crypto.X509StoreContext(store, interm2_cert)
        try:
            store_ctx.verify_certificate()
            print("Verify Interm2 Cert - OK")
            store.add_cert(interm2_cert)
        except OpenSSL.crypto.X509StoreContextError:
            print("Verify Interm2 Cert - Failed!")
            print("Probably the order of intermediates is wrong. Use %s as argument for --interm1 instead and %s as argument for --interm2" % (args['interm2'], args['interm1']))
            exit(1)

    if args['interm1']:
        f = open(args['interm1'])
        interm1_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
        #print(interm1_cert)
        store_ctx = crypto.X509StoreContext(store, interm1_cert)
        try:
            store_ctx.verify_certificate()
            print("Verify Interm1 Cert - OK")
            store.add_cert(interm1_cert)
        except OpenSSL.crypto.X509StoreContextError:
            print("Verify Interm1 Cert - Failed!")
            print("The --interm1 certificate %s is expired or wrong!" % args['interm1'])
            exit(1)

    if args['interm2']:
        verify_cert_chain(main_cert, store, args['mcert'], args['interm1'], args['interm2'], args['rootca'])
    else:
        verify_cert_chain(main_cert, store, args['mcert'], args['interm1'], args['rootca'])
