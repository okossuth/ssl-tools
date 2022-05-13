#!/usr/bin/python3 

# (c) Oskar Kossuth 2022.
# This script verifies an SSL certificate chain to see if its valid.
# It can process separated ssl certs or all of them into one file.
    
import OpenSSL
import os
import argparse
import certifi
from OpenSSL import crypto
from cryptography import x509

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
    parser.add_argument('-combo','--combo', help='Intermediate + RootCA certificate chain combo', required=False)
    args = vars(parser.parse_args())

    if args['fullchain'] and args['combo']:
        print("Intermediate certificate combo and full certificate chain cannot be given at the same time. Exiting...")
        exit(1)

    if args['combo'] and not args['mcert']:
        print("Main certificate is not given. Exiting...")
        exit(1)

    if args['combo'] and args['mcert']:
        with open(args['combo'], "rb") as f:
            bytes_read = f.read()

        with open(args['mcert'], "rb") as m:
            mbytes_read = m.read()

        start_line = b'-----BEGIN CERTIFICATE-----'
        main_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, mbytes_read)
        result = []
        cert_slots = bytes_read.split(start_line)
        store = crypto.X509Store()
        for single_pem_cert in cert_slots[1:]:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, start_line+single_pem_cert)
            store.add_cert(cert)
            store_ctx = crypto.X509StoreContext(store, cert)

        try:
            store.add_cert(main_cert)
            store_ctx = crypto.X509StoreContext(store, main_cert)
            result=store_ctx.verify_certificate()
            print("\n")
            print("Certificate chain verified successfully!")
            print("                 ")
            print("The Certificate chain structure should be: \n")
            print("------------------------------------------\n")

            for intcert in cert_slots[1:]:
                ext = x509.load_pem_x509_certificate(start_line+intcert)
                try:
                    b=str(ext.extensions.get_extension_for_class(x509.ExtendedKeyUsage))
                    interm1=intcert
                except Exception as e:
                    try:
                        c=str(ext.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier))
                        if "authority_cert_issuer=None" in c:
                             interm2=intcert
                    except Exception as e:
                        rootca=intcert

            if len(cert_slots[1:]) == 3:
                print("Main Cert:\n%s\n" % mbytes_read.decode())
                print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm1.decode())
                print("Intermediate2 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm2.decode())
                print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s" % rootca.decode())
            else:
                print("Main Cert:\n%s\n" % mbytes_read.decode())
                print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm1.decode())
                if interm2 is None:
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s\n" % rootca.decode())
                else:
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm2.decode())
            print("-------------------------")

            exit(0)
        except Exception as e:
            print(e)
            print("Certificate chain provided failed verification!")
            print("Eiher main/intermediates certs are missing or wrong in %s and %s\n\n" % (args['mcert'], args['combo']))

            exit(1)

    
    if args['fullchain'] and args['mcert']:
        print("Main certificate and full certificate chain cannot be given at the same time. Exiting...")
        exit(1)

    if args['fullchain'] and not args['mcert']:
        with open(args['fullchain'], "rb") as f:
            bytes_read = f.read()

        start_line = b'-----BEGIN CERTIFICATE-----'
        result = []
        main=""
        cert_slots = bytes_read.split(start_line)
        store = crypto.X509Store()

        ext = x509.load_pem_x509_certificate(start_line+cert_slots[1])
        a=str(ext.extensions.get_extension_for_class(x509.BasicConstraints))
        if "ca=False" in a:
            testcert=start_line+cert_slots[-1]
            #print("testcert is at the end")
        else:
            testcert=start_line+cert_slots[1]
            #print(testcert)
            #print("testcert is at the beginning")

        cert = crypto.load_certificate(crypto.FILETYPE_PEM, testcert)
        subject = cert.get_subject()
        issued_to = subject.CN    # the Common Name field
        issuer = cert.get_issuer()
        issued_by = issuer.CN

        if issued_to != issued_by:
            #print("Cert is not a real rootCA!")
            lookup = issued_by
            start = 0
            rootca ="\n"
            endline = "-----END CERTIFICATE-----"
            cert = certifi.where()
            with open(cert) as myFile:
                for num, line in enumerate(myFile, 1):
                    if lookup in line:
                        #print('found at line:', num)
                        break
                myFile.close()

            with open(cert) as myFile:
                lines = [line.rstrip() for line in myFile]
                start = num + 7
                #print(start)
                for i in lines[start:]:
                    i = i+'\n'
                    rootca = rootca+i
                    if endline in i:
                        break
                myFile.close()
                cert_slots.append(str.encode(rootca))
        else:
            print("We've got a real rootCA in the chain")

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

            for intcert in cert_slots[1:]:
                ext = x509.load_pem_x509_certificate(start_line+intcert)
                a=str(ext.extensions.get_extension_for_class(x509.BasicConstraints))
                if "ca=False" in a:
                    main=intcert
                    continue
                try:
                    b=str(ext.extensions.get_extension_for_class(x509.ExtendedKeyUsage))
                    interm1=intcert
                except Exception as e:
                    try:
                        c=str(ext.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier))
                        if "authority_cert_issuer=None" in c:
                             interm2=intcert
                    except Exception as e:
                        rootca=intcert

            if main is "":
                print("ERROR: It seems the main cert is empty or not available. Exiting...")
                exit(1)

            if len(cert_slots[1:]) == 4:
                print("Main Cert:\n-----BEGIN CERTIFICATE----- %s\n" % main.decode())
                print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm1.decode())
                print("Intermediate2 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm2.decode())
                print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s" % rootca.decode())
            else:

                print("Main Cert:\n-----BEGIN CERTIFICATE----- %s\n" % main.decode())
                print("Intermediate1 Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm1.decode())
                if interm2 is None:
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s\n" % rootca.decode())
                else:
                    print("RootCA Cert:\n-----BEGIN CERTIFICATE----- %s\n" % interm2.decode())

            print("-------------------------")

            exit(0)
        except Exception as e:
            print(e)
            print("Certificate chain provided failed verification!")
            print("Eiher main/intermediates certs are missing or wrong in %s\n\n" % args['fullchain'])
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
        store.add_cert(rootca_cert)
        store_ctx = crypto.X509StoreContext(store, rootca_cert)
        try:
            store_ctx.verify_certificate()
            print("Verify Root CA Cert - OK")
        except OpenSSL.crypto.X509StoreContextError:
            print("Verify Root CA Cert - Failed!")
            print("Probably the certificate %s passed as Root CA is not a rootCA cert or its expired!" % args['rootca'])
            exit(1)

    if args['interm2']:
        f = open(args['interm2'])
        interm2_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())
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
