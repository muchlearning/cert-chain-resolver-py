#!/usr/bin/python

# The MIT License (MIT)
#
# Copyright (c) 2016 FastTrack Technologies
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import OpenSSL.crypto
import re
import urllib2
import sys

issuer_re = re.compile('^CA Issuers - URI:(.*)$', re.MULTILINE)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""\
SSL certificate chain resolver
""")
    parser.add_argument("-i", "--input", metavar="FILE", required=True, help="read certificate from FILE")
    parser.add_argument("-o", "--output", metavar="FILE", required=True, help="write chain to FILE (NOTE: the output will not contain the given certificate)")
    parser.add_argument("-n", metavar="NUM", required=False, type=int, help="maximum number of certificates to fetch (not including the given certificate)")
    parser.add_argument("-t", "--trusted", metavar="STORE", required=False, help="stop fetching when we find a certificate signed by a trusted CA whose certificate is given in STORE (STORE may contain multiple PEM-format certificates concatenated together)")

    args = parser.parse_args()
    store = None
    if args.trusted:
        if not hasattr(OpenSSL.crypto, "X509StoreContext"):
            sys.stderr.write("Error: pyOpenSSL 0.15 or greater is required for verifying certificates\n")
            exit(1)
        store = OpenSSL.crypto.X509Store()
        with open(args.trusted, 'r') as f:
            line = f.readline()
            while line:
                if line.strip() == "-----BEGIN CERTIFICATE-----":
                    certlines = [line]
                    line = f.readline()
                    while line:
                        certlines.append(line)
                        if line.strip() == "-----END CERTIFICATE-----":
                            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ''.join(certlines))
                            store.add_cert(cert)
                            break
                        line = f.readline()
                if not line:
                    break
                line = f.readline()

    with open(args.output, 'w') as outfile:
        with open(args.input, 'r') as infile:
            cert_text = infile.read()
        first = True
        found = True
        n = 0
        while found:
            try:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_text)
            except:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_text)
            if n != 0:
                outfile.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            sys.stderr.write("%d: %s\n" % (n, cert.get_subject().commonName))
            n = n+1
            if store:
                storectx = OpenSSL.crypto.X509StoreContext(store, cert)
                try:
                    storectx.verify_certificate()
                    sys.stderr.write("Certificate is signed by a trusted CA\n")
                    break
                except:
                    pass
            if args.n and args.n < n:
                break
            found = False
            num_extensions = cert.get_extension_count()
            for i in range(0,num_extensions-1):
                extension = cert.get_extension(i)
                if extension.get_short_name() == "authorityInfoAccess":
                    aia = str(extension)
                    m = issuer_re.search(aia)
                    if m:
                        found = True
                        infile = urllib2.urlopen(m.group(1))
                        cert_text = infile.read()
                        infile.close()
    sys.stderr.write("%d certificate(s) found.\n" % (n-1))
