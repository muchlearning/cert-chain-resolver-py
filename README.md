# SSL certificate chain resolver

SSL certificates are usually signed by an intermediate certificate rather than
a trusted CA certificate.  The path from a server's certificate to a trusted CA
certificate is called the certificate chain.  This program downloads the
certificate chain for a given server certificate.

## Requirements

* Python (only tested with Python 2.x)
* pyOpenSSL (version 0.15 or later if you want to verify the fetched
  certificates against a store of trusted CA certificates)

## Similar projects

* [zakjan/cert-chain-resolver](https://github.com/zakjan/cert-chain-resolver) (Go)
* [freekmurze/ssl-certificate-chain-resolver](https://github.com/freekmurze/ssl-certificate-chain-resolver) (PHP)
* [SSLMate/mkcertchan](https://github.com/SSLMate/mkcertchain) (Perl)
