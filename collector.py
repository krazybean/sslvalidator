import os
import time
import datetime
import requests
import M2Crypto
from OpenSSL import crypto


class SSLValidate:

    def __init__(self):
        """ constructor """
        moz_host = 'http://mxr.mozilla.org'
        moz_path = 'mozilla-central/source/security/nss/lib/ckfw/builtins'
        moz_file = 'certdata.txt?raw=1'
        self.file_path = "/tmp/ca.txt"
        # Invalidate flatfile by minute
        self.file_expire = 120
        self.moz_url = "{0}/{1}/{2}".format(moz_host, moz_path, moz_file)

    def collect_catxt(self, target_file=None):
        """ Write to overwritable file_path """
        certificates = requests.get(self.moz_url).content
        fh = open(target_file, "w")
        for line in certificates.splitlines():
            fh.write("{0}\n".format(line))

    def check_file(self, target_file=None):
        """ validates file retention """
        file_time = os.path.getctime(target_file)
        now_time = int(time.time())
        time_diff = datetime.timedelta(seconds=((now_time - file_time)))
        if time_diff > datetime.timedelta(minutes=self.file_expire):
            try:
                self.collect_catxt(self.file_path)
            except Exception:
                # Do nothing, wait and use the old file
                pass

    def validate_provider(self, provider_list=None, cert=None):
        """ extracts issuer.O and compares against mozillas list """
        if not provider_list or not cert:
            return {'error': 'No provider list or cert provided'}
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        subject = cert.get_subject()
        issued_to = subject.CN
        issuer = cert.get_issuer()
        issued_by = issuer.CN
        provider = issuer.O
        cert_obj = {'fqdn': issued_to,
                    'provider': issuer.O}
        valid_provider = False
        for line in open(provider_list).readlines():
            if '# Issuer' in line and provider in line:
                valid_provider = True
        if not valid_provider:
            cert_obj['valid_provider'] = False
        cert_obj['valid_provider'] = True
        return cert_obj

    def cert_modulus(self, cert):
        """ extracts modulus from cert object """
        try:
            cert = M2Crypto.X509.load_cert_string(cert)
        except Exception:
            return {'error': 'Could not read cert provided'}
        pub_key = cert.get_pubkey()
        modulus = pub_key.get_modulus()
        return modulus

    def key_modulus(self, key):
        """ extracts modulus from the key object """
        try:
            pkey = M2Crypto.EVP.load_key_string(key)
        except Exception:
            return {'error': 'Could not read key provided'}
        modulus = pkey.get_modulus()
        return modulus

    def validate_modulus(self, cert, key):
        """ returns match/mismatch if the modulus matches cert/key """
        cert_mod = self.cert_modulus(cert)
        key_mod = self.key_modulus(key)
        mod = "mis-match"
        if 'Error' in cert_mod:
            return {'error': 'Empty cert provided'}
        if cert_mod == key_mod:
            mod = "match"
        return mod

    def main(self, cert, key):
        """ putting it together """
        self.check_file(self.file_path)
        cert_body = self.validate_provider(self.file_path, cert)
        cert_body.update({'modulus': self.validate_modulus(cert, key)})
        print cert_body

if __name__ == '__main__':
    sslv = SSLValidate()
    certificate = open("keys/cust2.crt", "r").read()
    key = open("keys/cust2.key", "r").read()
    sslv.main(certificate, key)
