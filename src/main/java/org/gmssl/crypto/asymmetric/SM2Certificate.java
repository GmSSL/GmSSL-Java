/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.*;
import java.security.cert.*;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 * The certificate format is the standard X.509v3 certificate. Currently, only the SM2 signature algorithm is supported.
 * This includes functions for parsing and verifying SM2 certificates. However, issuing and generating SM2 certificates are not supported.
 * If the application needs to implement certificate request (i.e., generating CSR files) or self-built CA certificate issuance,
 * these functionalities can be achieved using the GmSSL library or the gmssl command-line tool.
 */
public class SM2Certificate{

    private byte[] cert;

    public byte[] getEncoded() throws CertificateEncodingException {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        return this.cert;
    }

    public String toString() {
        return null;
    }

    public PublicKey getPublicKey() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        long pub_key;
        if ((pub_key = GmSSLJNI.cert_get_subject_public_key(this.cert)) == 0) {
            throw new GmSSLException("");
        }
        boolean has_private_key = false;
        return new SM2PublicKey(pub_key, has_private_key);
    }

    public void importPem(String file) {
        if ((this.cert = GmSSLJNI.cert_from_pem(file)) == null) {
            throw new GmSSLException("");
        }
    }

    public void exportPem(String file) {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.cert_to_pem(this.cert, file) != 1) {
            throw new GmSSLException("");
        }
    }

    public boolean verifyByCaCertificate(SM2Certificate caCert, String sm2Id) throws CertificateEncodingException {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        int ret = GmSSLJNI.cert_verify_by_ca_cert(this.cert, caCert.getEncoded(), sm2Id);
        if (ret == 1) {
            return true;
        } else {
            return false;
        }
    }

    public byte[] getSerialNumber() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        byte[] serial;
        if ((serial = GmSSLJNI.cert_get_serial_number(this.cert)) == null) {
            throw new GmSSLException("");
        }
        return serial;
    }

    public java.util.Date getNotBefore() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        return new java.util.Date(GmSSLJNI.cert_get_not_before(this.cert));
    }

    public java.util.Date getNotAfter() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        return new java.util.Date(GmSSLJNI.cert_get_not_after(this.cert));
    }

    public String[] getIssuer() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        String[] issuer;
        if ((issuer = GmSSLJNI.cert_get_issuer(this.cert)) == null) {
            throw new GmSSLException("");
        }
        return issuer;
    }

    public String[] getSubject() {
        if (this.cert == null) {
            throw new GmSSLException("");
        }
        String[] subject;
        if ((subject = GmSSLJNI.cert_get_subject(this.cert)) == null) {
            throw new GmSSLException("");
        }
        return subject;
    }
}
