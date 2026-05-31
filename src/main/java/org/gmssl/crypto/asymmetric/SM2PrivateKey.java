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

import java.security.PrivateKey;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM2PrivateKey extends SM2Key implements PrivateKey{

    protected SM2PrivateKey() {
        super();
    }

    public SM2PrivateKey(byte[] der) {
        importPrivateKeyInfoDer(der);
    }

    public SM2PrivateKey(String password, String file) {
        importEncryptedPrivateKeyInfoPem(password, file);
    }

    protected SM2PrivateKey(long sm2_key, boolean has_private_key) {
        super(sm2_key,has_private_key);
    }

    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return exportPrivateKeyInfoDer();
    }

    public void importPrivateKeyInfoDer(byte[] der) {
        if (der == null) {
            throw new GmSSLException("");
        }
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_private_key_info_from_der(der)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

    public byte[] exportPrivateKeyInfoDer() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        byte[] der;
        if ((der = GmSSLJNI.sm2_private_key_info_to_der(this.sm2_key)) == null) {
            throw new GmSSLException("");
        }
        return der;
    }

    public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((sm2_key = GmSSLJNI.sm2_private_key_info_decrypt_from_pem(pass, file)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

    public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm2_private_key_info_encrypt_to_pem(this.sm2_key, pass, file) != 1) {
            throw new GmSSLException("");
        }
    }

}
