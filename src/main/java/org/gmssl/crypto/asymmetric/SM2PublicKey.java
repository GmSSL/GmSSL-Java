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
import org.gmssl.Sm3;

import java.security.PublicKey;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM2PublicKey extends SM2Key implements PublicKey{

    protected SM2PublicKey() {
        super();
    }

    public SM2PublicKey(byte[] der) {
        importPublicKeyInfoDer(der);
    }

    public SM2PublicKey(String file) {
        importPublicKeyInfoPem(file);
    }

    protected SM2PublicKey(long sm2_key, boolean has_private_key) {
        super(sm2_key,has_private_key);
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return exportPublicKeyInfoDer();
    }

    public void importPublicKeyInfoDer(byte[] der) {
        if (der == null) {
            throw new GmSSLException("");
        }
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_der(der)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = false;
    }

    public byte[] exportPublicKeyInfoDer() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        byte[] der;
        if ((der = GmSSLJNI.sm2_public_key_info_to_der(this.sm2_key)) == null) {
            throw new GmSSLException("");
        }
        return der;
    }

    public void importPublicKeyInfoPem(String file) {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_pem(file)) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = false;
    }

    public void exportPublicKeyInfoPem(String file) {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm2_public_key_info_to_pem(this.sm2_key, file) != 1) {
            throw new GmSSLException("");
        }
    }

    public byte[] computeZ(String id) {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        byte[] z = new byte[Sm3.DIGEST_SIZE];
        if (GmSSLJNI.sm2_compute_z(this.sm2_key, id, z) != 1) {
            throw new GmSSLException("");
        }
        return z;
    }

}
