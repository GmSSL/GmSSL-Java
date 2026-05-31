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
/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM2KeyPairGenerator extends KeyPairGeneratorSpi {

    private long sm2_key = 0;
    private boolean has_private_key = false;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        generateKey();
    }

    @Override
    public KeyPair generateKeyPair() {
        PublicKey publicKey = new SM2PublicKey(sm2_key, has_private_key);
        PrivateKey privateKey = new SM2PrivateKey(sm2_key, has_private_key);
        return new KeyPair(publicKey, privateKey);
    }

    private void generateKey() {
        if (this.sm2_key != 0) {
            GmSSLJNI.sm2_key_free(this.sm2_key);
        }
        if ((sm2_key = GmSSLJNI.sm2_key_generate()) == 0) {
            throw new GmSSLException("");
        }
        this.has_private_key = true;
    }

}
