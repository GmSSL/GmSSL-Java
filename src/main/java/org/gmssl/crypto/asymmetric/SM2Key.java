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

import java.security.Key;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description SM2Key
 *
 */
public abstract class SM2Key implements Key {

    public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM2_MAX_PLAINTEXT_SIZE;

    protected long sm2_key;
    protected boolean has_private_key;

    protected SM2Key() {
        this.sm2_key = 0;
        this.has_private_key = false;
    }

    protected SM2Key(long sm2_key, boolean has_private_key) {
        this.sm2_key = sm2_key;
        this.has_private_key = has_private_key;
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    long getPrivateKey() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        return this.sm2_key;
    }

    long getPublicKey() {
        if (this.sm2_key == 0) {
            throw new GmSSLException("");
        }
        return this.sm2_key;
    }

}
