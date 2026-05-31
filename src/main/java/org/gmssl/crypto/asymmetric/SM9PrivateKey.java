/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import java.security.PrivateKey;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public abstract class SM9PrivateKey implements PrivateKey {

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    public abstract KeySpec getSecretKey();

    public abstract void importEncryptedPrivateKeyInfoPem(String pass, String file);

    public abstract void exportEncryptedPrivateKeyInfoPem(String pass, String file);

    public byte[] decrypt(byte[] ciphertext) {
        return null;
    }

    public byte[] sign(long sign_ctx) {
        return null;
    }
}
