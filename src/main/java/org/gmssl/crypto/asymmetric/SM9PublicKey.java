/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import java.security.PublicKey;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public abstract class SM9PublicKey implements PublicKey {

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

    public abstract long getPublicKey();

    public abstract void importPublicKeyPem(String file);

    public abstract void exportPublicKeyPem(String file);

    public byte[] encrypt(byte[] plaintext, String id){
        return null;
    };

    public Boolean verify(byte[] signature, String id,long sign_ctx){
        return null;
    }
}
