/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLJNI;

import javax.crypto.SecretKey;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public class ZucKey implements SecretKey {

    public final static int KEY_SIZE = GmSSLJNI.ZUC_KEY_SIZE;

    private byte[] key;

    public ZucKey(byte[] key){
        this.key = key;
    }

    @Override
    public String getAlgorithm() {
        return "ZUC";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
}
