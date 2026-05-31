/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.SecureRandomSpi;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public class Random extends SecureRandomSpi {

    public Random() {
        super();
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        if (seed == null || seed.length == 0) {
            throw new IllegalArgumentException("Seed cannot be null or empty");
        }
        //rand_seed
        throw new GmSSLException("The current method is not supported.");
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null) {
            throw new IllegalArgumentException("Output buffer cannot be null");
        }
        randBytes(bytes,0, bytes.length);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes <= 0) {
            throw new IllegalArgumentException("Number of bytes must be positive");
        }
        return randBytes(numBytes);
    }

    public byte[] randBytes(int len) {
        byte[] out = new byte[len];
        if (GmSSLJNI.rand_bytes(out, 0, len) != 1) {
            throw new GmSSLException("Failed to generate seed");
        }
        return out;
    }

    public void randBytes(byte[] out, int offset, int len) {
        if (out == null
                || offset < 0
                || len < 0
                || offset + len <= 0
                || out.length < offset + len) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.rand_bytes(out, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }
}
