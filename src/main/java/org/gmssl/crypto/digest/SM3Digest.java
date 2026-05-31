/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.digest;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import java.security.MessageDigestSpi;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/09/07
 * @description
 * The SM3 cryptographic hash function can compute input data of arbitrary length into a fixed hash value of 32 bytes.
 */
public class SM3Digest extends MessageDigestSpi {

    private final static int DIGEST_SIZE = GmSSLJNI.SM3_DIGEST_SIZE;

    private long sm3_ctx = 0;

    public SM3Digest() {
        init();
    }

    /**
     * You can call the update method multiple times. After all the data has been input, finally call the digest method to obtain the SM3 hash value of the entire data.
     * @param input the input byte to be processed.
     */
    @Override
    protected void engineUpdate(byte input) {
        byte[] data = new byte[]{input};
        this.update(data, 0, data.length);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        this.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        return this.digest();
    }

    /**
     * If you need to calculate different SM3 hash values for multiple sets of data, you can use the reset method to reset,
     * and then call the update and digest methods again to compute the hash value of a new set of data.
     */
    @Override
    protected void engineReset() {
        this.reset();
    }

    private void init(){
        if ((sm3_ctx = GmSSLJNI.sm3_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
    }

    private void update(byte[] data, int offset, int len) {
        if (data == null
                || offset < 0
                || len < 0
                || offset + len <= 0
                || data.length < offset + len) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_update(sm3_ctx, data, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }

    private byte[] digest() {
        byte[] dgst = new byte[DIGEST_SIZE];
        if (GmSSLJNI.sm3_finish(sm3_ctx, dgst) != 1) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
        return dgst;
    }

    private void reset() {
        if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
            throw new GmSSLException("");
        }
    }

}
