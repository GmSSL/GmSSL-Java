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

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/09/07
 * @description
 * HMAC-SM3 is a Message Authentication Code (MAC) algorithm based on the SM3 cryptographic hash algorithm.
 * A MAC algorithm can be viewed as a keyed hash function, primarily used to protect messages from tampering.
 * Both communicating parties need to agree on a key in advance, such as a 32-byte random byte sequence.
 * The data sender uses this key to compute the MAC value of the message and appends the MAC value to the message.
 * Upon receiving the message, the recipient uses the same key to compute the MAC value of the message and compares it with the MAC value attached to the sent message.
 * If they match, it indicates that the message has not been tampered with; if they do not match, it indicates that the message has been altered.
 */
public class SM3Hmac extends MacSpi {

    public final static int MAC_SIZE = GmSSLJNI.SM3_HMAC_SIZE;

    private Key key;

    private long sm3_hmac_ctx = 0;

    public SM3Hmac() {
        super();
        ctx();
    }

    @Override
    protected int engineGetMacLength() {
        return MAC_SIZE;
    }

    /**
     * The HMAC-SM3 algorithm can be seen as the SM3 algorithm with a key, so when creating an Sm3Hmac object, a key must be passed as an input parameter.
     * Although HMAC-SM3 does not have any restrictions on key length in terms of the algorithm and implementation, for considerations of security and efficiency, the key length for the HMAC-SM3 algorithm is recommended to be 32 bytes (equivalent to the length of the SM3 hash value) and should not be less than 16 bytes.
     * Using a key length longer than 32 bytes would increase computational overhead without enhancing security.
     * @param key the (secret) key.
     * @param params the algorithm parameters.
     *
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new GmSSLException("Invalid key for HMAC-SM3");
        }
        this.key = key;
        init();
    }

    /**
     * You can call update multiple times and ultimately execute doFinal. The HMAC-SM3 output is a fixed 32 bytes, which is a binary message authentication code of length MAC_SIZE.
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
    protected byte[] engineDoFinal() {
        return generateMac();
    }

    @Override
    protected void engineReset() {
        this.reset(this.key);
    }

    private void ctx(){
        if ((this.sm3_hmac_ctx = GmSSLJNI.sm3_hmac_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
    }

    private void init() {
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key.getEncoded()) != 1) {
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
        if (GmSSLJNI.sm3_hmac_update(this.sm3_hmac_ctx, data, offset, len) != 1) {
            throw new GmSSLException("");
        }
    }

    private void update(byte[] data) {
        this.update(data, 0, data.length);
    }

    private byte[] generateMac() {
        byte[] mac = new byte[this.MAC_SIZE];
        if (GmSSLJNI.sm3_hmac_finish(this.sm3_hmac_ctx, mac) != 1) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, this.key.getEncoded()) != 1) {
            throw new GmSSLException("");
        }
        return mac;
    }

    private void reset(Key key) {
        if (key == null) {
            throw new GmSSLException("");
        }
        if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key.getEncoded()) != 1) {
            throw new GmSSLException("");
        }
        this.key = key;
    }
}
