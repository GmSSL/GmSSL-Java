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
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM9Signature extends SignatureSpi {

    private long sm9_sign_ctx;

    private boolean inited;

    private boolean do_sign;

    private Key key;

    private String id;

    public SM9Signature() {
        super();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SM9PublicKey)) {
            throw new GmSSLException("Invalid publicKey type");
        }
        this.key = publicKey;
        init();
        initVerify();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SM9PrivateKey)) {
            throw new GmSSLException("Invalid privateKey type");
        }
        this.key = privateKey;
        init();
        initSign();
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] data= new byte[]{b};
        update(data, 0, data.length);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        update(b, off, len);
    }

    @Override
    protected byte[] engineSign() {
        SM9PrivateKey sm9_private_key = (SM9PrivateKey)key;
        byte[] signature = sm9_private_key.sign(sm9_sign_ctx);
        this.inited = false;
        return signature;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        SM9PublicKey sm9_public_key = (SM9PublicKey)key;
        boolean verify = sm9_public_key.verify(sigBytes,id,sm9_sign_ctx);
        this.inited = false;
        return verify;
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        this.id = ((SM9SignMasterKeyGenParameterSpec)params).getId();
    }

    private void init(){
        if ((this.sm9_sign_ctx = GmSSLJNI.sm9_sign_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = true;
    }

    private void initSign() {
        if (GmSSLJNI.sm9_sign_init(this.sm9_sign_ctx) != 1) {
            throw new GmSSLException("");
        }
        this.do_sign = true;
    }

    private void initVerify() {
        if (GmSSLJNI.sm9_verify_init(this.sm9_sign_ctx) != 1) {
            throw new GmSSLException("");
        }
        this.do_sign = false;
    }

    public void reset(boolean do_sign) {
        if (do_sign == true) {
            if (GmSSLJNI.sm9_sign_init(this.sm9_sign_ctx) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm9_verify_init(this.sm9_sign_ctx) != 1) {
                throw new GmSSLException("");
            }
        }
        this.inited = true;
        this.do_sign = do_sign;
    }

    public void update(byte[] data, int offset, int len) {
        if (this.inited == false) {
            throw new GmSSLException("");
        }
        if (data == null
                || offset < 0
                || len < 0
                || offset + len <= 0
                || data.length < offset + len) {
            throw new GmSSLException("");
        }
        if (this.do_sign == true) {
            if (GmSSLJNI.sm9_sign_update(this.sm9_sign_ctx, data, offset, len) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm9_verify_update(this.sm9_sign_ctx, data, offset, len) != 1) {
                throw new GmSSLException("");
            }
        }
    }
}
