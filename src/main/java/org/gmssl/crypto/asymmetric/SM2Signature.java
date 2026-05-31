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
 * @description SM2Signature
 * It provides signing and verification functionality for messages of arbitrary length.
 */
public class SM2Signature extends SignatureSpi {

    public final static String DEFAULT_ID = GmSSLJNI.SM2_DEFAULT_ID;

    private long sm2_sign_ctx = 0;
    private boolean inited = false;

    private boolean do_sign = true;

    public SM2Signature() {
        super();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof SM2PublicKey)) {
            throw new GmSSLException("Invalid publicKey type");
        }
        init();
        initVerify((SM2PublicKey) publicKey,DEFAULT_ID);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SM2PrivateKey)) {
            throw new GmSSLException("Invalid privateKey type");
        }
        init();
        initSign((SM2PrivateKey) privateKey,DEFAULT_ID);
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
    protected byte[] engineSign() throws SignatureException {
        byte[] data = sign();
        return data;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        boolean verifyResult= verify(sigBytes);
        return verifyResult;
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    private void init(){
        if ((this.sm2_sign_ctx = GmSSLJNI.sm2_sign_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = true;
    }

    private void initSign(SM2PrivateKey privateKey,String id){
        if (GmSSLJNI.sm2_sign_init(this.sm2_sign_ctx, privateKey.getPrivateKey(), id) != 1) {
            throw new GmSSLException("");
        }
        this.do_sign = true;
    }

    private void initVerify(SM2PublicKey publicKey,String id){
        if (GmSSLJNI.sm2_verify_init(sm2_sign_ctx, publicKey.getPublicKey(), id) != 1) {
            throw new GmSSLException("");
        }
        this.do_sign = false;
    }

    private void update(byte[] data, int offset, int len) {
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
            if (GmSSLJNI.sm2_sign_update(this.sm2_sign_ctx, data, offset, len) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm2_verify_update(this.sm2_sign_ctx, data, offset, len) != 1) {
                throw new GmSSLException("");
            }
        }
    }

    private byte[] sign() {
        if (this.inited == false) {
            throw new GmSSLException("");
        }
        if (this.do_sign == false) {
            throw new GmSSLException("");
        }

        byte[] sig;
        if ((sig = GmSSLJNI.sm2_sign_finish(this.sm2_sign_ctx)) == null) {
            throw new GmSSLException("");
        }
        this.inited = false;
        return sig;
    }

    private boolean verify(byte[] signature) {
        if (this.sm2_sign_ctx == 0) {
            throw new GmSSLException("");
        }
        if (this.do_sign == true) {
            throw new GmSSLException("");
        }
        this.inited = false;
        int ret;
        if ((ret = GmSSLJNI.sm2_verify_finish(sm2_sign_ctx, signature)) != 1) {
            return false;
        }
        return true;
    }

}
