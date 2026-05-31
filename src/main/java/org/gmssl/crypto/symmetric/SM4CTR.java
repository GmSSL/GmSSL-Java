/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public class SM4CTR extends SM4Engine {

    public final static int IV_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private byte[] iv;

    private long sm4_ctr_ctx = 0;
    private boolean inited = false;

    private int offset;

    private byte[] outputByteArray;

    protected SM4CTR() {
        super();
        ctx();
    }

    @Override
    protected void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new GmSSLException("Initialization method not supported!");
    }

    @Override
    protected void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        if (!(params instanceof IvParameterSpec)) {
            throw new GmSSLException("need the IvParameterSpec parameter");
        }
        this.iv = ((IvParameterSpec) params).getIV();
        init(key.getEncoded(), iv);

        outputByteArray = new byte[BLOCK_SIZE];
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected byte[] processUpdate(byte[] input, int inputOffset, int inputLen) {
        int newOutputLength = BLOCK_SIZE + offset + inputLen;
        if (outputByteArray.length < newOutputLength) {
            int newSize = Math.max(outputByteArray.length * 3 / 2 + BLOCK_SIZE, newOutputLength);
            outputByteArray = Arrays.copyOf(outputByteArray, newSize);
        }

        int outLen = processUpdate(input, inputOffset, inputLen, outputByteArray, offset);
        return Arrays.copyOfRange(outputByteArray,offset-outLen,offset);
    }

    @Override
    protected int processUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        int outLen = update(input, inputOffset, inputLen, output, outputOffset);
        this.offset += outLen;
        return outLen;
    }

    @Override
    protected byte[] processBlock(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(null!=input){
            processUpdate(input, inputOffset, inputLen);
        }
        int outLen = doFinal(outputByteArray, this.offset);
        outLen = outLen + this.offset;
        this.offset = 0;
        outputByteArray = Arrays.copyOfRange(outputByteArray,0,outLen);
        return outputByteArray;
    }

    @Override
    protected int processBlock(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLen = 0;
        if(null!=input){
            outLen=this.processUpdate(input, inputOffset, inputLen, output, outputOffset);
        }
        outLen += doFinal(output, this.offset);
        this.offset = 0;
        return outLen;
    }

    public void ctx(){
        if ((this.sm4_ctr_ctx = GmSSLJNI.sm4_ctr_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
    }

    public void init(byte[] key, byte[] iv) {
        if (key == null
                || key.length != this.KEY_SIZE
                || iv == null
                || iv.length != this.IV_SIZE) {
            throw new GmSSLException("");
        }

        if (GmSSLJNI.sm4_ctr_encrypt_init(this.sm4_ctr_ctx, key, iv) != 1) {
            throw new GmSSLException("");
        }

        this.inited = true;
    }

    public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {
        if (this.inited == false) {
            throw new GmSSLException("");
        }

        if (in == null
                || in_offset < 0
                || inlen < 0
                || in_offset + inlen <= 0
                || in.length < in_offset + inlen) {
            throw new GmSSLException("");
        }
        if (out == null
                || out_offset < 0
                || out.length < out_offset) {
            throw new GmSSLException("");
        }

        int outlen;
        if ((outlen = GmSSLJNI.sm4_ctr_encrypt_update(this.sm4_ctr_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
            throw new GmSSLException("");
        }
        return outlen;
    }

    public int doFinal(byte[] out, int out_offset){
        if (this.inited == false) {
            throw new GmSSLException("");
        }

        if (out == null
                || out_offset < 0
                || out.length < out_offset) {
            throw new GmSSLException("");
        }

        int outlen;
        if ((outlen = GmSSLJNI.sm4_ctr_encrypt_finish(this.sm4_ctr_ctx, out, out_offset)) < 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
        return outlen;
    }
}
