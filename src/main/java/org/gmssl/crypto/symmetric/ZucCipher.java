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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 * The Zu Chongzhi Cipher Algorithm (ZU Cipher, ZUC) is a stream cipher with both the key and IV lengths set to 16 bytes.
 * As a stream cipher, ZUC can encrypt input data of variable length, and the ciphertext output has the same length as the input data.
 * This makes it suitable for applications that do not allow ciphertext expansion.
 * In terms of security, it is not recommended to use the ZUC algorithm to encrypt large amounts of data (such as GB or TB levels) with a single key and IV, to avoid a decrease in security when the stream cipher produces extremely long outputs.
 */
public class ZucCipher extends CipherSpi {

    public final static int IV_SIZE = GmSSLJNI.ZUC_IV_SIZE;
    public final static int BLOCK_SIZE = 4;

    private long zuc_ctx;
    private boolean inited;

    private byte[] iv;

    private int offset;

    private byte[] outputByteArray;

    public ZucCipher(){
        ctx();
    }

    /**
     * As a stream cipher, ZUC generates a pseudo-random sequence for each encryption or decryption operation, which is then XORed bit-by-bit with the plaintext to achieve encryption or decryption.
     * Therefore, ZUC does not require the use of specific modes like block ciphers; instead, it directly generates the encryption key stream and performs the encryption operation bit-by-bit.
     * @param mode the cipher mode
     *
     */
    @Override
    protected void engineSetMode(String mode){
    }

    /**
     * ZUC does not require a padding mode and can directly handle plaintext of any length.
     * @param padding the padding mechanism
     *
     */
    @Override
    protected void engineSetPadding(String padding){
    }

    @Override
    protected int engineGetBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new GmSSLException("Initialization method not supported!");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof IvParameterSpec) {
            IvParameterSpec ivSpec = (IvParameterSpec) params;
            this.iv = ivSpec.getIV();
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported parameters");
        }
        init(key.getEncoded(), iv);

        outputByteArray = new byte[BLOCK_SIZE];
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new GmSSLException("Initialization method not supported!");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        int newOutputLength = BLOCK_SIZE + offset + inputLen;
        if (outputByteArray.length < newOutputLength) {
            int newSize = Math.max(outputByteArray.length * 3 / 2 + BLOCK_SIZE, newOutputLength);
            outputByteArray = Arrays.copyOf(outputByteArray, newSize);
        }

        int outLen = engineUpdate(input, inputOffset, inputLen, outputByteArray, offset);
        return Arrays.copyOfRange(outputByteArray,offset-outLen,offset);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset){
        int outLen = update(input, inputOffset, inputLen, output, outputOffset);
        this.offset+=outLen;
        return outLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(null!=input){
            engineUpdate(input, inputOffset, inputLen);
        }
        int outLen = doFinal(outputByteArray, this.offset);
        outLen = outLen + this.offset;
        this.offset = 0;
        outputByteArray = Arrays.copyOfRange(outputByteArray,0,outLen);
        return outputByteArray;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLen = 0;
        if(null!=input){
            outLen=this.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
        }
        outLen += doFinal(output, this.offset);
        this.offset = 0;
        return outLen;
    }

    private void ctx(){
        if ((this.zuc_ctx = GmSSLJNI.zuc_ctx_new()) == 0) {
            throw new GmSSLException("");
        }
        this.inited = false;
    }

    private void init(byte[] key, byte[] iv){
        if (key == null
                || key.length != ZucKey.KEY_SIZE
                || iv == null
                || iv.length != this.IV_SIZE) {
            throw new GmSSLException("");
        }

        if (GmSSLJNI.zuc_encrypt_init(this.zuc_ctx, key, iv) != 1) {
            throw new GmSSLException("");
        }

        this.inited = true;
    }

    private int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {

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
        if ((outlen = GmSSLJNI.zuc_encrypt_update(this.zuc_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
            throw new GmSSLException("");
        }

        return outlen;
    }

    private int doFinal(byte[] out, int out_offset) {

        if (this.inited == false) {
            throw new GmSSLException("");
        }

        if (out == null
                || out_offset < 0
                || out.length < out_offset) {
            throw new GmSSLException("");
        }

        int outlen;
        if ((outlen = GmSSLJNI.zuc_encrypt_finish(this.zuc_ctx, out, out_offset)) < 0) {
            throw new GmSSLException("");
        }

        this.inited = false;
        return outlen;
    }
}
