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
import org.gmssl.Sm4;

import javax.crypto.*;
import java.nio.ByteBuffer;
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
public class SM4ECB extends SM4Engine {

    private Key key;
    private long sm4_key;

    private boolean do_encrypt;

    private ByteBuffer buffer;

    @Override
    protected void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new GmSSLException("Invalid KeySpec");
        }
        this.do_encrypt = (opmode == Cipher.ENCRYPT_MODE);
        this.key = key;
        // 初始化缓冲区
        this.buffer = ByteBuffer.allocate(2048);
        init();
    }

    @Override
    protected void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        throw new GmSSLException("Initialization method not supported!");
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    /**
     * Mainly used for caching data; it will not immediately generate encryption or decryption results
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return null
     * Return a non-actual value; actual encryption or decryption operations are performed in processBlock
     */
    @Override
    protected byte[] processUpdate(byte[] input, int inputOffset, int inputLen) {
        putBytes(input, inputOffset, inputLen);
        return null;
    }

    @Override
    protected byte[] processBlock(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(null!=input){
            putBytes(input, inputOffset, inputLen);
        }
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        byte[] outPutByteArray = new byte[buffer.position()];
        if(do_encrypt){
            data = this.paddingScheme.pad(data,this.BLOCK_SIZE);
            outPutByteArray = new byte[data.length];
            for (int i = 0; i < data.length; i += this.BLOCK_SIZE) {
                encrypt(data,i,outPutByteArray,i);
            }
        }else{
            for (int i = 0; i < data.length; i += this.BLOCK_SIZE) {
                encrypt(data,i,outPutByteArray,i);
            }
            outPutByteArray=this.paddingScheme.unpad(outPutByteArray);
        }

        buffer.clear();
        return outPutByteArray;
    }

    /**
     * Mainly used for caching data; it will not immediately generate encryption or decryption results
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     * @return 0
     * Return a non-actual value; actual encryption or decryption operations are performed in processBlock
     */
    @Override
    protected int processUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {
        putBytes(input, inputOffset, inputLen);
        return 0;
    }

    /**
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @param output
     * @param outputOffset
     * @return actual encryption or decryption bytes length,not the whole length of the output data
     *
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Override
    protected int processBlock(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws IllegalBlockSizeException, BadPaddingException {
        byte[] outPutByteArray = processBlock(input, inputOffset, inputLen);
        System.arraycopy(outPutByteArray, 0,output, outputOffset, outPutByteArray.length);
        return outPutByteArray.length;
    }

    private void putBytes(byte[] input, int inputOffset, int inputLen){
        if(buffer.remaining()<inputLen){
            ByteBuffer newByteBuffer=ByteBuffer.allocate(buffer.capacity()+inputLen);
            buffer.flip();
            newByteBuffer.put(buffer);
            buffer=newByteBuffer;
        }
        buffer.put(input, inputOffset, inputLen);
    }

    private void init(){
        if ((sm4_key = GmSSLJNI.sm4_key_new()) == 0) {
            throw new GmSSLException("");
        }

        if (do_encrypt == true) {
            if (GmSSLJNI.sm4_set_encrypt_key(sm4_key, key.getEncoded()) != 1) {
                throw new GmSSLException("");
            }
        } else {
            if (GmSSLJNI.sm4_set_decrypt_key(sm4_key, key.getEncoded()) != 1) {
                throw new GmSSLException("");
            }
        }
    }

    private void encrypt(byte[] in, int in_offset, byte[] out, int out_offset) {
        if (in == null
                || in_offset < 0
                || in_offset + this.BLOCK_SIZE <= 0
                || in_offset + this.BLOCK_SIZE > in.length) {
            throw new GmSSLException("");
        }
        if (out == null
                || out_offset < 0
                || out_offset + this.BLOCK_SIZE <= 0
                || out_offset + this.BLOCK_SIZE > in.length) {
            throw new GmSSLException("");
        }

        if (GmSSLJNI.sm4_encrypt(sm4_key, in, in_offset, out, out_offset) != 1) {
            throw new GmSSLException("");
        }
    }
}
