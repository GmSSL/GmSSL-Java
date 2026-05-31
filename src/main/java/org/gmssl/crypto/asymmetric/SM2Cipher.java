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

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 * The SM2Cipher class implements encryption and decryption methods. When calling the encrypt method, ensure that the length of the plaintext input does not exceed the MAX_PLAINTEXT_SIZE limit.
 * If you need to encrypt a message at the reference layer, first generate a symmetric key, encrypt the message using SM4-GCM, and then encrypt the symmetric key using SM2.
 */
public class SM2Cipher extends CipherSpi {

    private int mode;
    private SM2Key key;
    private SecureRandom random;
    private ByteBuffer buffer;

    /**
     * SM2 uses the C1C2C3 encryption mode.
     * @param mode the cipher mode
     *
     * @throws NoSuchAlgorithmException
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

    }

    /**
     * SM2 has adopted the corresponding padding rule and does not involve specific padding modes.
     * @param padding the padding mechanism
     *
     * @throws NoSuchPaddingException
     */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    /**
     * SM2 does not have a fixed block size.
     * @return
     */
    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int mode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        if (!(key instanceof SM2Key)) {
            throw new InvalidKeyException("Invalid key type");
        }
        this.key = (SM2Key)key;
        this.mode = mode;
        this.random = (secureRandom != null) ? secureRandom : new SecureRandom();
        this.buffer = ByteBuffer.allocate(1024);
    }

    @Override
    protected void engineInit(int mode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(mode, key, random);
    }

    @Override
    protected void engineInit(int i, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(mode, key, random);
    }

    /**
     *
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     *
     * @return null
     * The SM2 algorithm typically does not return any data during the engineUpdate phase.
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (input == null || inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid input parameters");
        }
        buffer.put(input, inputOffset, inputLen);
        return null;
    }

    /**
     * The method does not perform any encryption or decryption; it only stores the input data. The returned result is meaningless, and the final result is output through `doFinal`.
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     * @param output the buffer for the result
     * @param outputOffset the offset in <code>output</code> where the result
     * is stored
     *
     * @return
     * @throws ShortBufferException
     */
    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        if (input == null || inputOffset < 0 || inputLen < 0 || inputOffset + inputLen > input.length) {
            throw new IllegalArgumentException("Invalid input parameters");
        }
        buffer.put(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if(null != input){
            buffer.put(input, inputOffset, inputLen);
        }
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        buffer.clear();

        if (mode == Cipher.ENCRYPT_MODE) {
            return encrypt(data);
        } else if (mode == Cipher.DECRYPT_MODE) {
            return decrypt(data);
        } else {
            throw new GmSSLException("Cipher not initialized properly");
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    public byte[] encrypt(byte[] plaintext) {
        if (this.key.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (plaintext == null
                || plaintext.length > this.key.MAX_PLAINTEXT_SIZE) {
            throw new GmSSLException("");
        }

        byte[] ciphertext;
        if ((ciphertext = GmSSLJNI.sm2_encrypt(this.key.sm2_key, plaintext)) == null) {
            throw new GmSSLException("");
        }
        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        if (this.key.sm2_key == 0) {
            throw new GmSSLException("");
        }
        if (this.key.has_private_key == false) {
            throw new GmSSLException("");
        }
        if (ciphertext == null) {
            throw new GmSSLException("");
        }

        byte[] plaintext;
        if ((plaintext = GmSSLJNI.sm2_decrypt(this.key.sm2_key, ciphertext)) == null) {
            throw new GmSSLException("");
        }
        return plaintext;
    }
}
