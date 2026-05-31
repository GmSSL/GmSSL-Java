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

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description SM9Cipher
 * The SM9 algorithm belongs to an identity-based encryption (IBE) system.
 * Since IBE does not require a Certificate Authority (CA) or a digital certificate infrastructure,
 * if the application operates in a closed internal environment where all participating users are within the system, adopting the SM9 solution is a better choice.
 */
public class SM9Cipher extends CipherSpi {

    private int opmode;

    private Key key;

    private ByteBuffer buffer;

    private String id;

    /**
     *
     * @param mode the cipher mode
     * @throws NoSuchAlgorithmException
     * @description
     * SM9 is an identity-based encryption and signature algorithm that does not support traditional block cipher modes.
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    }

    /**
     *
     * @param padding the padding mechanism
     * @throws NoSuchPaddingException
     * @description
     * SM9 is an identity-based encryption and signature algorithm that does not support common padding modes.
     */
    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    }

    /**
     * SM9 is a public key encryption algorithm that does not have a fixed block size and does not use blocks.
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
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (!(key instanceof SM9PrivateKey)) {
            throw new GmSSLException("Invalid privateKey type");
        }
        this.opmode = opmode;
        this.key = key;
        SM9PrivateKey privateKey = (SM9PrivateKey)key;
        SM9UserKey userKey = (SM9UserKey)privateKey.getSecretKey();
        this.id = userKey.getId();
        this.buffer = ByteBuffer.allocate(1024);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SM9PublicKey)) {
            throw new GmSSLException("Invalid publicKey type");
        }
        this.opmode = opmode;
        this.key = key;
        this.id = ((SM9EncMasterKeyGenParameterSpec)params).getId();
        this.buffer = ByteBuffer.allocate(1024);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
    }

    /**
     * SM9 encryption and decryption are completed during the engineDoFinal phase. During the update phase, data is only cached, and no partial encryption or decryption results are returned.
     * @param input the input buffer
     * @param inputOffset the offset in <code>input</code> where the input
     * starts
     * @param inputLen the input length
     *
     * @return
     */
    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.put(input, inputOffset, inputLen);
        return null;
    }

    /**
     * SM9 encryption and decryption are completed during the engineDoFinal phase. During the update phase, data is only cached, and no partial encryption or decryption results are returned.
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
        buffer.put(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.put(input, inputOffset, inputLen);
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        buffer.clear();

        if (opmode == Cipher.ENCRYPT_MODE) {
            return encrypt(data);
        } else if (opmode == Cipher.DECRYPT_MODE) {
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

    private byte[] encrypt(byte[] plaintext) {
        SM9PublicKey encMasterKey = (SM9PublicKey) key;
        byte[] ciphertext = encMasterKey.encrypt(plaintext,id);
        return ciphertext;
    }

    private byte[] decrypt(byte[] ciphertext) {
        SM9PrivateKey privateKey = (SM9PrivateKey)key;
        byte[] plaintext = privateKey.decrypt(ciphertext);
        return plaintext;
    }
}
