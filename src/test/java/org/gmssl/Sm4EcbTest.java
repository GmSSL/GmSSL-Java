/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2023/09/25
 * @description Sm4Ecb unit test
 */
public class Sm4EcbTest {

    byte[] key;

    @Before
    public void beforeTest(){
        key=new byte[]{74, 97, -73, 5, -31, 1, -88, -21, -7, -2, -65, 98, 70, 5, -54, 15};
    }

    @Test
    public void encryptTest(){
        String test_plaintext="gmssl";
        byte[] paddingPlaintext=pkcs5padding(test_plaintext.getBytes(),Sm4.BLOCK_SIZE);
        byte[] encrypted =  encrypt(paddingPlaintext,key);
        //System.out.println("encrypted data："+HexUtil.byteToHex(encrypted));
        Assert.assertNotNull("data is empty exception!",encrypted);
    }

    @Test
    public void decryptTest(){
        String test_hex_chipertext="31acce3f0317026c30accba2be9d326f";
        String test_plaintext="gmssl";
        byte[] encrypted =HexUtil.hexToByte(test_hex_chipertext);
        byte[] plaintextArray = decrypt(encrypted,key);
        byte[] unpaddingPlaintextArray = pkcs5Unpadding(plaintextArray);
        String plaintext=new String(unpaddingPlaintextArray);
        //System.out.println("chipertext:"+plaintext);
        Assert.assertEquals("original value is not equal to the expected value after decryption!",plaintext,test_plaintext);
    }


    /**
     * The purpose of PKCS5Padding is to pad the data to the block size required by the encryption algorithm, ensuring that the data length meets the requirements of the encryption algorithm.
     * In special cases where the data length is already a multiple of the block size, according to the PKCS5 rule, padding is still added at the end.
     * This is done to ensure consistent handling of padding during encryption and decryption processes.
     * @param ciphertextArray 
     * @param blockSize
     * @return byte[] ciphertext
     */
    private static byte[] pkcs5padding(byte[] ciphertextArray, int blockSize) {
        int paddingLength = blockSize - (ciphertextArray.length % blockSize);
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) paddingLength);
        byte[] result = new byte[ciphertextArray.length + padding.length];
        System.arraycopy(ciphertextArray, 0, result, 0, ciphertextArray.length);
        System.arraycopy(padding, 0, result, ciphertextArray.length, padding.length);
        return result;
    }

    /**
     * unpadding the plaintext
     * @param plaintextArray
     * @return byte[] plaintext
     * @throws IllegalArgumentException
     */
    private static byte[] pkcs5Unpadding(byte[] plaintextArray) throws IllegalArgumentException {
        int paddingSize = plaintextArray[plaintextArray.length - 1];
        if (paddingSize <= 0 || paddingSize > plaintextArray.length) {
            throw new IllegalArgumentException("Invalid pkcs#5 padding!");
        }
        for (int i = plaintextArray.length - paddingSize; i < plaintextArray.length; i++) {
            if (plaintextArray[i] != paddingSize) {
                throw new IllegalArgumentException("Invalid pkcs#5 padding!");
            }
        }
        return Arrays.copyOfRange(plaintextArray, 0, plaintextArray.length - paddingSize);
    }


    /**
     * Encrypt data by block
     * @param data data to be encrypted
     * @param key
     * @return byte[] encrypted data
     */
    private static byte[] encrypt(byte[] data, byte[] key) {
        byte[] ciphertext = new byte[data.length];
        Sm4 sm4 = new Sm4(key, true);
        for (int i = 0; i < data.length; i += Sm4.BLOCK_SIZE) {
            sm4.encrypt(data, i, ciphertext, i);
        }
        return ciphertext;
    }

    /**
     * Decrypt data by block
     * @param data data to be decrypted
     * @param key
     * @return byte[] decrypted data
     */
    private static byte[] decrypt(byte[] data, byte[] key) {
        byte[] plaintext=new byte[data.length];
        Sm4 sm4 = new Sm4(key, false);
        for (int i = 0; i < data.length; i += 16) {
            sm4.encrypt(data, i, plaintext, i);
        }
        return plaintext;
    }

}
