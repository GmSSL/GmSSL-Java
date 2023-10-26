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

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2023/10/20
 * @description Sm4 unit test
 */
public class Sm4Test {

    byte[] key;

    @Before
    public void beforeTest(){
        key=new byte[]{49, 50, 51, 52, 53, 54, 55, 56, 56, 55, 54, 53, 52, 51, 50, 49};
    }

    @Test
    public void encryptTest(){
        String plaintextStr="1234567887654321";
        byte[] plaintext=plaintextStr.getBytes();
        byte[] ciphertext=new byte[Sm4.BLOCK_SIZE];
        Sm4 sm4enc = new Sm4(key, true);
        sm4enc.encrypt(plaintext, 0, ciphertext, 0);
        String ciphertextHex = HexUtil.byteToHex(ciphertext);
        //System.out.println(ciphertextHex);
        Assert.assertNotNull("data is empty exception!",ciphertextHex);
    }

    @Test
    public void decryptTest(){
        String ciphertextHex="4a7dc8fc6f7fb9bac989bbf8a5f194a7";
        byte[] ciphertext = HexUtil.hexToByte(ciphertextHex);
        byte[] plaintext = new byte[ciphertext.length];
        Sm4 sm4dec = new Sm4(key, false);
        sm4dec.encrypt(ciphertext, 0, plaintext, 0);
        String plaintext1=new String(plaintext);
        //System.out.println(plaintext1);
        Assert.assertEquals("original value is not equal to the expected value after decryption!","1234567887654321",plaintext1);
    }

}
