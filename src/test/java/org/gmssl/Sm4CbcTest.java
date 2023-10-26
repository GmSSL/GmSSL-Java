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
 * @date 2023/09/07
 * @description Sm4Cbc unit test
 */
public class Sm4CbcTest {

    Sm4Cbc sm4Cbc;
    byte[] key , iv ;

    @Before
    public void beforeTest(){
        sm4Cbc = new Sm4Cbc();
        key = new byte[]{-73, -55, -122, -95, 0, -4, 51, -38, 125, -31, 38, 12, 112, 8, -50, -92};
        iv = new byte[]{88, 121, -51, 88, 32, -85, 98, 56, 108, 18, 102, -73, -122, -59, -97, -25};
    }

    @Test
    public void encryptTest(){
        String testStr="gmssl";

        byte[] plaintext = testStr.getBytes();
        byte[] ciphertext = new byte[plaintext.length+Sm4Cbc.BLOCK_SIZE];
        sm4Cbc.init(key, iv, true);
        int cipherlen = sm4Cbc.update(plaintext, 0, plaintext.length, ciphertext, 0);
        cipherlen += sm4Cbc.doFinal(ciphertext, cipherlen);
        byte[] ciphertext1 =Arrays.copyOfRange(ciphertext,0,cipherlen);
        //System.out.println("cipher:"+HexUtil.byteToHex(ciphertext1));
        Assert.assertNotNull("data is empty exception!",HexUtil.byteToHex(ciphertext1));
    }

    @Test
    public void decryptTest(){
        String cipherHex="ccedec05b742098b33e0fc8c5c006365";
        byte[] ciphertext=HexUtil.hexToByte(cipherHex);
        sm4Cbc.init(key, iv, false);
        byte[] decrypted = new byte[ciphertext.length + Sm4Cbc.BLOCK_SIZE]; // prepare large enough plaintext buffer
        int decryptedOffset = 0;
        int decryptedLen;
        int ciphertextOffset = 0;
        decryptedLen = sm4Cbc.update(ciphertext, ciphertextOffset, ciphertext.length, decrypted, decryptedOffset);
        decryptedOffset += decryptedLen;
        decryptedLen += sm4Cbc.doFinal(decrypted, decryptedOffset);
        byte[] plaintext =Arrays.copyOfRange(decrypted,0,decryptedLen);
        String plaintextStr=new String(plaintext);
        //System.out.println(plaintextStr);
        Assert.assertEquals("original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }

}
