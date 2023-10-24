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
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;

/**
 * @author yongfei.li
 * @email 290836576@qq.com
 * @date 2023/09/12
 * @description zuc unit test
 */
public class ZucTest {

    byte[] key , iv;
    Zuc zuc;


    @Before
    public void beforeTest(){
        zuc = new Zuc();
        key=new byte[]{-58, -106, -55, 98, -75, 49, -74, -101, -50, 1, -79, 43, -33, -86, -57, -106};
        iv=new byte[]{-119, 19, 24, 45, 83, 17, -89, 102, -72, -104, 91, -31, -25, -109, -28, 30};
    }

    /**
     * encryption unit test
     */
    @Test
    public void encryptTest(){
        String plaintextStr = "gmss";
        byte[] plaintext = plaintextStr.getBytes();

        int ciphertextLen = 2 * Zuc.BLOCK_SIZE * (int)Math.ceil((plaintext.length)/(double)Zuc.BLOCK_SIZE);
        byte[] ciphertext = new byte[Math.max(16,ciphertextLen)];
        int cipherlen;

        zuc.init(key, iv);
        cipherlen = zuc.update(plaintext, 0, plaintext.length, ciphertext, 0);
        cipherlen += zuc.doFinal(ciphertext, cipherlen);

        ciphertext = Arrays.copyOfRange(ciphertext,0,cipherlen);
        String ciphertextHex= HexUtil.byteToHex(ciphertext);
        //System.out.println(ciphertextHex);
        Assert.assertNotNull("data is empty exception!",ciphertextHex);
    }

    /**
     * decryption unit test
     */
    @Test
    public void decryptTest(){
        String ciphertextHex = "91a99db164";

        int plainlen;
        byte[] ciphertext=HexUtil.hexToByte(ciphertextHex);
        int plaintextLen = 2 * Zuc.BLOCK_SIZE * (int)Math.ceil((ciphertext.length)/(double)Zuc.BLOCK_SIZE);
        byte[] plaintext = new byte[Math.max(16,plaintextLen)];

        zuc.init(key, iv);
        plainlen = zuc.update(ciphertext, 0, ciphertext.length, plaintext, 0);
        plainlen += zuc.doFinal(plaintext, plainlen);

        plaintext=Arrays.copyOfRange(plaintext,0,plainlen);
        String plaintextStr = new String(plaintext);
        //System.out.println(plaintextStr);
        Assert.assertEquals("original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }


}
