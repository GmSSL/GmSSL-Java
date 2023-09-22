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
 * @description Sm4Ctr unit test
 */
public class Sm4CtrTest {

    private Sm4Ctr sm4Ctr;

    byte[] key = null,iv = null;

    @Before
    public void beforeTest(){
        sm4Ctr = new Sm4Ctr();
        key=new byte[]{99, -49, -44, -61, 104, 76, -65, 88, 55, 54, 48, -81, 99, -10, 50, 22};
        iv=new byte[]{-127, 39, -104, -97, 61, -119, 85, -18, -14, -79, 47, -92, -113, 92, 28, -34};
    }

    @Test
    public void encryptTest(){
        String ciphertext_1="gmssl",ciphertext_2="_",ciphertext_3="v3";
        byte[] ciphertext = new byte[64];
        sm4Ctr.init(key, iv);
        int cipherlen = sm4Ctr.update(ciphertext_1.getBytes(), 0, ciphertext_1.length(), ciphertext, 0);
        cipherlen += sm4Ctr.update(ciphertext_2.getBytes(), 0, ciphertext_2.length(), ciphertext, cipherlen);
        cipherlen += sm4Ctr.update(ciphertext_3.getBytes(), 0, ciphertext_3.length(), ciphertext, cipherlen);
        cipherlen += sm4Ctr.doFinal(ciphertext, cipherlen);
        byte[] ciphertextEnd =  Arrays.copyOfRange(ciphertext,0,cipherlen);
        //System.out.println(HexUtil.byteToHex(ciphertextEnd));
        Assert.assertNotNull("数据为空异常",HexUtil.byteToHex(ciphertextEnd));
    }

    @Test
    public void decryptTest(){
        String plainText="gmssl_v3";
        String ciphertext="912c3317275d8e5f";
        byte[] ciphertextByte=HexUtil.hexToByte(ciphertext);
        byte[] plaintext = new byte[64];

        sm4Ctr.init(key, iv);
        int plainlen = sm4Ctr.update(ciphertextByte, 0, ciphertext.length()/2, plaintext, 0);
        plainlen += sm4Ctr.doFinal(plaintext, plainlen);
        plaintext=Arrays.copyOfRange(plaintext,0,plainlen);
        //System.out.println(new String(plaintext));
        Assert.assertEquals(plainText,new String(plaintext));
    }

}
