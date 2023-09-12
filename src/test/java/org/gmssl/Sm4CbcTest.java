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

    Sm4Cbc sm4Cbc=null;
    Random rng = new Random();
    byte[] key = rng.randBytes(Sm4Cbc.KEY_SIZE);
    byte[] iv = rng.randBytes(Sm4Cbc.IV_SIZE);

    @Before
    public void beforeTest(){
        sm4Cbc = new Sm4Cbc();
    }

    @Test
    public void encryptTest(){
        String testStr="abc";
        byte[] ciphertext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
        sm4Cbc.init(key, iv, true);
        int cipherlen = sm4Cbc.update(testStr.getBytes(), 0, 3, ciphertext, 0);
        cipherlen += sm4Cbc.doFinal(ciphertext, cipherlen);

        byte[] ciphertextEnd =Arrays.copyOfRange(ciphertext,0,cipherlen);
        //System.out.println("cipher:"+HexUtil.byteToHex(ciphertextEnd));
        Assert.assertNotNull("数据为空异常",HexUtil.byteToHex(ciphertextEnd));
    }

    @Test
    public void decryptTest(){


    }

}
