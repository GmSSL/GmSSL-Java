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
 * @date 2023/09/07
 * @description Sm2 unit test
 */
public class Sm2Test {

    Sm2Key sm2_key=null;

    @Before
    public void beforeTest(){
        sm2_key = new Sm2Key();
        sm2_key.generateKey();
    }

    @Test
    public void computeZTest(){
        byte[] z = sm2_key.computeZ(Sm2Key.DEFAULT_ID);

        String hexZ= HexUtil.byteToHex(z);
        //System.out.println("z:"+hexZ);
        Assert.assertNotNull("数据为空异常",hexZ);
    }

    @Test
    public void verifyTest(){
        Random rng = new Random();
        byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
        byte[] sig = sm2_key.sign(dgst);
        boolean verify_ret = sm2_key.verify(dgst, sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("数据不为真异常",verify_ret);
    }

    @Test
    public void encryptAndDecryptTest(){
        String testStr="gmssl";
        byte[] ciphertext = sm2_key.encrypt(testStr.getBytes());
        byte[] plaintext = sm2_key.decrypt(ciphertext);
        String originalStr= new String(plaintext);
        //System.out.printf("Plaintext : "+originalStr);
        Assert.assertEquals("原值与加解密后期望值不相等异常",testStr,originalStr);
    }

    @Test
    public void verifySignatureTest(){
        String testStr="gmssl";
        Sm2Signature sign = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, true);
        sign.update(testStr.getBytes());
        byte[] sig = sign.sign();

        Sm2Signature verify = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, false);
        verify.update(testStr.getBytes());
        boolean verify_ret = verify.verify(sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("数据不为真异常",verify_ret);
    }

}
