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
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author yongfei.li
 * @email 290836576@qq.com
 * @date 2023/09/12
 * @description zuc unit test
 */
public class ZucTest {

    Random rng = new Random();
    byte[] key = rng.randBytes(Zuc.KEY_SIZE);
    byte[] iv = rng.randBytes(Zuc.IV_SIZE);
    static Zuc zuc;


    @BeforeClass
    public static void beforeClass() throws Exception {
        zuc = new Zuc();
    }

    /**
     * encryption unit test
     */
    @Test
    public void encryptTest(){
        byte[] ciphertext = new byte[32];

        int cipherlen;

        zuc.init(key, iv);
        cipherlen = zuc.update("abc".getBytes(), 0, 3, ciphertext, 0);
        cipherlen += zuc.doFinal(ciphertext, cipherlen);

        //System.out.print("ciphertext : ");
        byte[] ciphertextEnd = new byte[cipherlen];
        for (int i = 0; i < cipherlen; i++) {
            //System.out.printf("%02x", ciphertext[i]);
            ciphertextEnd[i]=ciphertext[i];
        }
        String ciphertextHex= HexUtil.byteToHex(ciphertextEnd);
        //System.out.println(ciphertextHex);
        Assert.assertNotNull("数据为空异常",ciphertextHex);
    }

    /**
     * decryption unit test
     */
    @Test
    public void decryptTest(){
        String plaintextStr="abc";

        key=new byte[]{-58, -106, -55, 98, -75, 49, -74, -101, -50, 1, -79, 43, -33, -86, -57, -106};
        iv=new byte[]{-119, 19, 24, 45, 83, 17, -89, 102, -72, -104, 91, -31, -25, -109, -28, 30};
        int cipherlen=3;
        int plainlen;
        byte[] ciphertext=new byte[]{-105, -90, -115, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] plaintext = new byte[32];

        zuc.init(key, iv);
        plainlen = zuc.update(ciphertext, 0, cipherlen, plaintext, 0);
        plainlen += zuc.doFinal(plaintext, plainlen);

        //System.out.print("plaintext : ");
        byte[] plaintextEnd = new byte[plainlen];
        for (int i = 0; i < plainlen; i++) {
            //System.out.printf("%02x", plaintext[i]);
            plaintextEnd[i]=plaintext[i];
        }
        //System.out.println(new String(plaintextEnd));
        Assert.assertEquals(plaintextStr,new String(plaintextEnd));
    }


}
