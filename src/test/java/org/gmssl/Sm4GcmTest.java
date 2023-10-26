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
 * @date 2023/09/26
 * @description Sm4Gcm unit test.
 * In SM4 GCM mode, GCM provides both encryption and authentication functionalities.
 * Encryption is performed using the SM4 algorithm, while authentication is provided by the GCM mode through message authentication codes.
 * Additionally, GCM offers additional data integrity checks to detect if the data has been tampered with.
 */
public class Sm4GcmTest {

    Sm4Gcm sm4gcm;
    byte[] key ,iv ;
    int taglen;
    byte[] aad;

    @Before
    public void beforeTest(){
        sm4gcm=new Sm4Gcm();
        key=new byte[]{52, -63, -74, 123, 75, -42, -109, -94, -108, -35, 117, -70, 95, 126, -71, 6};
        iv=new byte[]{-97, -42, 38, -65, 37, -75, -26, -119, -19, 124, -116, -27};
        taglen=Sm4Gcm.MAX_TAG_SIZE;
        aad = "Hello: ".getBytes();
    }

    /**
     * sm4Gcm encrypt
     * GCM operates on fixed size blocks (usually 128 bits), unlike other encryption modes such as CBC or ECB that require padding.
     */
    @Test
    public void encryptTest(){
        String testStr="gmssl";
        byte[] palaintextByte=testStr.getBytes();
        int blockLength= (int)Math.ceil((palaintextByte.length+taglen)/(double)Sm4.BLOCK_SIZE);
        byte[] tempCiphertextByte=new byte[blockLength*Sm4.BLOCK_SIZE];
        int cipherlen;
        sm4gcm.init(key, iv, aad, taglen, true);
        cipherlen = sm4gcm.update(palaintextByte, 0, palaintextByte.length, tempCiphertextByte, 0);
        cipherlen += sm4gcm.doFinal(tempCiphertextByte, cipherlen);
        byte[] ciphertextByte = Arrays.copyOfRange(tempCiphertextByte,0,cipherlen);
        //System.out.println("ciphertext:"+HexUtil.byteToHex(ciphertextByte));
        Assert.assertNotNull("data is empty exception!",ciphertextByte);
    }

    @Test
    public void decryptTest(){
        String test_plaintext="gmssl";
        String test_hex_ciphertext="b4a20037dc223f3e3474304dbb464a86423fa6c6db";
        byte[] ciphertextByte=HexUtil.hexToByte(test_hex_ciphertext);
        byte[] tempPlaintextByte = new byte[ciphertextByte.length+taglen];
        sm4gcm.init(key, iv, aad, taglen, false);
        int plainlen = sm4gcm.update(ciphertextByte, 0, ciphertextByte.length, tempPlaintextByte, 0);
        plainlen += sm4gcm.doFinal(tempPlaintextByte, plainlen);
        byte[] plaintextByte = Arrays.copyOfRange(tempPlaintextByte,0,plainlen);
        String plaintext=new String(plaintextByte);
        //System.out.println("plaintext:"+plaintext);
        Assert.assertEquals("original value is not equal to the expected value after decryption!",plaintext,test_plaintext);
    }

}

