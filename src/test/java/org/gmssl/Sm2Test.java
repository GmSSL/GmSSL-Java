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

    Sm2Key sm2_key;

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
        Assert.assertNotNull("data is empty exception!",hexZ);
    }

    @Test
    public void verifyTest(){
        Random rng = new Random();
        byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
        byte[] sig = sm2_key.sign(dgst);
        boolean verify_ret = sm2_key.verify(dgst, sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);
    }

    @Test
    public void encryptTest(){
        String testStr="gmssl";
        byte[] ciphertext = sm2_key.encrypt(testStr.getBytes());

        System.out.println("ciphertext : "+HexUtil.byteToHex(ciphertext));
        Assert.assertNotNull("data is empty exception!",ciphertext);
    }

    //@Test
    public void decryptTest(){
        String ciphertextHex="306e022100ebf23c4b85c461a6fbe33cfb9d81b96edad432f07be2f293b7a7ea027ee65dfd02201b903f2694cc614fb445f2968861f1c017844db5162fe4e55477ec167fd04e78042088513b72d6f7fdb4532cf0684f5bb15c505263559fb38de1694cb2951b9adc2d0405f7b6bf4c18";
        byte[] ciphertext = HexUtil.hexToByte(ciphertextHex);
        byte[] plaintext = sm2_key.decrypt(ciphertext);
        //TODO 加密和解密放到一起连续执行能够成功，拆带单独执行有问题
        String plaintextStr= new String(plaintext);
        System.out.printf("Plaintext : "+plaintextStr);
        Assert.assertEquals("The original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }

    @Test
    public void signatureTest(){
        String signatureContentStr="gmssl";
        Sm2Signature sign = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, true);
        sign.update(signatureContentStr.getBytes());
        byte[] sig = sign.sign();
        String sigHex = HexUtil.byteToHex(sig);
        System.out.println("sig : "+sigHex);
        Assert.assertNotNull("data is empty exception!",sig);
    }

    //@Test
    public void verifySignatureTest(){
        String signatureContentStr = "gmssl";
        String signatureContentHex = "304402207ad7865844e3e798525c084b83ec9d5318b4e3551190f65d4160ef82c280ccb802204097283db2652c74520b4f29bf80d70bf922115a2e148825613c2dd4603fd970";
        byte[] sig=HexUtil.hexToByte(signatureContentHex);
        //TODO fix 签名和验签的方法放到一起连续执行能执行，拆开单独执行有问题
        Sm2Signature verify = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, false);
        verify.update(signatureContentStr.getBytes());
        boolean verify_ret = verify.verify(sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);
    }


    public static void main(String[] args) {
        int i;

        Sm2Key sm2_key = new Sm2Key();

        sm2_key.generateKey();

        byte[] privateKeyInfo = sm2_key.exportPrivateKeyInfoDer();
        System.out.printf("PrivateKeyInfo: ");
        for (i = 0; i < privateKeyInfo.length; i++) {
            System.out.printf("%02x", privateKeyInfo[i]);
        }
        System.out.print("\n");

        byte[] publicKeyInfo = sm2_key.exportPublicKeyInfoDer();
        System.out.printf("PrivateKeyInfo: ");
        for (i = 0; i < publicKeyInfo.length; i++) {
            System.out.printf("%02x", publicKeyInfo[i]);
        }
        System.out.print("\n");


        Sm2Key priKey = new Sm2Key();
        priKey.importPrivateKeyInfoDer(privateKeyInfo);

        Sm2Key pubKey = new Sm2Key();
        pubKey.importPublicKeyInfoDer(publicKeyInfo);

        priKey.exportEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
        pubKey.exportPublicKeyInfoPem("sm2pub.pem");

        priKey.importEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
        pubKey.importPublicKeyInfoPem("sm2pub.pem");


        byte[] z = pubKey.computeZ(Sm2Key.DEFAULT_ID);

        System.out.printf("Z: ");
        for (i = 0; i < z.length; i++) {
            System.out.printf("%02x", z[i]);
        }
        System.out.print("\n");


        Random rng = new Random();
        byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
        byte[] sig = priKey.sign(dgst);
        boolean verify_ret = pubKey.verify(dgst, sig);
        System.out.println("Verify result = " + verify_ret);

        byte[] ciphertext = pubKey.encrypt("abc".getBytes());
        byte[] plaintext = priKey.decrypt(ciphertext);
        System.out.printf("Plaintext : ");
        for (i = 0; i < plaintext.length; i++) {
            System.out.printf("%02x", plaintext[i]);
        }
        System.out.print("\n");

        Sm2Signature sign = new Sm2Signature(priKey, Sm2Key.DEFAULT_ID, true);
        sign.update("abc".getBytes());
        sig = sign.sign();

        Sm2Signature verify = new Sm2Signature(pubKey, Sm2Key.DEFAULT_ID, false);
        verify.update("abc".getBytes());
        verify_ret = verify.verify(sig);
        System.out.println("Verify result = " + verify_ret);

    }

}
