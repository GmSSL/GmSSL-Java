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
import org.junit.Test;

import java.util.Map;

/**
 * @author yongfei.li
 * @email 290836576@qq.com
 * @date 2023/10/20
 * @description sm9 unit test
 */
public class Sm9Test {


    @Test
    public void signTest() {
        String singContentStr = "gmssl";
        byte[] singContent = singContentStr.getBytes();
        Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
        sign_master_key.generateMasterKey();
        Sm9SignKey sign_key = sign_master_key.extractKey("Alice");

        Sm9Signature sign = new Sm9Signature(true);
        sign.update(singContent);
        byte[] sig = sign.sign(sign_key);
        String hexSig = HexUtil.byteToHex(sig);

        System.out.println(hexSig);
        Assert.assertNotNull("data is empty exception!",hexSig);
    }

    //@Test
    public void verifyTest(){
        String  hexSig="3066042016d5e5e3c95bc4e6d865917f6ac8d07aac3ad66cc5c99c99bbe2a66572f53e4403420004970928485c4ad22b932d960633444560a21191cad0d931eba09bbcc6964596bfa395f20e1e94d0e97defbfeafc31ad695e443bc4151c9ac8b69277b43b8ac597";
        byte[] sig=HexUtil.hexToByte(hexSig);
        String singContentStr = "gmssl";
        byte[] singContent = singContentStr.getBytes();

        //Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
        //sign_master_key.generateMasterKey();
        //sign_master_key.exportPublicMasterKeyPem("sm9sign.mpk");
        //TODO 方法执行报错，和签名方法放到一起连续执行可以，怀疑必须是同一个内存对象或参数问题
        Sm9SignMasterKey sign_master_pub_key = new Sm9SignMasterKey();
        sign_master_pub_key.importPublicMasterKeyPem("sm9sign.mpk");

        Sm9Signature verify = new Sm9Signature(false);
        verify.update(singContent);
        boolean verify_ret = verify.verify(sig, sign_master_pub_key, "Alice");

        System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);
    }

    @Test
    public void encryptTest(){
        String plaintextStr = "gmssl";
        byte[] plaintext = plaintextStr.getBytes();
        Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
        enc_master_key.generateMasterKey();

        //enc_master_key.exportPublicMasterKeyPem("sm9enc.mpk");
        Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
        enc_master_pub_key.importPublicMasterKeyPem("sm9enc.mpk");

        byte[] ciphertext = enc_master_pub_key.encrypt(plaintext, "Bob");
        String ciphertextHex=HexUtil.byteToHex(ciphertext);

        System.out.println(ciphertextHex);
        Assert.assertNotNull("data is empty exception!",ciphertextHex);
    }

    //@Test
    public void decryptTest(){
        String ciphertextHex="3070020100034200049718c02b7f61b714fd7b23251cfbd617909ff5e123c15762cb709052d697318742deef3dd6bb98782f80f88f4167d96c684f9460cdbb9eaedf3550ceae588c9004204245245ad278bf17a188604955d2716390736456c4bf1b664d2e025ff043b90204058f67a1a225";
        byte[] ciphertext=HexUtil.hexToByte(ciphertextHex);

        Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
        //enc_master_key.generateMasterKey();

        //enc_master_key.exportPublicMasterKeyPem("sm9enc.mpk");
        //Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
        //enc_master_pub_key.importPublicMasterKeyPem("sm9enc.mpk");
       //TODO 方法执行报错，和解密方法放到一起连续执行可以，怀疑必须是同一个内存对象或参数问题
        Sm9EncKey enc_key = enc_master_key.extractKey("Bob");
        byte[] plaintext = enc_key.decrypt(ciphertext);

        String plaintextStr = new String(plaintext);
        System.out.print("plaintext:"+plaintextStr);
        Assert.assertEquals("The original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }

    public static void main(String[] args) {
        Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
        sign_master_key.generateMasterKey();

        Sm9SignKey sign_key = sign_master_key.extractKey("Alice");

        Sm9Signature sign = new Sm9Signature(true);
        sign.update("abc".getBytes());
        byte[] sig = sign.sign(sign_key);


        //-------------------
        //String hexSig = HexUtil.byteToHex(sig);
        String hexSig ="30660420023667f3b3ccf1cdd59980a82c96630486ebef8a8e18928aad2b9bc3232b9c2c03420004aa4ee1834a3496ae6fabb494ac3a1302a69a730dd24f9cf53227c100be574eb92121925044d04fec7635c23698afc03e82cf1195b3f73520d23af5d4e9ebc8b1";
        System.out.println(hexSig);
        byte[] sig1=HexUtil.hexToByte(hexSig);

        //-------------------------



        sign_master_key.exportPublicMasterKeyPem("sm9sign.mpk");
        Sm9SignMasterKey sign_master_pub_key = new Sm9SignMasterKey();
        sign_master_pub_key.importPublicMasterKeyPem("sm9sign.mpk");

        Sm9Signature verify = new Sm9Signature(false);
        verify.update("abc".getBytes());
        boolean verify_ret = verify.verify(sig, sign_master_pub_key, "Alice");
        System.out.println("Verify result = " + verify_ret);

        Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
        enc_master_key.generateMasterKey();

        enc_master_key.exportPublicMasterKeyPem("sm9enc.mpk");
        Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
        enc_master_pub_key.importPublicMasterKeyPem("sm9enc.mpk");

        byte[] ciphertext = enc_master_pub_key.encrypt("abc".getBytes(), "Bob");

        Sm9EncKey enc_key = enc_master_key.extractKey("Bob");
        byte[] plaintext = enc_key.decrypt(ciphertext);
        int i;
        System.out.printf("plaintext: ");
        for (i = 0; i < plaintext.length; i++) {
            System.out.printf("%02x", plaintext[i]);
        }
        System.out.print("\n");
    }
}
