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
    byte[] privateKeyInfo;
    byte[] publicKeyInfo;
    Sm2Key priKey,pubKey;
    byte[] dgst;

    @Before
    public void beforeTest(){
        sm2_key = new Sm2Key();
        sm2_key.generateKey();

        //byte[] privateKeyInfo=sm2_key.exportPrivateKeyInfoDer();
        String privateKeyInfoHex="308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104207fef3e258348873c47117c15093266e9dad99e131f1778e53d362b2b70649f85a00a06082a811ccf5501822da14403420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
        privateKeyInfo = HexUtil.hexToByte(privateKeyInfoHex);

        //byte[] publicKeyInfo = sm2_key.exportPublicKeyInfoDer();
        String publicKeyInfoHex = "3059301306072a8648ce3d020106082a811ccf5501822d03420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
        publicKeyInfo = HexUtil.hexToByte(publicKeyInfoHex);

        priKey = new Sm2Key();
        priKey.importPrivateKeyInfoDer(privateKeyInfo);
        priKey.exportEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
        priKey.importEncryptedPrivateKeyInfoPem("Password", "sm2.pem");

        pubKey = new Sm2Key();
        pubKey.importPublicKeyInfoDer(publicKeyInfo);
        pubKey.exportPublicKeyInfoPem("sm2.pem");
        pubKey.importPublicKeyInfoPem("sm2.pem");

        //byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
        String dgstHex="372a28b963da9733515640f163dd017ae8544cafa78097d5765e4169348c030b";
        dgst=HexUtil.hexToByte(dgstHex);

    }

    @Test
    public void computeZTest(){
        byte[] z = pubKey.computeZ(Sm2Key.DEFAULT_ID);

        String hexZ= HexUtil.byteToHex(z);
        //System.out.println("z:"+hexZ);
        Assert.assertNotNull("data is empty exception!",hexZ);
    }

    @Test
    public void signTest(){
        byte[] sig = priKey.sign(dgst);
        String sigHex = HexUtil.byteToHex(sig);
        //System.out.println("sigHex : "+sigHex);
        Assert.assertNotNull("data is empty exception!",sig);
    }

    @Test
    public void verifySignTest(){
        String sigHex="3046022100c2a92338bf430b0bd1ed68ea9910168cbd6bbb6f8de0992e1350e894296273b1022100e4814ac9ea6dab86334f47b2de6122923a0abbb7ec0687a2a1974773eb9a9542";
        byte[] sig=HexUtil.hexToByte(sigHex);

        boolean verify_ret = pubKey.verify(dgst, sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);
    }

    @Test
    public void encryptTest(){
        String testStr="gmssl";

        byte[] ciphertext = pubKey.encrypt(testStr.getBytes());
        //System.out.println("ciphertext : "+HexUtil.byteToHex(ciphertext));
        Assert.assertNotNull("data is empty exception!",ciphertext);
    }

    @Test
    public void decryptTest(){
        String ciphertextHex="306e022100d5d193d99876b6b2a2456356c09db06074aceb3ad6ae736d415d6988bdd4392902207ffbef363ae9584703d10b799609aff0fcb7a026b04aeec14021c9e12d22d2470420bbcc0a0bd07ffde6d0f5d5ee6e81eb47debbd9c6c0fca55107b1891cea29f742040526af292b75";
        byte[] ciphertext = HexUtil.hexToByte(ciphertextHex);

        byte[] plaintext = priKey.decrypt(ciphertext);
        String plaintextStr= new String(plaintext);
        //System.out.printf("Plaintext : "+plaintextStr);
        Assert.assertEquals("The original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }

    @Test
    public void signatureTest(){
        String signatureContentStr="gmssl";

        Sm2Signature sign = new Sm2Signature(priKey, Sm2Key.DEFAULT_ID, true);
        sign.update(signatureContentStr.getBytes());
        byte[] sig = sign.sign();
        String sigHex = HexUtil.byteToHex(sig);
        //System.out.println("signatureContentHex : "+sigHex);
        Assert.assertNotNull("data is empty exception!",sig);
    }

    @Test
    public void verifySignatureTest(){
        String signatureContentStr = "gmssl";
        String signatureContentHex = "3046022100cf526564d0964225f857856bc6ef181df5fcf1c87d630ccf6b992d4371772ed3022100915a309279e90ed00a02e84617991aaf1baa70586cc6cce395e52b7105bb73fa";
        byte[] sig=HexUtil.hexToByte(signatureContentHex);

        Sm2Signature verify = new Sm2Signature(pubKey, Sm2Key.DEFAULT_ID, false);
        verify.update(signatureContentStr.getBytes());
        boolean verify_ret = verify.verify(sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);
    }

}
