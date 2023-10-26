/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl;


import org.junit.Test;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2023/10/20
 * @description Sm3Pbkdf2 unit test
 */
public class Sm3Pbkdf2Test {

    /**
     * PBKDF2 (Password-Based Key Derivation Function 2) is a cryptographic algorithm used to derive a key from a password.
     * It employs a pseudorandom function to generate the key, and the length of the derived key can be arbitrarily chosen. However, PBKDF2 allows for multiple iterations of the computation to further enhance security.
     * By incorporating a salt value (random data) along with the plaintext password, PBKDF2 generates a salted key, which greatly improves resistance against attacks like rainbow table attacks.
     */
    //@Test
    public void deriveKeyTest(){
        Sm3Pbkdf2 kdf = new Sm3Pbkdf2();

        Random rng = new Random();
        byte[] salt = rng.randBytes(Sm3Pbkdf2.DEFAULT_SALT_SIZE);

        String pass = "P@ssw0rd";
        byte[] key = kdf.deriveKey(pass, salt, Sm3Pbkdf2.MIN_ITER * 2, 16);
        //TODO fix 链接c库异常，可能是C库未找到匹配的方法. 报错信息：Exception in thread "main" java.lang.UnsatisfiedLinkError: 'byte[] org.gmssl.GmSSLJNI.sm3_pbkdf2(java.lang.String, byte[], int, int)'
        String keyHexStr = HexUtil.byteToHex(key);
        System.out.println(keyHexStr);
    }


    public static void main(String[] args) {

        Sm3Pbkdf2 kdf = new Sm3Pbkdf2();

        Random rng = new Random();
        byte[] salt = rng.randBytes(Sm3Pbkdf2.DEFAULT_SALT_SIZE);

        String pass = "P@ssw0rd";
        byte[] key = kdf.deriveKey(pass, salt, Sm3Pbkdf2.MIN_ITER * 2, 16);
        //TODO fix
        //没有对应到方法
        //Exception in thread "main" java.lang.UnsatisfiedLinkError: 'byte[] org.gmssl.GmSSLJNI.sm3_pbkdf2(java.lang.String, byte[], int, int)'

        int i;
        System.out.printf("pbkdf2(pass, salt, iter, keylen): ");
        for (i = 0; i < key.length; i++) {
            System.out.printf("%02x", key[i]);
        }
        System.out.print("\n");
    }
}
