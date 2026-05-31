/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto;

import java.security.Provider;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 * GmSSL-Java currently provides functionality for random number generation, SM3 hash, SM3 message authentication code (HMAC-SM3),
 * SM4 encryption (including block encryption and CBC/CTR/GCM encryption modes), ZUC encryption, SM2 encryption/signature, SM9 encryption/signature, and SM2 certificate parsing.
 * These features cover the main application development scenarios for the current Chinese cryptographic algorithms.
 */
public class GmSSLProvider extends Provider {

    public GmSSLProvider() {
        super("GmSSL", "3.1.1", "GmSSL Provider");

        put("SecureRandom.Random", "org.gmssl.crypto.Random");
        put("Cipher.SM2", "org.gmssl.crypto.asymmetric.SM2Cipher");
        put("KeyPairGenerator.SM2", "org.gmssl.crypto.asymmetric.SM2KeyPairGenerator");
        put("Signature.SM2", "org.gmssl.crypto.asymmetric.SM2Signature");
        put("MessageDigest.SM3", "org.gmssl.crypto.digest.SM3Digest");
        put("Mac.SM3", "org.gmssl.crypto.digest.SM3Hmac");
        put("SecretKeyFactory.SM3Pbkdf2", "org.gmssl.crypto.digest.SM3Pbkdf2");
        put("Cipher.SM4", "org.gmssl.crypto.symmetric.SM4Cipher");
        put("Cipher.SM9", "org.gmssl.crypto.asymmetric.SM9Cipher");
        put("Signature.SM9", "org.gmssl.crypto.asymmetric.SM9Signature");
        put("KeyPairGenerator.SM9", "org.gmssl.crypto.asymmetric.SM9KeyPairGeneratorSpi");
        put("Cipher.ZUC", "org.gmssl.crypto.symmetric.ZucCipher");
    }


}
