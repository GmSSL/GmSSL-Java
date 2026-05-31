/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.digest;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/09/07
 * @description
 * PBKDF2 is one of the secure and widely used PBKDF algorithm standards. The algorithm uses a hash function as the primary component to map passwords to keys.
 * It employs a random and public salt value (Salt) to resist precomputation attacks, increases the difficulty of online cracking by adding multiple rounds of iterative computation, and supports variable derived key lengths.
 */
public class SM3Pbkdf2 extends SecretKeyFactorySpi {

    public final static int MAX_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_SALT_SIZE;
    public final static int DEFAULT_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_DEFAULT_SALT_SIZE;
    public final static int MIN_ITER = GmSSLJNI.SM3_PBKDF2_MIN_ITER;
    public final static int MAX_ITER = GmSSLJNI.SM3_PBKDF2_MAX_ITER;
    public final static int MAX_KEY_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_KEY_SIZE;

    public final static String ALGORITHM = "SM3Pbkdf2";

    public SM3Pbkdf2() {
        super();
    }

    /**
     *
     * @param keySpec PBEKeySpec the specification (key material) of the secret key
     * pass is the user password used for deriving the key.
     * salt is the value used to resist precomputation attacks. This value should be randomly generated (for example, using the Random class) and should have a certain length.
     * The iter parameter represents the number of times the SM3 algorithm is called iteratively when deriving the key. A larger iter value increases the difficulty of brute-force attacks but also increases the computational overhead for users calling this function.
     * The keylen parameter indicates the desired length of the derived key, which must not exceed the constant MAX_KEY_SIZE.
     * @return
     * @throws InvalidKeySpecException
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new GmSSLException("Invalid KeySpec");
        }
        PBEKeySpec pbeKeySpec = (PBEKeySpec) keySpec;
        char[] password = pbeKeySpec.getPassword();
        byte[] salt = pbeKeySpec.getSalt();
        int iterations = pbeKeySpec.getIterationCount();
        int derivedKeyLength = pbeKeySpec.getKeyLength();
        byte[] key = deriveKey(new String(password), salt, iterations, derivedKeyLength);
        return new SecretKeySpec(key, ALGORITHM);
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        throw new GmSSLException("Not supported");
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        throw new GmSSLException("Not supported");
    }

    private byte[] deriveKey(String pass, byte[] salt, int iter, int keylen) {
        if (pass == null) {
            throw new GmSSLException("");
        }
        if (salt == null || salt.length > MAX_SALT_SIZE) {
            throw new GmSSLException("");
        }
        if (iter < MIN_ITER || iter > MAX_ITER) {
            throw new GmSSLException("");
        }
        if (keylen < 0 || keylen > MAX_KEY_SIZE) {
            throw new GmSSLException("");
        }
        byte[] key = GmSSLJNI.sm3_pbkdf2(pass, salt, iter, keylen);
        if (key == null) {
            throw new GmSSLException("");
        }
        return key;
    }
}
