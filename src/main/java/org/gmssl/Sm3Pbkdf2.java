/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm3Pbkdf2 {

	public final static int MAX_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_SALT_SIZE;
	public final static int DEFAULT_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_DEFAULT_SALT_SIZE;
	public final static int MIN_ITER = GmSSLJNI.SM3_PBKDF2_MIN_ITER;
	public final static int MAX_ITER = GmSSLJNI.SM3_PBKDF2_MAX_ITER;
	public final static int MAX_KEY_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_KEY_SIZE;

	public Sm3Pbkdf2() {
	}

	public byte[] deriveKey(String pass, byte[] salt, int iter, int keylen) {
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
