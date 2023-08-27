/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm2Key {

	public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM2_MAX_PLAINTEXT_SIZE;
	public static final int NOT_INITED = 0;
	public static final int PUBLIC_KEY = 1;
	public static final int PRIVATE_KEY = 3;

	private long sm2_key = 0;
	private int state = 0;

	public Sm2Key() {
		state = NOT_INITED;
	}

	public void generateKey() {
		sm2_key = GmSSLJNI.sm2_key_generate();
		state = PRIVATE_KEY;
	}

	public long getKey() {
		return sm2_key;
	}

	public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (state != PRIVATE_KEY) {
			throw new GmSSLJNIException("Private key not initialized");
		}
		GmSSLJNI.sm2_private_key_info_encrypt_to_pem(sm2_key, pass, file);
	}

	public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
		sm2_key = GmSSLJNI.sm2_private_key_info_decrypt_from_pem(pass, file);
		if (sm2_key == 0) {
			throw new GmSSLJNIException("Import failure");
		}
	}

	public void exportPublicKeyInfoPem(String file) {
		if (state != PRIVATE_KEY && state != PUBLIC_KEY) {
			throw new GmSSLJNIException("Public key not initialized");
		}
		GmSSLJNI.sm2_public_key_info_to_pem(sm2_key, file);
	}

	public void importPublicKeyInfoPem(String file) {
		sm2_key = GmSSLJNI.sm2_public_key_info_from_pem(file);
		if (sm2_key == 0) {
			throw new GmSSLJNIException("Import failure");
		}
	}

	public byte[] computeZ(String id) {
		byte[] z = new byte[Sm3.DIGEST_SIZE];
		GmSSLJNI.sm2_compute_z(sm2_key, id, z);
		return z;
	}

	public byte[] sign(byte[] dgst) {
		return GmSSLJNI.sm2_sign(sm2_key, dgst);
	}

	public boolean verify(byte[] dgst, byte[] signature) {
		int ret = GmSSLJNI.sm2_verify(sm2_key, dgst, signature);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}

	public byte[] encrypt(byte[] plaintext) {
		return GmSSLJNI.sm2_encrypt(sm2_key, plaintext);
	}

	public byte[] decrypt(byte[] ciphertext) {
		return GmSSLJNI.sm2_decrypt(sm2_key, ciphertext);
	}
}
