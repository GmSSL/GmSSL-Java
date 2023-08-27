/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm9EncKey {

	private long sm9_enc_key = 0;
	private String id;

	public Sm9EncKey(String id) {
		this.id = id;
	}

	public Sm9EncKey(long key, String id) {
		this.sm9_enc_key = key;
		this.id = id;
	}

	public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
		sm9_enc_key = GmSSLJNI.sm9_enc_key_info_decrypt_from_pem(pass, file);
		if (sm9_enc_key == 0) {
			throw new GmSSLJNIException("Import key failure");
		}
	}

	public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (sm9_enc_key == 0) {
			throw new GmSSLJNIException("Key not initialized");
		}
		GmSSLJNI.sm9_enc_key_info_encrypt_to_pem(sm9_enc_key, pass, file);
	}

	public byte[] decrypt(byte[] ciphertext) {
		return GmSSLJNI.sm9_decrypt(sm9_enc_key, id, ciphertext);
	}
}
