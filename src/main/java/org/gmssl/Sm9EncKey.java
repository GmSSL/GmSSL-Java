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

	Sm9EncKey(long key, String id) {
		this.sm9_enc_key = key;
		this.id = id;
	}

	public Sm9EncKey(String id) {
		this.sm9_enc_key = 0;
		this.id = id;
	}

	public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm9_enc_key != 0) {
			GmSSLJNI.sm9_enc_key_free(this.sm9_enc_key);
		}
		if ((this.sm9_enc_key = GmSSLJNI.sm9_enc_key_info_decrypt_from_pem(pass, file)) == 0) {
			throw new GmSSLException("");
		}
	}

	public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm9_enc_key == 0) {
			throw new GmSSLException("Key not initialized");
		}
		if (GmSSLJNI.sm9_enc_key_info_encrypt_to_pem(this.sm9_enc_key, pass, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public String getId() {
		return this.id;
	}

	public byte[] decrypt(byte[] ciphertext) {
		if (this.sm9_enc_key == 0) {
			throw new GmSSLException("");
		}
		if (ciphertext == null) {
			throw new GmSSLException("");
		}

		byte[] plaintext;
		if ((plaintext = GmSSLJNI.sm9_decrypt(this.sm9_enc_key, this.id, ciphertext)) == null) {
			throw new GmSSLException("");
		}
		return plaintext;
	}
}
