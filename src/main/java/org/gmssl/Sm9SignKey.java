/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm9SignKey {

	private long sm9_sign_key = 0;
	private String id;

	Sm9SignKey(long key, String id) {
		this.sm9_sign_key = key;
		this.id = id;
	}

	public Sm9SignKey(String id) {
		this.sm9_sign_key = 0;
		this.id = id;
	}

	long getKey() {
		if (this.sm9_sign_key == 0) {
			throw new GmSSLException("");
		}
		return this.sm9_sign_key;
	}

	public String getId() {
		return this.id;
	}

	public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm9_sign_key == 0) {
			throw new GmSSLException("Key not initialized");
		}
		if (GmSSLJNI.sm9_sign_key_info_encrypt_to_pem(this.sm9_sign_key, pass, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm9_sign_key != 0) {
			GmSSLJNI.sm9_sign_key_free(this.sm9_sign_key);
		}
		if ((this.sm9_sign_key = GmSSLJNI.sm9_sign_key_info_decrypt_from_pem(pass, file)) == 0) {
			throw new GmSSLException("Import key failure");
		}
	}
}
