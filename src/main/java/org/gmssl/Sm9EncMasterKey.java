/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;


public class Sm9EncMasterKey {

	public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM9_MAX_PLAINTEXT_SIZE;

	private long master_key = 0;
	private boolean has_private_key = false;

	public Sm9EncMasterKey() {
		this.master_key = 0;
	}

	public void generateMasterKey() {
		if (this.master_key != 0) {
			GmSSLJNI.sm9_enc_master_key_free(this.master_key);
		}
		if ((this.master_key = GmSSLJNI.sm9_enc_master_key_generate()) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = true;
	}

	public long getMasterKey() {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		return this.master_key;
	}

	public long getPublicMasterKey() {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		return this.master_key;
	}

	public Sm9EncKey extractKey(String id) {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		long key;
		if ((key = GmSSLJNI.sm9_enc_master_key_extract_key(this.master_key, id)) == 0) {
			throw new GmSSLException("");
		}
		return new Sm9EncKey(key, id);
	}

	public void importEncryptedMasterKeyInfoPem(String pass, String file) {
		if (this.master_key != 0) {
			GmSSLJNI.sm9_enc_master_key_free(this.master_key);
		}
		if ((this.master_key = GmSSLJNI.sm9_enc_master_key_info_decrypt_from_pem(pass, file)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = true;
	}

	public void exportEncryptedMasterKeyInfoPem(String pass, String file) {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm9_enc_master_key_info_encrypt_to_pem(this.master_key, pass, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public void importPublicMasterKeyPem(String file) {
		if (this.master_key != 0) {
			GmSSLJNI.sm9_enc_master_key_free(this.master_key);
		}
		if ((this.master_key = GmSSLJNI.sm9_enc_master_public_key_from_pem(file)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = false;
	}

	public void exportPublicMasterKeyPem(String file) {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm9_enc_master_public_key_to_pem(this.master_key, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public byte[] encrypt(byte[] plaintext, String id) {
		if (this.master_key == 0) {
			throw new GmSSLException("");
		}
		if (plaintext == null
			|| plaintext.length > this.MAX_PLAINTEXT_SIZE) {
			throw new GmSSLException("");
		}

		byte[] ciphertext;
		if ((ciphertext = GmSSLJNI.sm9_encrypt(this.master_key, id, plaintext)) == null) {
			throw new GmSSLException("");
		}
		return ciphertext;
	}
}
