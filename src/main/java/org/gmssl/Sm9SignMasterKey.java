/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm9SignMasterKey {

	public static final int NOT_INITED = 0;
	public static final int PUBLIC_KEY = 1;
	public static final int PRIVATE_KEY = 3;

	private long master_key = 0;
	private int state = 0;

	public Sm9SignMasterKey() {
		state = NOT_INITED;
	}

	public void generateMasterKey() {
		master_key = GmSSLJNI.sm9_sign_master_key_generate();
		state = PRIVATE_KEY;
	}

	public long getMasterKey() {
		return master_key;
	}

	public Sm9SignKey extractKey(String id) {
		long key = GmSSLJNI.sm9_sign_master_key_extract_key(master_key, id);
		return new Sm9SignKey(key, id);
	}

	public void importEncryptedMasterKeyInfoPem(String pass, String file) {
		master_key = GmSSLJNI.sm9_sign_master_key_info_decrypt_from_pem(pass, file);
		state = PRIVATE_KEY;
	}

	public void exportEncryptedMasterKeyInfoPem(String pass, String file) {
		if (state != PRIVATE_KEY && state != PUBLIC_KEY) {
			throw new GmSSLJNIException("Private master key not initialized");
		}
		GmSSLJNI.sm9_sign_master_key_info_encrypt_to_pem(master_key, pass, file);
	}

	public void importPublicMasterKeyPem(String file) {
		master_key = GmSSLJNI.sm9_sign_master_public_key_from_pem(file);
		state = PUBLIC_KEY;
	}

	public void exportPublicMasterKeyPem(String file) {
		if (state != PRIVATE_KEY && state != PUBLIC_KEY) {
			throw new GmSSLJNIException("Private master key not initialized");
		}
		GmSSLJNI.sm9_sign_master_public_key_to_pem(master_key, file);
	}
}
