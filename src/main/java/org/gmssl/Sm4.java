/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm4 {

	public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
	public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

	public static final int ENCRYPT_MODE = 1;
	public static final int DECRYPT_MODE = 0;

	private long sm4_key = 0;

	public Sm4(byte[] key, int mode) {
		sm4_key = GmSSLJNI.sm4_key_new();
		if (mode == DECRYPT_MODE) {
			GmSSLJNI.sm4_set_decrypt_key(sm4_key, key);
		} else {
			GmSSLJNI.sm4_set_encrypt_key(sm4_key, key);
		}
	}

	public void encrypt(byte[] in, int in_offset, byte[] out, int out_offset) {
		GmSSLJNI.sm4_encrypt(sm4_key, in, in_offset, out, out_offset);
	}
}
