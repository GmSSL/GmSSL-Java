/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm4Cbc {

	public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
	public final static int IV_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

	public static final int ENCRYPT_MODE = 1;
	public static final int DECRYPT_MODE = 0;

	private long sm4_cbc_ctx = 0;
	private int mode;

	public Sm4Cbc(byte[] key, byte[] iv, int opmode) {
		sm4_cbc_ctx = GmSSLJNI.sm4_cbc_ctx_new();
		mode = opmode;
		if (mode == DECRYPT_MODE) {
			GmSSLJNI.sm4_cbc_decrypt_init(sm4_cbc_ctx, key, iv);
		} else {
			GmSSLJNI.sm4_cbc_encrypt_init(sm4_cbc_ctx, key, iv);
		}
	}

	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {
		if (mode == DECRYPT_MODE) {
			return GmSSLJNI.sm4_cbc_decrypt_update(sm4_cbc_ctx, in, in_offset, inlen, out, out_offset);
		} else {
			return GmSSLJNI.sm4_cbc_encrypt_update(sm4_cbc_ctx, in, in_offset, inlen, out, out_offset);
		}
	}

	public int doFinal(byte[] out, int out_offset) {
		if (mode == DECRYPT_MODE) {
			return GmSSLJNI.sm4_cbc_decrypt_finish(sm4_cbc_ctx, out, out_offset);
		} else {
			return GmSSLJNI.sm4_cbc_encrypt_finish(sm4_cbc_ctx, out, out_offset);
		}
	}
}
