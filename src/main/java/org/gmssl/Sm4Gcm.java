/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm4Gcm {

	public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
	public final static int MIN_IV_SIZE = GmSSLJNI.SM4_GCM_MIN_IV_SIZE;
	public final static int MAX_IV_SIZE = GmSSLJNI.SM4_GCM_MAX_IV_SIZE;
	public final static int DEFAULT_IV_SIZE = GmSSLJNI.SM4_GCM_DEFAULT_IV_SIZE;
	public final static int MAX_TAG_SIZE = GmSSLJNI.SM4_GCM_MAX_TAG_SIZE;

	public static final int ENCRYPT_MODE = 1;
	public static final int DECRYPT_MODE = 0;

	private long sm4_gcm_ctx = 0;
	private int mode;

	public Sm4Gcm(byte[] key, byte[] iv, byte[] aad, int taglen, int opmode) {
		sm4_gcm_ctx = GmSSLJNI.sm4_gcm_ctx_new();
		mode = opmode;
		if (mode == DECRYPT_MODE) {
			GmSSLJNI.sm4_gcm_decrypt_init(sm4_gcm_ctx, key, iv, aad, taglen);
		} else {
			GmSSLJNI.sm4_gcm_encrypt_init(sm4_gcm_ctx, key, iv, aad, taglen);
		}
	}

	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {
		if (mode == DECRYPT_MODE) {
			return GmSSLJNI.sm4_gcm_decrypt_update(sm4_gcm_ctx, in, in_offset, inlen, out, out_offset);
		} else {
			return GmSSLJNI.sm4_gcm_encrypt_update(sm4_gcm_ctx, in, in_offset, inlen, out, out_offset);
		}
	}

	public int doFinal(byte[] out, int out_offset) {
		if (mode == DECRYPT_MODE) {
			return GmSSLJNI.sm4_gcm_decrypt_finish(sm4_gcm_ctx, out, out_offset);
		} else {
			return GmSSLJNI.sm4_gcm_encrypt_finish(sm4_gcm_ctx, out, out_offset);
		}
	}
}
