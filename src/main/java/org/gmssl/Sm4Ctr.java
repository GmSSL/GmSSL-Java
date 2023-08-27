/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm4Ctr {

	public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
	public final static int IV_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

	private long sm4_ctr_ctx = 0;

	public Sm4Ctr(byte[] key, byte[] iv) {
		sm4_ctr_ctx = GmSSLJNI.sm4_ctr_ctx_new();
		GmSSLJNI.sm4_ctr_encrypt_init(sm4_ctr_ctx, key, iv);
	}

	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {
		return GmSSLJNI.sm4_ctr_encrypt_update(sm4_ctr_ctx, in, in_offset, inlen, out, out_offset);
	}

	public int doFinal(byte[] out, int out_offset) {
		return GmSSLJNI.sm4_ctr_encrypt_finish(sm4_ctr_ctx, out, out_offset);
	}
}
