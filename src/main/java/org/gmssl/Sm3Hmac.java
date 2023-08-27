/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm3Hmac {

	public final static int HMAC_SIZE = GmSSLJNI.SM3_HMAC_SIZE;

	private long sm3_hmac_ctx = 0;

	public Sm3Hmac(byte[] key) {
		sm3_hmac_ctx = GmSSLJNI.sm3_hmac_ctx_new();
		GmSSLJNI.sm3_hmac_init(sm3_hmac_ctx, key);
	}

	public void update(byte[] data, int offset, int len) {
		GmSSLJNI.sm3_hmac_update(sm3_hmac_ctx, data, offset, len);
	}

	public void update(byte[] data) {
		GmSSLJNI.sm3_hmac_update(sm3_hmac_ctx, data, 0, data.length);
	}

	public byte[] doFinal() {
		byte[] mac = new byte[HMAC_SIZE];
		GmSSLJNI.sm3_hmac_finish(sm3_hmac_ctx, mac);
		GmSSLJNI.sm3_hmac_ctx_free(sm3_hmac_ctx);
		sm3_hmac_ctx = 0;
		return mac;
	}
}

