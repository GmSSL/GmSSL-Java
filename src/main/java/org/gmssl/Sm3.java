/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm3 {

	public final static int DIGEST_SIZE = GmSSLJNI.SM3_DIGEST_SIZE;

	private long sm3_ctx = 0;

	public Sm3() {
		sm3_ctx = GmSSLJNI.sm3_ctx_new();
		GmSSLJNI.sm3_init(sm3_ctx);
	}

	public void update(byte[] data, int offset, int len) {
		GmSSLJNI.sm3_update(sm3_ctx, data, offset, len);
	}

	public void update(byte[] data) {
		GmSSLJNI.sm3_update(sm3_ctx, data, 0, data.length);
	}

	public byte[] digest() {
		byte[] dgst = new byte[DIGEST_SIZE];
		GmSSLJNI.sm3_finish(sm3_ctx, dgst);
		GmSSLJNI.sm3_ctx_free(sm3_ctx);
		sm3_ctx = 0;
		return dgst;
	}
}
