/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm3 implements AutoCloseable{

	public final static int DIGEST_SIZE = GmSSLJNI.SM3_DIGEST_SIZE;

	private long sm3_ctx = 0;

	public Sm3() {
		if ((sm3_ctx = GmSSLJNI.sm3_ctx_new()) == 0) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
			throw new GmSSLException("");
		}
	}

	public void reset() {
		if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
			throw new GmSSLException("");
		}
	}

	public void update(byte[] data, int offset, int len) {
		if (data == null
			|| offset < 0
			|| len < 0
			|| offset + len <= 0
			|| data.length < offset + len) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_update(sm3_ctx, data, offset, len) != 1) {
			throw new GmSSLException("");
		}
	}

	public void update(byte[] data) {
		this.update(data, 0, data.length);
	}

	public byte[] digest() {
		byte[] dgst = new byte[DIGEST_SIZE];
		if (GmSSLJNI.sm3_finish(sm3_ctx, dgst) != 1) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_init(sm3_ctx) != 1) {
			throw new GmSSLException("");
		}
		return dgst;
	}

	@Override
	public void close() throws Exception {
		GmSSLJNI.sm3_ctx_free(sm3_ctx);
	}
}
