/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl.jce;

import org.gmssl.GmSSLJNI;
import java.security.MessageDigestSpi;


public final class GmSSLMessageDigest extends MessageDigestSpi {

	private long sm3_ctx = 0;

	public GmSSLMessageDigest() {
		sm3_ctx = GmSSLJNI.sm3_ctx_new();
		GmSSLJNI.sm3_init(sm3_ctx);
	}

	@Override
	protected int engineGetDigestLength() {
		return GmSSLJNI.SM3_DIGEST_SIZE;
	}

	@Override
	protected void engineReset() {
		GmSSLJNI.sm3_init(sm3_ctx);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		GmSSLJNI.sm3_update(sm3_ctx, input, offset, len);
	}

	@Override
	protected void engineUpdate(byte input) {
		byte[] data = new byte[1];
		data[0] = input;
		GmSSLJNI.sm3_update(sm3_ctx, data, 0, 1);
	}

	@Override
	protected byte[] engineDigest() {
		byte[] dgst = new byte[GmSSLJNI.SM3_DIGEST_SIZE];
		GmSSLJNI.sm3_finish(sm3_ctx, dgst);
		return dgst;
	}
}
