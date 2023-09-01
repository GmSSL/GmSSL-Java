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

	public final static int MAC_SIZE = GmSSLJNI.SM3_HMAC_SIZE;

	private byte[] key;

	private long sm3_hmac_ctx = 0;

	public Sm3Hmac(byte[] key) {
		if (key == null) {
			throw new GmSSLException("");
		}
		if ((this.sm3_hmac_ctx = GmSSLJNI.sm3_hmac_ctx_new()) == 0) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key) != 1) {
			throw new GmSSLException("");
		}
		this.key = key;
	}

	public void reset(byte[] key) {
		if (key == null) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, key) != 1) {
			throw new GmSSLException("");
		}
		this.key = key;
	}

	public void update(byte[] data, int offset, int len) {
		if (data == null
			|| offset < 0
			|| len < 0
			|| offset + len <= 0
			|| data.length < offset + len) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_hmac_update(this.sm3_hmac_ctx, data, offset, len) != 1) {
			throw new GmSSLException("");
		}
	}

	public void update(byte[] data) {
		this.update(data, 0, data.length);
	}

	public byte[] generateMac() {
		byte[] mac = new byte[this.MAC_SIZE];
		if (GmSSLJNI.sm3_hmac_finish(this.sm3_hmac_ctx, mac) != 1) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm3_hmac_init(this.sm3_hmac_ctx, this.key) != 1) {
			throw new GmSSLException("");
		}
		return mac;
	}
}

