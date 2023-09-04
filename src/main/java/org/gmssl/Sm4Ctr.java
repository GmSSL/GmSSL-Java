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
	public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

	private long sm4_ctr_ctx = 0;
	private boolean inited = false;

	public Sm4Ctr() {
		if ((this.sm4_ctr_ctx = GmSSLJNI.sm4_ctr_ctx_new()) == 0) {
			throw new GmSSLException("");
		}
		this.inited = false;
	}

	public void init(byte[] key, byte[] iv) {

		if (key == null
			|| key.length != this.KEY_SIZE
			|| iv == null
			|| iv.length != this.IV_SIZE) {
			throw new GmSSLException("");
		}

		if (GmSSLJNI.sm4_ctr_encrypt_init(this.sm4_ctr_ctx, key, iv) != 1) {
			throw new GmSSLException("");
		}

		this.inited = true;
	}

	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset) {

		if (this.inited == false) {
			throw new GmSSLException("");
		}

		if (in == null
			|| in_offset < 0
			|| inlen < 0
			|| in_offset + inlen <= 0
			|| in.length < in_offset + inlen) {
			throw new GmSSLException("");
		}
		if (out == null
			|| out_offset < 0
			|| out.length < out_offset) {
			throw new GmSSLException("");
		}

		int outlen;
		if ((outlen = GmSSLJNI.sm4_ctr_encrypt_update(this.sm4_ctr_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
			throw new GmSSLException("");
		}
		return outlen;
	}

	public int doFinal(byte[] out, int out_offset) {

		if (this.inited == false) {
			throw new GmSSLException("");
		}

		if (out == null
			|| out_offset < 0
			|| out.length < out_offset) {
			throw new GmSSLException("");
		}

		int outlen;
		if ((outlen = GmSSLJNI.sm4_ctr_encrypt_finish(this.sm4_ctr_ctx, out, out_offset)) < 0) {
			throw new GmSSLException("");
		}
		this.inited = false;
		return outlen;
	}
}
