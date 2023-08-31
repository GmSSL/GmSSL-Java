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
	public final static int MIN_TAG_SIZE = 8;
	public final static int MAX_TAG_SIZE = GmSSLJNI.SM4_GCM_MAX_TAG_SIZE;

	private long sm4_gcm_ctx = 0;
	private boolean do_encrypt = true;
	private boolean inited = false;


	public Sm4Gcm() {
		if ((this.sm4_gcm_ctx = GmSSLJNI.sm4_gcm_ctx_new()) == 0) {
			throw new GmSSLException("");
		}
		this.inited = false;
	}

	public void init(byte[] key, byte[] iv, byte[] aad, int taglen, boolean do_encrypt) {

		if (key == null
			|| key.length != this.KEY_SIZE
			|| iv == null
			|| iv.length < this.MIN_IV_SIZE
			|| iv.length > this.MAX_IV_SIZE
			|| taglen < this.MIN_TAG_SIZE
			|| taglen > this.MAX_TAG_SIZE) {
			throw new GmSSLException("");
		}

		if (do_encrypt == true) {
			if (GmSSLJNI.sm4_gcm_encrypt_init(this.sm4_gcm_ctx, key, iv, aad, taglen) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm4_gcm_decrypt_init(this.sm4_gcm_ctx, key, iv, aad, taglen) != 1) {
				throw new GmSSLException("");
			}
		}

		this.do_encrypt = do_encrypt;
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
		if (this.do_encrypt) {
			if ((outlen = GmSSLJNI.sm4_gcm_encrypt_update(this.sm4_gcm_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
				throw new GmSSLException("");
			}
		} else {
			if ((outlen = GmSSLJNI.sm4_gcm_decrypt_update(this.sm4_gcm_ctx, in, in_offset, inlen, out, out_offset)) < 0) {
				throw new GmSSLException("");
			}
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
		if (this.do_encrypt) {
			if ((outlen = GmSSLJNI.sm4_gcm_encrypt_finish(this.sm4_gcm_ctx, out, out_offset)) < 0) {
				throw new GmSSLException("");
			}
		} else {
			if ((outlen = GmSSLJNI.sm4_gcm_decrypt_finish(this.sm4_gcm_ctx, out, out_offset)) < 0) {
				throw new GmSSLException("");
			}
		}

		this.inited = false;
		return outlen;
	}
}
