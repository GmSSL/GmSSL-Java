/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm4 {

	public final static int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;
	public final static int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

	private long sm4_key = 0;

	public Sm4(byte[] key, boolean do_encrypt) {

		if (key == null) {
			throw new GmSSLException("");
		}
		if (key.length != this.KEY_SIZE) {
			throw new GmSSLException("");
		}

		if ((sm4_key = GmSSLJNI.sm4_key_new()) == 0) {
			throw new GmSSLException("");
		}

		if (do_encrypt == true) {
			if (GmSSLJNI.sm4_set_encrypt_key(sm4_key, key) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm4_set_decrypt_key(sm4_key, key) != 1) {
				throw new GmSSLException("");
			}
		}
	}

	public void encrypt(byte[] in, int in_offset, byte[] out, int out_offset) {
		if (in == null
			|| in_offset < 0
			|| in_offset + this.BLOCK_SIZE <= 0
			|| in_offset + this.BLOCK_SIZE > in.length) {
			throw new GmSSLException("");
		}
		if (out == null
			|| out_offset < 0
			|| out_offset + this.BLOCK_SIZE <= 0
			|| out_offset + this.BLOCK_SIZE > in.length) {
			throw new GmSSLException("");
		}

		if (GmSSLJNI.sm4_encrypt(sm4_key, in, in_offset, out, out_offset) != 1) {
			throw new GmSSLException("");
		}
	}
}
