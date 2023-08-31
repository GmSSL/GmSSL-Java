/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class Sm2Signature {

	public final static String DEFAULT_ID = GmSSLJNI.SM2_DEFAULT_ID;

	private long sm2_sign_ctx = 0;
	private boolean inited = false;
	private boolean do_sign = true;

	public Sm2Signature(Sm2Key key, String id, boolean do_sign) {

		if ((this.sm2_sign_ctx = GmSSLJNI.sm2_sign_ctx_new()) == 0) {
			throw new GmSSLException("");
		}

		if (do_sign == true) {
			if (GmSSLJNI.sm2_sign_init(this.sm2_sign_ctx, key.getPrivateKey(), id) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm2_verify_init(sm2_sign_ctx, key.getPublicKey(), id) != 1) {
				throw new GmSSLException("");
			}
		}

		this.inited = true;
		this.do_sign = do_sign;
	}

	public void reset(Sm2Key key, String id, boolean do_sign) {
		if (do_sign == true) {
			if (GmSSLJNI.sm2_sign_init(this.sm2_sign_ctx, key.getPrivateKey(), id) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm2_verify_init(sm2_sign_ctx, key.getPublicKey(), id) != 1) {
				throw new GmSSLException("");
			}
		}
		this.inited = true;
		this.do_sign = do_sign;
	}

	public void update(byte[] data, int offset, int len) {

		if (this.inited == false) {
			throw new GmSSLException("");
		}

		if (data == null
			|| offset < 0
			|| len < 0
			|| offset + len <= 0
			|| data.length < offset + len) {
			throw new GmSSLException("");
		}

		if (this.do_sign == true) {
			if (GmSSLJNI.sm2_sign_update(this.sm2_sign_ctx, data, offset, len) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm2_verify_update(this.sm2_sign_ctx, data, offset, len) != 1) {
				throw new GmSSLException("");
			}
		}
	}

	public void update(byte[] data) {
		update(data, 0, data.length);
	}

	public byte[] sign() {
		if (this.inited == false) {
			throw new GmSSLException("");
		}
		if (this.do_sign == false) {
			throw new GmSSLException("");
		}
		this.inited = false;

		byte[] sig;
		if ((sig = GmSSLJNI.sm2_sign_finish(this.sm2_sign_ctx)) == null) {
			throw new GmSSLException("");
		}
		return sig;
	}

	public boolean verify(byte[] signature) {
		if (this.sm2_sign_ctx == 0) {
			throw new GmSSLException("");
		}
		if (this.do_sign == true) {
			throw new GmSSLException("");
		}
		this.inited = false;

		int ret;
		if ((ret = GmSSLJNI.sm2_verify_finish(sm2_sign_ctx, signature)) != 1) {
			return false;
		}
		return true;
	}
}
