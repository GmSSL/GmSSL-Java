/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;


public class Sm9Signature {

	private long sm9_sign_ctx = 0;
	private boolean inited = false;
	private boolean do_sign = true;

	public Sm9Signature(boolean do_sign) {
		if ((this.sm9_sign_ctx = GmSSLJNI.sm9_sign_ctx_new()) == 0) {
			throw new GmSSLException("");
		}
		if (do_sign == true) {
			if (GmSSLJNI.sm9_sign_init(this.sm9_sign_ctx) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm9_verify_init(this.sm9_sign_ctx) != 1) {
				throw new GmSSLException("");
			}
		}
		this.inited = true;
		this.do_sign = do_sign;
	}

	public void reset(boolean do_sign) {
		if (do_sign == true) {
			if (GmSSLJNI.sm9_sign_init(this.sm9_sign_ctx) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm9_verify_init(this.sm9_sign_ctx) != 1) {
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
			if (GmSSLJNI.sm9_sign_update(this.sm9_sign_ctx, data, offset, len) != 1) {
				throw new GmSSLException("");
			}
		} else {
			if (GmSSLJNI.sm9_verify_update(this.sm9_sign_ctx, data, offset, len) != 1) {
				throw new GmSSLException("");
			}
		}
	}

	public void update(byte[] data) {
		update(data, 0, data.length);
	}

	public byte[] sign(Sm9SignKey signKey) {
		if (this.inited == false) {
			throw new GmSSLException("");
		}
		if (this.do_sign == false) {
			throw new GmSSLException("");
		}

		byte[] signature;
		if ((signature = GmSSLJNI.sm9_sign_finish(this.sm9_sign_ctx, signKey.getKey())) == null) {
			throw new GmSSLException("");
		}
		this.inited = false;
		return signature;
	}

	public boolean verify(byte[] signature, Sm9SignMasterKey masterPublicKey, String id) {
		if (this.inited == false) {
			throw new GmSSLException("");
		}
		if (this.do_sign == true) {
			throw new GmSSLException("");
		}
		int ret;
		ret = GmSSLJNI.sm9_verify_finish(sm9_sign_ctx, signature, masterPublicKey.getPublicMasterKey(), id);
		this.inited = false;
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
