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
	public final static int SIGN = 0;
	public final static int VERIFY = 1;

	private long sm2_sign_ctx = 0;
	private int mode = 0;

	public Sm2Signature(Sm2Key key, String id, int opmode) {
		sm2_sign_ctx = GmSSLJNI.sm2_sign_ctx_new();
		mode = opmode;
		if (mode == SIGN) {
			GmSSLJNI.sm2_sign_init(sm2_sign_ctx, key.getKey(), id);
		} else {
			GmSSLJNI.sm2_verify_init(sm2_sign_ctx, key.getKey(), id);
		}
	}

	public void update(byte[] data, int offset, int len) {
		if (mode == SIGN) {
			GmSSLJNI.sm2_sign_update(sm2_sign_ctx, data, offset, len);
		} else {
			GmSSLJNI.sm2_verify_update(sm2_sign_ctx, data, offset, len);
		}
	}

	public void update(byte[] data) {
		if (mode == SIGN) {
			GmSSLJNI.sm2_sign_update(sm2_sign_ctx, data, 0, data.length);
		} else {
			GmSSLJNI.sm2_verify_update(sm2_sign_ctx, data, 0, data.length);
		}
	}

	public byte[] sign() {
		return GmSSLJNI.sm2_sign_finish(sm2_sign_ctx);
	}

	public boolean verify(byte[] signature) {
		int ret = GmSSLJNI.sm2_verify_finish(sm2_sign_ctx, signature);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
