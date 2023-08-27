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

	public final static int SIGN = 0;
	public final static int VERIFY = 1;

	private long sm9_sign_ctx = 0;
	private int mode = 0;

	public Sm9Signature(int opmode) {
		sm9_sign_ctx = GmSSLJNI.sm9_sign_ctx_new();
		mode = opmode;
		if (mode == SIGN) {
			GmSSLJNI.sm9_sign_init(sm9_sign_ctx);
		} else {
			GmSSLJNI.sm9_verify_init(sm9_sign_ctx);
		}
	}

	public void update(byte[] data, int offset, int len) {
		if (mode == SIGN) {
			GmSSLJNI.sm9_sign_update(sm9_sign_ctx, data, offset, len);
		} else {
			GmSSLJNI.sm9_verify_update(sm9_sign_ctx, data, offset, len);
		}
	}

	public void update(byte[] data) {
		update(data, 0, data.length);
	}

	public byte[] sign(Sm9SignKey signKey) {
		return GmSSLJNI.sm9_sign_finish(sm9_sign_ctx, signKey.getKey());
	}

	public boolean verify(byte[] signature, Sm9SignMasterKey masterPublicKey, String id) {
		int ret = GmSSLJNI.sm9_verify_finish(sm9_sign_ctx, signature, masterPublicKey.getMasterKey(), id);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
