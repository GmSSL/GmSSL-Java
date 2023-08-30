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
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.security.InvalidKeyException;


public final class GmSSLMac extends MacSpi {

	private long sm3_hmac_ctx = 0;
	byte[] sm3_hmac_key;

	public GmSSLMac() {
		sm3_hmac_ctx = GmSSLJNI.sm3_hmac_ctx_new();
	}

	@Override
	protected int engineGetMacLength() {
		return GmSSLJNI.SM3_HMAC_SIZE;
	}

	@Override
	protected void engineInit(Key key, AlgorithmParameterSpec params)
		throws InvalidKeyException {

		if (!(key instanceof SecretKey)) {
			throw new InvalidKeyException("Key should be SecretKey");
		}

		sm3_hmac_key = key.getEncoded();
		if (sm3_hmac_key == null) {
			throw new InvalidKeyException("");
		}

		GmSSLJNI.sm3_hmac_init(sm3_hmac_ctx, sm3_hmac_key);
	}

	@Override
	protected void engineReset() {
		GmSSLJNI.sm3_hmac_init(sm3_hmac_ctx, sm3_hmac_key);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		GmSSLJNI.sm3_hmac_update(sm3_hmac_ctx, input, offset, len);
	}

	@Override
	protected void engineUpdate(byte input) {
		byte[] data = new byte[1];
		data[0] = input;
		GmSSLJNI.sm3_hmac_update(sm3_hmac_ctx, data, 0, 1);
	}

	@Override
	protected byte[] engineDoFinal() {
		byte[] mac = new byte[32];
		GmSSLJNI.sm3_hmac_finish(sm3_hmac_ctx, mac);
		return mac;
	}
}
