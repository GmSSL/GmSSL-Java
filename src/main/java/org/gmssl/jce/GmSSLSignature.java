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

import java.security.SignatureSpi;

import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import java.security.InvalidKeyException;


public class GmSSLSignature extends SignatureSpi {

	private long sm2_sign_ctx = 0;
	private int do_sign = 0;

	private GmSSLSignature() {
		sm2_sign_ctx = GmSSLJNI.sm2_sign_ctx_new();
	}

	// Deprecated
	@Override
	protected Object engineGetParameter(String param) {
		return null;
	}

	// Deprecated
	@Override
	protected void engineSetParameter(String param, Object value) {
	}

	@Override
	protected void engineInitSign(PrivateKey privateKey)
		throws InvalidKeyException {

		if (!(privateKey instanceof ECPrivateKey)) {
			throw new InvalidKeyException("");
		}

		byte[] pri_key_info = privateKey.getEncoded();
		if (pri_key_info == null) {
			throw new InvalidKeyException("");
		}

		long sm2_key = GmSSLJNI.sm2_private_key_info_from_der(pri_key_info);
		if (sm2_key == 0) {
			throw new InvalidKeyException("");
		}

		// FIXME: how to get id ?
		String id = GmSSLJNI.SM2_DEFAULT_ID;

		GmSSLJNI.sm2_sign_init(sm2_sign_ctx, sm2_key, id);

		GmSSLJNI.sm2_key_free(sm2_key);

		do_sign = 1;
	}

	@Override
	protected void engineInitVerify(PublicKey publicKey)
		throws InvalidKeyException {

		if (!(publicKey instanceof ECPublicKey)) {
			throw new InvalidKeyException("");
		}

		byte[] pub_key_info = publicKey.getEncoded();
		if (pub_key_info == null) {
			throw new InvalidKeyException("");
		}

		long sm2_key = GmSSLJNI.sm2_public_key_info_from_der(pub_key_info);
		if (sm2_key == 0) {
			throw new InvalidKeyException("");
		}

		// FIXME: how to get id ?
		String id = GmSSLJNI.SM2_DEFAULT_ID;

		GmSSLJNI.sm2_verify_init(sm2_sign_ctx, sm2_key, id);

		GmSSLJNI.sm2_key_free(sm2_key);

		do_sign = 0;
	}

	@Override
	protected void engineUpdate(byte[] b, int off, int len) {
		if (do_sign == 1) {
			GmSSLJNI.sm2_sign_update(sm2_sign_ctx, b, off, len);
		} else {
			GmSSLJNI.sm2_verify_update(sm2_sign_ctx, b, off, len);
		}
	}

	@Override
	protected void engineUpdate(byte b) {
		byte[] data = new byte[1];
		data[0] = b;
		if (do_sign == 1) {
			GmSSLJNI.sm2_sign_update(sm2_sign_ctx, data, 0, 1);
		} else {
			GmSSLJNI.sm2_verify_update(sm2_sign_ctx, data, 0, 1);
		}
	}

	@Override
	protected byte[] engineSign() {

		byte[] sig = GmSSLJNI.sm2_sign_finish(this.sm2_sign_ctx);

		return sig;
	}

	@Override
	protected boolean engineVerify(byte[] sigBytes) {
		int ret = GmSSLJNI.sm2_verify_finish(this.sm2_sign_ctx, sigBytes);
		if (ret == 1) {
			return true;
		} else {
			return false;
		}
	}
}
