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

import java.security.KeyPairGeneratorSpi;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public final class GmSSLKeyPairGenerator extends KeyPairGeneratorSpi {

	private GmSSLKeyPairGenerator() {
	}

	@Override
	public void initialize(int keysize, SecureRandom random) {
		if (keysize != 256) {
		}
	}

	@Override
	public KeyPair generateKeyPair() {

		long sm2_key;
		byte[] pri_key_info;
		byte[] pub_key_info;
		KeySpec pri_key_spec;
		KeySpec pub_key_spec;
		KeyPair keypair;

		sm2_key = GmSSLJNI.sm2_key_generate();

		pri_key_info = GmSSLJNI.sm2_private_key_info_to_der(sm2_key);
		pub_key_info = GmSSLJNI.sm2_public_key_info_to_der(sm2_key);

		pri_key_spec = new PKCS8EncodedKeySpec(pri_key_info);
		pub_key_spec = new X509EncodedKeySpec(pub_key_info);

		// clean pri_key_info!

		try {
			KeyFactory factory = KeyFactory.getInstance("EC");

			ECPrivateKey pri_key = (ECPrivateKey)factory.generatePrivate(pri_key_spec);
			ECPublicKey pub_key = (ECPublicKey)factory.generatePublic(pub_key_spec);

			keypair = new KeyPair(pub_key, pri_key);
			return keypair;

		} catch (Exception e) {
		}

		return null;
	}
}
