/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl.jce;

import java.security.Provider;


public final class GmSSLProvider extends Provider {

	public GmSSLProvider() {
		super("GmSSL", "2.1.0 dev", "GmSSL JCE Provider");

		put("MessageDigest.SM3", "org.gmssl.jce.GmSSLMessageDigest");
		put("Mac.HmacSM3", "org.gmssl.jce.GmSSLMac");
		put("Cipher.SM4/CBC/PKCS5Padding", "org.gmssl.jce.GmSSLCipher$sm4CbcCipher");
		put("Cipher.SM4/CTR", "org.gmssl.jce.GmSSLCipher$sm4CtrCipher");
		put("Cipher.SM4/GCM", "org.gmssl.jce.GmSSLCipher$sm4GcmCipher");
		put("Cipher.ZUC", "org.gmssl.jce.GmSSLCipher$zucCipher");
		put("KeyPairGenerator.SM2", "org.gmssl.jce.GmSSLKeyPairGenerator");
		put("Signature.SM2signWithSM3", "org.gmssl.jce.GmSSLSignature");
	}
}
