/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm2Key;
import org.gmssl.Sm2Signature;
import org.gmssl.Sm3;
import org.gmssl.Random;

public class Sm2Example {

	public static void main(String[] args) {
		int i;

		Sm2Key sm2_key = new Sm2Key();

		sm2_key.generateKey();

		byte[] privateKeyInfo = sm2_key.exportPrivateKeyInfoDer();
		System.out.printf("PrivateKeyInfo: ");
		for (i = 0; i < privateKeyInfo.length; i++) {
			System.out.printf("%02x", privateKeyInfo[i]);
		}
		System.out.print("\n");

		byte[] publicKeyInfo = sm2_key.exportPublicKeyInfoDer();
		System.out.printf("PrivateKeyInfo: ");
		for (i = 0; i < publicKeyInfo.length; i++) {
			System.out.printf("%02x", publicKeyInfo[i]);
		}
		System.out.print("\n");


		Sm2Key priKey = new Sm2Key();
		priKey.importPrivateKeyInfoDer(privateKeyInfo);

		Sm2Key pubKey = new Sm2Key();
		pubKey.importPublicKeyInfoDer(publicKeyInfo);

		priKey.exportEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
		pubKey.exportPublicKeyInfoPem("sm2pub.pem");

		priKey.importEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
		pubKey.importPublicKeyInfoPem("sm2pub.pem");


		byte[] z = pubKey.computeZ(Sm2Key.DEFAULT_ID);

		System.out.printf("Z: ");
		for (i = 0; i < z.length; i++) {
			System.out.printf("%02x", z[i]);
		}
		System.out.print("\n");


		Random rng = new Random();
		byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
		byte[] sig = priKey.sign(dgst);
		boolean verify_ret = pubKey.verify(dgst, sig);
		System.out.println("Verify result = " + verify_ret);

		byte[] ciphertext = pubKey.encrypt("abc".getBytes());
		byte[] plaintext = priKey.decrypt(ciphertext);
		System.out.printf("Plaintext : ");
		for (i = 0; i < plaintext.length; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");

		Sm2Signature sign = new Sm2Signature(priKey, Sm2Key.DEFAULT_ID, true);
		sign.update("abc".getBytes());
		sig = sign.sign();

		Sm2Signature verify = new Sm2Signature(pubKey, Sm2Key.DEFAULT_ID, false);
		verify.update("abc".getBytes());
		verify_ret = verify.verify(sig);
		System.out.println("Verify result = " + verify_ret);

	}
}

