/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
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

		Sm2Key sm2_key = new Sm2Key();

		sm2_key.generateKey();

		byte[] z = sm2_key.computeZ(Sm2Key.DEFAULT_ID);

		int i;
		System.out.printf("Z: ");
		for (i = 0; i < z.length; i++) {
			System.out.printf("%02x", z[i]);
		}
		System.out.print("\n");

		Random rng = new Random();
		byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
		byte[] sig = sm2_key.sign(dgst);
		boolean verify_ret = sm2_key.verify(dgst, sig);
		System.out.println("Verify result = " + verify_ret);

		byte[] ciphertext = sm2_key.encrypt("abc".getBytes());
		byte[] plaintext = sm2_key.decrypt(ciphertext);
		System.out.printf("Plaintext : ");
		for (i = 0; i < plaintext.length; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");

		Sm2Signature sign = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, true);
		sign.update("abc".getBytes());
		sig = sign.sign();

		Sm2Signature verify = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, false);
		verify.update("abc".getBytes());
		verify_ret = verify.verify(sig);
		System.out.println("Verify result = " + verify_ret);

	}
}

