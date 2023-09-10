/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm4Gcm;
import org.gmssl.Random;

public class Sm4GcmExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4Gcm.KEY_SIZE);
		byte[] iv = rng.randBytes(Sm4Gcm.DEFAULT_IV_SIZE);
		byte[] aad = "Hello: ".getBytes();
		int taglen = Sm4Gcm.MAX_TAG_SIZE;
		byte[] ciphertext = new byte[64];
		byte[] plaintext = new byte[64];
		int cipherlen;
		int plainlen;
		boolean encrypt = true;
		boolean decrypt = false;
		int i;

		Sm4Gcm sm4gcm = new Sm4Gcm();

		sm4gcm.init(key, iv, aad, taglen, encrypt);
		cipherlen = sm4gcm.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += sm4gcm.doFinal(ciphertext, cipherlen);

		System.out.print("ciphertext : ");
		for (i = 0; i < cipherlen; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		sm4gcm.init(key, iv, aad, taglen, decrypt);
		plainlen = sm4gcm.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += sm4gcm.doFinal(plaintext, plainlen);

		System.out.print("plaintext : ");
		for (i = 0; i < plainlen; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");
	}
}
