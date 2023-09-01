/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Zuc;
import org.gmssl.Random;

public class ZucExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Zuc.KEY_SIZE);
		byte[] iv = rng.randBytes(Zuc.IV_SIZE);
		byte[] ciphertext = new byte[32];
		byte[] plaintext = new byte[32];
		int cipherlen;
		int plainlen;
		int i;

		Zuc zuc = new Zuc();

		zuc.init(key, iv);
		cipherlen = zuc.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += zuc.doFinal(ciphertext, cipherlen);

		System.out.print("ciphertext : ");
		for (i = 0; i < cipherlen; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		zuc.init(key, iv);
		plainlen = zuc.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += zuc.doFinal(plaintext, plainlen);

		System.out.print("plaintext : ");
		for (i = 0; i < plainlen; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");
	}
}
