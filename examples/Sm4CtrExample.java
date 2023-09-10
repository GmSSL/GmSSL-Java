/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm4Ctr;
import org.gmssl.Random;

public class Sm4CtrExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4Ctr.KEY_SIZE);
		byte[] iv = rng.randBytes(Sm4Ctr.IV_SIZE);
		byte[] ciphertext = new byte[64];
		byte[] plaintext = new byte[64];
		int cipherlen;
		int plainlen;
		int i;

		Sm4Ctr sm4ctr = new Sm4Ctr();

		sm4ctr.init(key, iv);
		cipherlen = sm4ctr.update("abc".getBytes(), 0, "abc".length(), ciphertext, 0);
		cipherlen += sm4ctr.update("12345678".getBytes(), 0, "12345678".length(), ciphertext, cipherlen);
		cipherlen += sm4ctr.update("xxyyyzzz".getBytes(), 0, "xxyyyzzz".length(), ciphertext, cipherlen);
		cipherlen += sm4ctr.doFinal(ciphertext, cipherlen);

		System.out.print("ciphertext : ");
		for (i = 0; i < cipherlen; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		sm4ctr.init(key, iv);
		plainlen = sm4ctr.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += sm4ctr.doFinal(plaintext, plainlen);

		System.out.print("plaintext : ");
		for (i = 0; i < plainlen; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");
	}
}
