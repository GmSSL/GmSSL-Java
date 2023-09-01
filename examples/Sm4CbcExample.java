/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm4Cbc;
import org.gmssl.Random;

public class Sm4CbcExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4Cbc.KEY_SIZE);
		byte[] iv = rng.randBytes(Sm4Cbc.IV_SIZE);
		byte[] ciphertext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
		byte[] plaintext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
		int cipherlen;
		int plainlen;
		boolean encrypt = true;
		boolean decrypt = false;
		int i;

		Sm4Cbc sm4cbc = new Sm4Cbc();

		sm4cbc.init(key, iv, encrypt);
		cipherlen = sm4cbc.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += sm4cbc.doFinal(ciphertext, cipherlen);

		System.out.print("ciphertext : ");
		for (i = 0; i < cipherlen; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		sm4cbc.init(key, iv, decrypt);
		plainlen = sm4cbc.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += sm4cbc.doFinal(plaintext, plainlen);

		System.out.print("plaintext : ");
		for (i = 0; i < plainlen; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");
	}
}
