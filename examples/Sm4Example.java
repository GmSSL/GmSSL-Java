/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm4;
import org.gmssl.Random;
import java.util.Arrays;

public class Sm4Example {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4.KEY_SIZE);
		byte[] plaintext1 = rng.randBytes(Sm4.BLOCK_SIZE);
		byte[] ciphertext = new byte[Sm4.BLOCK_SIZE];
		byte[] plaintext2 = new byte[Sm4.BLOCK_SIZE];

		Sm4 sm4enc = new Sm4(key, true);
		sm4enc.encrypt(plaintext1, 0, ciphertext, 0);

		Sm4 sm4dec = new Sm4(key, false);
		sm4dec.encrypt(ciphertext, 0, plaintext2, 0);

		System.out.println("Sm4 Example");

		int i;
		System.out.print("Plaintext  : ");
		for (i = 0; i < plaintext1.length; i++) {
			System.out.printf("%02x", plaintext1[i]);
		}
		System.out.print("\n");

		System.out.print("Ciphertext : ");
		for (i = 0; i < ciphertext.length; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		System.out.print("Plaintext  : ");
		for (i = 0; i < plaintext2.length; i++) {
			System.out.printf("%02x", plaintext2[i]);
		}
		System.out.print("\n");

		System.out.println("Decryption success : " + Arrays.equals(plaintext1, plaintext2));
	}
}
