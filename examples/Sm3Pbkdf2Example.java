/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm3Pbkdf2;
import org.gmssl.Random;

public class Sm3Pbkdf2Example {

	public static void main(String[] args) {

		Sm3Pbkdf2 kdf = new Sm3Pbkdf2();

		Random rng = new Random();
		byte[] salt = rng.randBytes(Sm3Pbkdf2.DEFAULT_SALT_SIZE);

		String pass = "P@ssw0rd";
		byte[] key = kdf.deriveKey(pass, salt, Sm3Pbkdf2.MIN_ITER * 2, 16);

		int i;
		System.out.printf("pbkdf2(pass, salt, iter, keylen): ");
		for (i = 0; i < key.length; i++) {
			System.out.printf("%02x", key[i]);
		}
		System.out.print("\n");
	}
}

