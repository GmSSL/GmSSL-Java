/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm4;
import org.gmssl.Random;
import java.util.Arrays;

public class Sm4EcbExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4.KEY_SIZE);

		int nblocks = 4;
		byte[] plaintext = rng.randBytes(Sm4.BLOCK_SIZE * nblocks);
		byte[] ciphertext = new byte[Sm4.BLOCK_SIZE * nblocks];
		byte[] decrypted = new byte[Sm4.BLOCK_SIZE * nblocks];
		int plaintextOffset, ciphertextOffset, decryptedOffset;
		int i;

		System.out.println("SM4-ECB Example");

		System.out.print("Plaintext  : ");
		for (i = 0; i < plaintext.length; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");

		// Encrypt

		Sm4 sm4enc = new Sm4(key, true);

		plaintextOffset = 0;
		ciphertextOffset = 0;
		for (i = 0; i < nblocks; i++) {
			sm4enc.encrypt(plaintext, plaintextOffset, ciphertext, ciphertextOffset);
			plaintextOffset += Sm4.BLOCK_SIZE;
			ciphertextOffset += Sm4.BLOCK_SIZE;
		}

		System.out.print("Ciphertext : ");
		for (i = 0; i < ciphertext.length; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		// Decrypt

		Sm4 sm4dec = new Sm4(key, false);

		ciphertextOffset = 0;
		decryptedOffset = 0;
		for (i = 0;  i < nblocks; i++) {
			sm4dec.encrypt(ciphertext, ciphertextOffset, decrypted, decryptedOffset);
			ciphertextOffset += Sm4.BLOCK_SIZE;
			decryptedOffset += Sm4.BLOCK_SIZE;
		}

		System.out.print("Decrypted  : ");
		for (i = 0; i < decrypted.length; i++) {
			System.out.printf("%02x", decrypted[i]);
		}
		System.out.print("\n");

		System.out.println("Decryption success : " + Arrays.equals(plaintext, decrypted));
	}
}
