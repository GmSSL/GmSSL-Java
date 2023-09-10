/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
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

		// Encrypted plaintext is "110101200106032443"
		byte[] plaintext = "ID:110101200106032443".getBytes();
		int plaintextOffset = "ID:".length();
		int plaintextLen = plaintext.length - plaintextOffset;

		boolean encrypt = true;
		boolean decrypt = false;
		int i;

		System.out.println("SM4-CBC Example");

		Sm4Cbc sm4cbc = new Sm4Cbc();

		// Encrypt

		byte[] ciphertext = new byte[plaintextLen + Sm4Cbc.BLOCK_SIZE]; // Prepare large enough ciphertext buffer
		int ciphertextOffset = 0;
		int ciphertextLen;

		sm4cbc.init(key, iv, encrypt);

		ciphertextLen = sm4cbc.update(plaintext, plaintextOffset, plaintextLen, ciphertext, ciphertextOffset);
		ciphertextOffset += ciphertextLen;

		ciphertextLen += sm4cbc.doFinal(ciphertext, ciphertextOffset);

		System.out.print("ciphertext : ");
		for (i = 0; i < ciphertextLen; i++) {
			System.out.printf("%02x", ciphertext[i]);
		}
		System.out.print("\n");

		// Decrypt

		sm4cbc.init(key, iv, decrypt);

		byte[] decrypted = new byte[ciphertextLen + Sm4Cbc.BLOCK_SIZE]; // prepare large enough plaintext buffer
		int decryptedOffset = 0;
		int decryptedLen;

		ciphertextOffset = 0;
		decryptedLen = sm4cbc.update(ciphertext, ciphertextOffset, ciphertextLen, decrypted, decryptedOffset);
		decryptedOffset += decryptedLen;

		decryptedLen += sm4cbc.doFinal(decrypted, decryptedOffset);

		System.out.print("decrypted : ");
		for (i = 0; i < decryptedLen; i++) {
			System.out.printf("%02x", decrypted[i]);
		}
		System.out.print("\n");
	}
}
