/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm9EncMasterKey;
import org.gmssl.Sm9EncKey;
import org.gmssl.Sm9SignMasterKey;
import org.gmssl.Sm9SignKey;
import org.gmssl.Sm9Signature;


public class Sm9Example {

	public static void main(String[] args) {

		Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
		sign_master_key.generateMasterKey();

		Sm9SignKey sign_key = sign_master_key.extractKey("Alice");

		Sm9Signature sign = new Sm9Signature(true);
		sign.update("abc".getBytes());
		byte[] sig = sign.sign(sign_key);

		sign_master_key.exportPublicMasterKeyPem("sm9sign.mpk");
		Sm9SignMasterKey sign_master_pub_key = new Sm9SignMasterKey();
		sign_master_pub_key.importPublicMasterKeyPem("sm9sign.mpk");

		Sm9Signature verify = new Sm9Signature(false);
		verify.update("abc".getBytes());
		boolean verify_ret = verify.verify(sig, sign_master_pub_key, "Alice");
		System.out.println("Verify result = " + verify_ret);

		Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
		enc_master_key.generateMasterKey();

		enc_master_key.exportPublicMasterKeyPem("sm9enc.mpk");
		Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
		enc_master_pub_key.importPublicMasterKeyPem("sm9enc.mpk");

		byte[] ciphertext = enc_master_pub_key.encrypt("abc".getBytes(), "Bob");

		Sm9EncKey enc_key = enc_master_key.extractKey("Bob");
		byte[] plaintext = enc_key.decrypt(ciphertext);
		int i;
		System.out.printf("plaintext: ");
		for (i = 0; i < plaintext.length; i++) {
			System.out.printf("%02x", plaintext[i]);
		}
		System.out.print("\n");


	}
}

