/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.Sm3Hmac;
import org.gmssl.Random;

public class Sm3HmacExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

		Sm3Hmac sm3hmac = new Sm3Hmac(key);
		sm3hmac.update("abc".getBytes(), 0, 3);
		byte[] mac = sm3hmac.generateMac();

		int i;
		System.out.printf("sm3hmac('abc'): ");
		for (i = 0; i < mac.length; i++) {
			System.out.printf("%02x", mac[i]);
		}
		System.out.print("\n");
	}
}

