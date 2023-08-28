/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

import org.gmssl.GmSSLJNI;
import org.gmssl.Sm3;


public class HelloGmSSLJNI {

	public static void main(String[] args) {

		System.out.println("GmSSL-Java version: " + GmSSLJNI.GMSSL_JNI_VERSION);
		System.out.println("GmSSL version: " + GmSSLJNI.version_str());

		Sm3 sm3 = new Sm3();
		sm3.update("abc".getBytes(), 0, 3);
		byte[] dgst = sm3.digest();

		int i;
		System.out.printf("sm3('abc'): ");
		for (i = 0; i < dgst.length; i++) {
			System.out.printf("%02x", dgst[i]);
		}
		System.out.print("\n");
	}
}

