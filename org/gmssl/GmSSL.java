/* ====================================================================
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
package org.gmssl;

public class GmSSL {

	public native String[] getVersions();
	public native String[] getCiphers();
	public native String[] getDigests();
	public native String[] getMacs();
	public native String[] getSignAlgorithms();
	public native String[] getPublicKeyEncryptions();
	public native String[] getDeriveKeyAlgorithms();
	public native byte[] generateRandom(int length);
	public native int getCipherIVLength(String cipher);
	public native int getCipherKeyLength(String cipher);
	public native int getCipherBlockSize(String cipher);
	public native byte[] symmetricEncrypt(String cipher, byte[] in, byte[] key, byte[] iv);
	public native byte[] symmetricDecrypt(String cipher, byte[] in, byte[] key, byte[] iv);
	public native int getDigestLength(String digest);
	public native int getDigestBlockSize(String digest);
	public native byte[] digest(String algor, byte[] data);
	public native String[] getMacLength(String algor);
	public native byte[] mac(String algor, byte[] data, byte[] key);
	public native byte[] sign(String algor, byte[] data, byte[] privateKey);
	public native int verify(String algor, byte[] digest, byte[] signature, byte[] publicKey);
	public native byte[] publicKeyEncrypt(String algor, byte[] in, byte[] publicKey);
	public native byte[] publicKeyDecrypt(String algor, byte[] in, byte[] privateKey);
	public native byte[] deriveKey(String algor, int keyLength, byte[] peerPublicKey, byte[] privateKey);
	//public native String[] getErrorStrings();

	public static void main(String[] args) {
		int i;
		final GmSSL gmssl = new GmSSL();

		/* GmSSL versions */
		String[] versions = gmssl.getVersions();
		for (i = 0; i < versions.length; i++) {
			System.out.println(versions[i]);
		}

		/* Supported algorithms */
		System.out.print("Ciphers: ");
		String[] ciphers = gmssl.getCiphers();
		for (i = 0; i < ciphers.length - 1; i++) {
			System.out.print(ciphers[i] + ", ");
		}
		System.out.println(ciphers[i]);

		System.out.print("Digests: ");
		String[] digests = gmssl.getDigests();
		for (i = 0; i < digests.length - 1; i++) {
			System.out.print(digests[i] + ", ");
		}
		System.out.println(digests[i]);

		System.out.print("MACs: ");
		String[] macs = gmssl.getMacs();
		for (i = 0; i < macs.length - 1; i++) {
			System.out.print(macs[i] + ", ");
		}
		System.out.println(macs[i]);

		System.out.print("SignAlgorithms: ");
		String[] signAlgors = gmssl.getSignAlgorithms();
		for (i = 0; i < signAlgors.length - 1; i++) {
			System.out.print(signAlgors[i] + ", ");
		}
		System.out.println(signAlgors[i]);

		System.out.print("PublicKeyEncryptions: ");
		String[] encAlgors = gmssl.getPublicKeyEncryptions();
		for (i = 0; i < encAlgors.length - 1; i++) {
			System.out.print(encAlgors[i] + ", ");
		}
		System.out.println(encAlgors[i]);

		/*
		System.out.print("DeriveKeyAlgorithms: ");
		String[] kdfs = gmssl.getDeriveKeyAlgorithms();
		for (i = 0; i < kdfs.length - 1; i++) {
			System.out.print(kdfs[i] + ", ");
		}
		System.out.println(kdfs[i]);
		*/

		/* Crypto operations */
		System.out.print("Random(20) = ");
		byte[] data = gmssl.generateRandom(20);
		for (i = 0; i < data.length; i++) {
			System.out.printf("%02X", data[i]);
		}
		System.out.println("");

		System.out.printf("SM4 IV length = %d bytes, key length = %d bytes, block size = %d bytes\n",
			gmssl.getCipherIVLength("SM4-CBC-PADDING"),
			gmssl.getCipherKeyLength("SM4-CBC-PADDING"),
			gmssl.getCipherBlockSize("SM4-CBC-PADDING"));

		byte[] key = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
		byte[] iv = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};
		byte[] ciphertext = gmssl.symmetricEncrypt("SM4-CBC-PADDING", "01234567".getBytes(), key, iv);

		System.out.print("Ciphertext: ");
		for (i = 0; i < ciphertext.length; i++) {
			System.out.printf("%02X", ciphertext[i]);
		}
		System.out.println("");

		byte[] plaintext = gmssl.symmetricDecrypt("SM4-CBC-PADDING", ciphertext, key, iv);

		System.out.print("Plaintext: ");
		for (i = 0; i < plaintext.length; i++) {
			System.out.printf("%02X", plaintext[i]);
		}
		System.out.println("");

		byte[] dgst = gmssl.digest("SM3", "abc".getBytes());
		System.out.print("SM3(\"abc\") = ");
		for (i = 0; i < dgst.length; i++) {
			System.out.printf("%02X", dgst[i]);
		}
		System.out.println("");

		byte[] macTag = gmssl.mac("HMAC-SM3", "abc".getBytes(), "password".getBytes());
		System.out.print("HMAC-SM3(\"abc\") = ");
		for (i = 0; i < macTag.length; i++) {
			System.out.printf("%02X", macTag[i]);
		}
		System.out.println("");

		byte[] sm2PrivateKey = new byte[] {
		(byte)0x64,(byte)0x97,(byte)0x32,(byte)0x1b,(byte)0x84,(byte)0xcd,(byte)0x18,(byte)0x44,
		(byte)0x88,(byte)0x15,(byte)0x73,(byte)0x16,(byte)0x2b,(byte)0x27,(byte)0x04,(byte)0x6e,
		(byte)0x77,(byte)0x5e,(byte)0xee,(byte)0xb4,(byte)0x62,(byte)0x33,(byte)0x22,(byte)0x1d,
		(byte)0xea,(byte)0x0f,(byte)0x84,(byte)0x82,(byte)0x32,(byte)0xe1,(byte)0x0e,(byte)0x72,
		(byte)0xb6,(byte)0x92,(byte)0xa2,(byte)0x8b,(byte)0xda,(byte)0xe8,(byte)0x17,(byte)0x13,
		(byte)0x65,(byte)0xe4,(byte)0x99,(byte)0x09,(byte)0x75,(byte)0xd3,(byte)0x9c,(byte)0x19,
		(byte)0x41,(byte)0x29,(byte)0xb8,(byte)0x6a,(byte)0xed,(byte)0xec,(byte)0xd2,(byte)0xe8,
		(byte)0xc1,(byte)0xcb,(byte)0xd1,(byte)0x4b,(byte)0xc2,(byte)0x8a,(byte)0xf8,(byte)0xd7,
		(byte)0x53,(byte)0x45,(byte)0x34,(byte)0x8c,(byte)0x71,(byte)0xfb,(byte)0x5b,(byte)0x78,
		(byte)0x23,(byte)0x38,(byte)0x56,(byte)0x76,(byte)0x69,(byte)0x76,(byte)0x8b,(byte)0xba,
		(byte)0x1a,(byte)0x0f,(byte)0xae,(byte)0x18,(byte)0x71,(byte)0xaa,(byte)0xe6,(byte)0x9f,
		(byte)0x3e,(byte)0x8c,(byte)0x9e,(byte)0x57,(byte)0x5d,(byte)0xcc,(byte)0xa4,(byte)0x36,
		};

		byte[] sm2PublicKey = new byte[] {
		(byte)0x64,(byte)0x97,(byte)0x32,(byte)0x1b,(byte)0x84,(byte)0xcd,(byte)0x18,(byte)0x44,
		(byte)0x88,(byte)0x15,(byte)0x73,(byte)0x16,(byte)0x2b,(byte)0x27,(byte)0x04,(byte)0x6e,
		(byte)0x77,(byte)0x5e,(byte)0xee,(byte)0xb4,(byte)0x62,(byte)0x33,(byte)0x22,(byte)0x1d,
		(byte)0xea,(byte)0x0f,(byte)0x84,(byte)0x82,(byte)0x32,(byte)0xe1,(byte)0x0e,(byte)0x72,
		(byte)0xb6,(byte)0x92,(byte)0xa2,(byte)0x8b,(byte)0xda,(byte)0xe8,(byte)0x17,(byte)0x13,
		(byte)0x65,(byte)0xe4,(byte)0x99,(byte)0x09,(byte)0x75,(byte)0xd3,(byte)0x9c,(byte)0x19,
		(byte)0x41,(byte)0x29,(byte)0xb8,(byte)0x6a,(byte)0xed,(byte)0xec,(byte)0xd2,(byte)0xe8,
		(byte)0xc1,(byte)0xcb,(byte)0xd1,(byte)0x4b,(byte)0xc2,(byte)0x8a,(byte)0xf8,(byte)0xd7,
		(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		};

		byte[] sig = gmssl.sign("SM2", dgst, sm2PrivateKey);
		System.out.print("SM2 Signature : ");
		for (i = 0; i < sig.length; i++) {
			System.out.printf("%02X", sig[i]);
		}
		System.out.print("\n");

		int vret = gmssl.verify("SM2", dgst, sig, sm2PublicKey);
		System.out.println("Verification result = " + vret);

		byte[] sm2Ciphertext = gmssl.publicKeyEncrypt("SM2", dgst, sm2PublicKey);
		System.out.print("SM2 Ciphertext : ");
		for (i = 0; i < sm2Ciphertext.length; i++) {
			System.out.printf("%02X", sm2Ciphertext[i]);
		}
		System.out.print("\n");

		byte[] sm2Plaintext = gmssl.publicKeyDecrypt("SM2", sm2Ciphertext, sm2PrivateKey);
		System.out.print("SM2 Plaintext : ");
		for (i = 0; i < sm2Plaintext.length; i++) {
			System.out.printf("%02X", sm2Plaintext[i]);
		}
		System.out.print("\n");

		/* Errors */
		/*
		System.out.println("Errors:");
		String[] errors = gmssl.getErrorStrings();
		for (i = 0; i < errors.length; i++) {
			System.out.println(errors[i]);
		}
		*/

	}

	static {
		System.loadLibrary("gmssljni");
	}
}
