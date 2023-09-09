/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;


public class Sm2Key {

	public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM2_MAX_PLAINTEXT_SIZE;
	public final static String DEFAULT_ID = GmSSLJNI.SM2_DEFAULT_ID;

	private long sm2_key = 0;
	private boolean has_private_key = false;

	public Sm2Key() {
		this.sm2_key = 0;
	}

	Sm2Key(long sm2_key, boolean has_private_key) {
		this.sm2_key = sm2_key;
		this.has_private_key = has_private_key;
	}

	long getPrivateKey() {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		return this.sm2_key;
	}

	long getPublicKey() {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		return this.sm2_key;
	}

	public void generateKey() {
		if (this.sm2_key != 0) {
			GmSSLJNI.sm2_key_free(this.sm2_key);
		}
		if ((sm2_key = GmSSLJNI.sm2_key_generate()) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = true;
	}

	public void importPrivateKeyInfoDer(byte[] der) {
		if (der == null) {
			throw new GmSSLException("");
		}
		if (this.sm2_key != 0) {
			GmSSLJNI.sm2_key_free(this.sm2_key);
		}
		if ((this.sm2_key = GmSSLJNI.sm2_private_key_info_from_der(der)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = true;
	}

	public byte[] exportPrivateKeyInfoDer() {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		byte[] der;
		if ((der = GmSSLJNI.sm2_private_key_info_to_der(this.sm2_key)) == null) {
			throw new GmSSLException("");
		}
		return der;
	}

	public void importPublicKeyInfoDer(byte[] der) {
		if (der == null) {
			throw new GmSSLException("");
		}
		if (this.sm2_key != 0) {
			GmSSLJNI.sm2_key_free(this.sm2_key);
		}
		if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_der(der)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = false;
	}

	public byte[] exportPublicKeyInfoDer() {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		byte[] der;
		if ((der = GmSSLJNI.sm2_public_key_info_to_der(this.sm2_key)) == null) {
			throw new GmSSLException("");
		}
		return der;
	}

	public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm2_key != 0) {
			GmSSLJNI.sm2_key_free(this.sm2_key);
		}
		if ((sm2_key = GmSSLJNI.sm2_private_key_info_decrypt_from_pem(pass, file)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = true;
	}

	public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm2_private_key_info_encrypt_to_pem(this.sm2_key, pass, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public void importPublicKeyInfoPem(String file) {
		if (this.sm2_key != 0) {
			GmSSLJNI.sm2_key_free(this.sm2_key);
		}
		if ((this.sm2_key = GmSSLJNI.sm2_public_key_info_from_pem(file)) == 0) {
			throw new GmSSLException("");
		}
		this.has_private_key = false;
	}

	public void exportPublicKeyInfoPem(String file) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (GmSSLJNI.sm2_public_key_info_to_pem(this.sm2_key, file) != 1) {
			throw new GmSSLException("");
		}
	}

	public byte[] computeZ(String id) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		byte[] z = new byte[Sm3.DIGEST_SIZE];
		if (GmSSLJNI.sm2_compute_z(this.sm2_key, id, z) != 1) {
			throw new GmSSLException("");
		}
		return z;
	}

	public byte[] sign(byte[] dgst) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}

		if (dgst == null || dgst.length != Sm3.DIGEST_SIZE) {
			throw new GmSSLException("");
		}

		byte[] sig;
		if ((sig = GmSSLJNI.sm2_sign(this.sm2_key, dgst)) == null) {
			throw new GmSSLException("");
		}
		return sig;
	}

	public boolean verify(byte[] dgst, byte[] signature) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (dgst == null
			|| dgst.length != Sm3.DIGEST_SIZE
			|| signature == null) {
			throw new GmSSLException("");
		}

		int ret;
		if ((ret = GmSSLJNI.sm2_verify(this.sm2_key, dgst, signature)) < 0) {
			throw new GmSSLException("");
		}
		if (ret > 0) {
			return true;
		} else {
			return false;
		}
	}

	public byte[] encrypt(byte[] plaintext) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (plaintext == null
			|| plaintext.length > this.MAX_PLAINTEXT_SIZE) {
			throw new GmSSLException("");
		}

		byte[] ciphertext;
		if ((ciphertext = GmSSLJNI.sm2_encrypt(this.sm2_key, plaintext)) == null) {
			throw new GmSSLException("");
		}
		return ciphertext;
	}

	public byte[] decrypt(byte[] ciphertext) {
		if (this.sm2_key == 0) {
			throw new GmSSLException("");
		}
		if (this.has_private_key == false) {
			throw new GmSSLException("");
		}
		if (ciphertext == null) {
			throw new GmSSLException("");
		}

		byte[] plaintext;
		if ((plaintext = GmSSLJNI.sm2_decrypt(this.sm2_key, ciphertext)) == null) {
			throw new GmSSLException("");
		}
		return plaintext;
	}
}
