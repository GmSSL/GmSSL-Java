/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl;

public class GmSSLJNI {

	public final static String GMSSL_JNI_VERSION = "GmSSL JNI 2.1.0 dev";

	public final static int SM3_DIGEST_SIZE = 32;
	public final static int SM3_HMAC_SIZE = 32;
	public final static int SM3_HMAC_MIN_KEY_SIZE = 16;
	public final static int SM4_KEY_SIZE = 16;
	public final static int SM4_BLOCK_SIZE = 16;
	public final static int SM4_GCM_MIN_IV_SIZE = 1;
	public final static int SM4_GCM_MAX_IV_SIZE = 64;
	public final static int SM4_GCM_DEFAULT_IV_SIZE = 12;
	public final static int SM4_GCM_MAX_TAG_SIZE = 16;
	public final static String SM2_DEFAULT_ID = "1234567812345678";
	public final static int SM2_MAX_PLAINTEXT_SIZE = 255;
	public final static int SM9_MAX_PLAINTEXT_SIZE = 255;
	public final static int ZUC_KEY_SIZE = 16;
	public final static int ZUC_IV_SIZE = 16;

	public final static native int version_num();
	public final static native String version_str();
	public final static native int rand_bytes(byte[] buf, int offset, long nbytes);
	public final static native long sm3_ctx_new();
	public final static native void sm3_ctx_free(long sm3_ctx);
	public final static native int sm3_init(long sm3_ctx);
	public final static native int sm3_update(long sm3_ctx, byte[] data, int offset, int datalen);
	public final static native int sm3_finish(long sm3_ctx, byte[] dgst);
	public final static native long sm3_hmac_ctx_new();
	public final static native void sm3_hmac_ctx_free(long sm3_hmac_ctx);
	public final static native int sm3_hmac_init(long sm3_hmac_ctx, byte[] key);
	public final static native int sm3_hmac_update(long sm3_hmac_ctx, byte[] data, int offset, int datalen);
	public final static native int sm3_hmac_finish(long sm3_hmac_ctx, byte[] hmac);
	public final static native long sm4_key_new();
	public final static native void sm4_key_free(long sm4_key);
	public final static native int sm4_set_encrypt_key(long sm4_key, byte[] key);
	public final static native int sm4_set_decrypt_key(long sm4_key, byte[] key);
	public final static native int sm4_encrypt(long sm4_key, byte[] in, int in_offset, byte[] out, int out_offset);
	public final static native long sm4_cbc_ctx_new();
	public final static native void sm4_cbc_ctx_free(long sm4_cbc_ctx);
	public final static native int sm4_cbc_encrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv);
	public final static native int sm4_cbc_encrypt_update(long sm4_cbc_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_cbc_encrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset);
	public final static native int sm4_cbc_decrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv);
	public final static native int sm4_cbc_decrypt_update(long sm4_cbc_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_cbc_decrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset);
	public final static native long sm4_ctr_ctx_new();
	public final static native void sm4_ctr_ctx_free(long sm4_ctr_ctx);
	public final static native int sm4_ctr_encrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv);
	public final static native int sm4_ctr_encrypt_update(long sm4_ctr_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_ctr_encrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset);
	public final static native int sm4_ctr_decrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv);
	public final static native int sm4_ctr_decrypt_update(long sm4_ctr_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_ctr_decrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset);
	public final static native long sm4_gcm_ctx_new();
	public final static native void sm4_gcm_ctx_free(long sm4_gcm_ctx);
	public final static native int sm4_gcm_encrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int taglen);
	public final static native int sm4_gcm_encrypt_update(long sm4_gcm_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_gcm_encrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset);
	public final static native int sm4_gcm_decrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int taglen);
	public final static native int sm4_gcm_decrypt_update(long sm4_gcm_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_gcm_decrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset);
	public final static native long sm2_key_generate();
	public final static native void sm2_key_free(long sm2_key);
	public final static native int sm2_private_key_info_encrypt_to_pem(long sm2_key, String pass, String file);
	public final static native long sm2_private_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm2_public_key_info_to_pem(long sm2_key, String file);
	public final static native long sm2_public_key_info_from_pem(String file);
	public final static native int sm2_compute_z(long sm2_key, String id, byte[] z);
	public final static native byte[] sm2_sign(long sm2_key, byte[] dgst);
	public final static native int sm2_verify(long sm2_key, byte[] dgst, byte[] sig);
	public final static native byte[] sm2_encrypt(long sm2_key, byte[] in);
	public final static native byte[] sm2_decrypt(long sm2_key, byte[] in);
	public final static native long sm2_sign_ctx_new();
	public final static native void sm2_sign_ctx_free(long sm2_sign_ctx);
	public final static native int sm2_sign_init(long sm2_sign_ctx, long sm2_key, String id);
	public final static native int sm2_sign_update(long sm2_sign_ctx, byte[] data, int offset, int length);
	public final static native byte[] sm2_sign_finish(long sm2_sign_ctx);
	public final static native int sm2_verify_init(long sm2_sign_ctx, long sm2_key, String id);
	public final static native int sm2_verify_update(long sm2_sign_ctx, byte[] data, int offset, int length);
	public final static native int sm2_verify_finish(long sm2_sign_ctx, byte[] sig);
	public final static native long sm9_sign_master_key_generate();
	public final static native void sm9_sign_master_key_free(long sm9_sign_master_key);
	public final static native int sm9_sign_master_key_info_encrypt_to_pem(long sm9_sign_master_key, String pass, String file);
	public final static native long sm9_sign_master_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm9_sign_master_public_key_to_pem(long sm9_sign_master_pub, String file);
	public final static native long sm9_sign_master_public_key_from_pem(String file);
	public final static native long sm9_sign_master_key_extract_key(long sm9_sign_master_key, String id);
	public final static native void sm9_sign_key_free(long sm9_sign_key);
	public final static native int sm9_sign_key_info_encrypt_to_pem(long sm9_sign_key, String pass, String file);
	public final static native long sm9_sign_key_info_decrypt_from_pem(String pass, String file);
	public final static native long sm9_sign_ctx_new();
	public final static native void sm9_sign_ctx_free(long sm9_sign_ctx);
	public final static native int sm9_sign_init(long sm9_sign_ctx);
	public final static native int sm9_sign_update(long sm9_sign_ctx, byte[] data, int offset, int length);
	public final static native byte[] sm9_sign_finish(long sm9_sign_ctx, long sm9_sign_key);
	public final static native int sm9_verify_init(long sm9_sign_ctx);
	public final static native int sm9_verify_update(long sm9_sign_ctx, byte[] data, int offset, int length);
	public final static native int sm9_verify_finish(long sm9_sign_ctx, byte[] sig, long sm9_sign_master_pub, String id);
	public final static native long sm9_enc_master_key_generate();
	public final static native void sm9_enc_master_key_free(long sm9_enc_master_key);
	public final static native int sm9_enc_master_key_info_encrypt_to_pem(long sm9_enc_master_key, String pass, String file);
	public final static native long sm9_enc_master_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm9_enc_master_public_key_to_pem(long sm9_enc_master_pub, String file);
	public final static native long sm9_enc_master_public_key_from_pem(String file);
	public final static native long sm9_enc_master_key_extract_key(long sm9_enc_master_key, String id);
	public final static native void sm9_enc_key_free(long sm9_sign_key);
	public final static native int sm9_enc_key_info_encrypt_to_pem(long sm9_enc_key, String pass, String file);
	public final static native long sm9_enc_key_info_decrypt_from_pem(String pass, String file);
	public final static native byte[] sm9_encrypt(long sm9_enc_master_pub, String id, byte[] in);
	public final static native byte[] sm9_decrypt(long sm9_enc_key, String id, byte[] in);

	public final static native byte[] cert_from_pem(String file);
	public final static native int cert_to_pem(byte[] cert, String file);
	public final static native byte[] cert_get_serial_number(byte[] cert);
	public final static native String[] cert_get_issuer(byte[] cert);
	public final static native String[] cert_get_subject(byte[] cert);
	public final static native long cert_get_not_before(byte[] cert);
	public final static native long cert_get_not_after(byte[] cert);
	public final static native long cert_get_subject_public_key(byte[] cert);
	public final static native int cert_verify_by_ca_cert(byte[] cert, byte[] cacert, String ca_sm2_id);

	public static void print_bytes(String label, byte[] data) {
		int i;
		System.out.printf("%s: ", label);
		for (i = 0; i < data.length; i++) {
			System.out.printf("%02x", data[i]);
		}
		System.out.print("\n");
	}

	public static void print_bytes_ex(String label, byte[] data, int offset, int len) {
		int i;
		System.out.printf("%s: ", label);
		for (i = 0; i < len; i++) {
			System.out.printf("%02x", data[offset + i]);
		}
		System.out.print("\n");
	}

	public static void main(String[] args) {
		int i;
		final GmSSLJNI gmssl = new GmSSLJNI();

		System.out.println(gmssl.version_num());
		System.out.println(gmssl.version_str());

		byte[] key = new byte[SM4_KEY_SIZE];
		rand_bytes(key, 0, gmssl.SM4_KEY_SIZE);

		print_bytes("rand_bytes(16)", key);

		long sm3_ctx = sm3_ctx_new();
		byte[] dgst = new byte[SM3_DIGEST_SIZE];
		sm3_init(sm3_ctx);
		sm3_update(sm3_ctx, "abc".getBytes(), 0, 3);
		sm3_finish(sm3_ctx, dgst);
		print_bytes("sm3('abc')", dgst);

		long sm3_hmac_ctx = sm3_hmac_ctx_new();
		byte[] hmac = new byte[SM3_HMAC_SIZE];
		sm3_hmac_init(sm3_hmac_ctx, key);
		sm3_hmac_update(sm3_hmac_ctx, "abc".getBytes(), 0, 3);
		sm3_hmac_finish(sm3_hmac_ctx, hmac);
		print_bytes("sm3_hmac('abc')", hmac);

		long sm4_key = sm4_key_new();
		sm4_set_encrypt_key(sm4_key, key);
		byte[] block = new byte[SM4_BLOCK_SIZE];
		rand_bytes(block, 0, block.length);
		print_bytes("sm4 plain", block);
		byte[] out_block = new byte[SM4_BLOCK_SIZE];
		sm4_encrypt(sm4_key, block, 0, out_block, 0);
		sm4_set_decrypt_key(sm4_key, key);
		byte[] plain_block = new byte[SM4_BLOCK_SIZE];
		sm4_encrypt(sm4_key, out_block, 0, plain_block, 0);
		print_bytes("sm4 decrypt", plain_block);

		byte[] iv = new byte[SM4_BLOCK_SIZE];
		byte[] buf = new byte[100];
		byte[] plain = new byte[100];
		int outlen;
		int left;
		int cipherlen;
		int plainlen;

		long sm4_cbc_ctx = sm4_cbc_ctx_new();
		sm4_cbc_encrypt_init(sm4_cbc_ctx, key, iv);
		outlen = sm4_cbc_encrypt_update(sm4_cbc_ctx, "abc".getBytes(), 0, 3, buf, 0);
		left = sm4_cbc_encrypt_finish(sm4_cbc_ctx, buf, outlen);
		cipherlen = outlen + left;
		print_bytes_ex("ciphertext", buf, 0, cipherlen);
		sm4_cbc_decrypt_init(sm4_cbc_ctx, key, iv);
		outlen = sm4_cbc_decrypt_update(sm4_cbc_ctx, buf, 0, cipherlen, plain, 0);
		left = sm4_cbc_decrypt_finish(sm4_cbc_ctx, plain, outlen);
		plainlen = outlen + left;
		print_bytes_ex("plaintext", plain, 0, plainlen);

		long sm4_ctr_ctx = sm4_ctr_ctx_new();
		sm4_ctr_encrypt_init(sm4_ctr_ctx, key, iv);
		outlen = sm4_ctr_encrypt_update(sm4_ctr_ctx, "abc".getBytes(), 0, 3, buf, 0);
		left = sm4_ctr_encrypt_finish(sm4_ctr_ctx, buf, outlen);
		cipherlen = outlen + left;
		print_bytes_ex("ciphertext", buf, 0, cipherlen);
		sm4_ctr_decrypt_init(sm4_ctr_ctx, key, iv);
		outlen = sm4_ctr_decrypt_update(sm4_ctr_ctx, buf, 0, cipherlen, plain, 0);
		left = sm4_ctr_decrypt_finish(sm4_ctr_ctx, plain, outlen);
		plainlen = outlen + left;
		print_bytes_ex("plaintext", plain, 0, plainlen);


		long sm4_gcm_ctx = sm4_gcm_ctx_new();
		byte[] aad = "aad".getBytes();
		sm4_gcm_encrypt_init(sm4_gcm_ctx, key, iv, aad, SM4_GCM_MAX_TAG_SIZE);
		outlen = sm4_gcm_encrypt_update(sm4_gcm_ctx, "abc".getBytes(), 0, 3, buf, 0);
		left = sm4_gcm_encrypt_finish(sm4_gcm_ctx, buf, outlen);
		cipherlen = outlen + left;
		print_bytes_ex("gcm ciphertext", buf, 0, cipherlen);
		sm4_gcm_decrypt_init(sm4_gcm_ctx, key, iv, aad, SM4_GCM_MAX_TAG_SIZE);
		outlen = sm4_gcm_decrypt_update(sm4_gcm_ctx, buf, 0, cipherlen, plain, 0);
		left = sm4_gcm_decrypt_finish(sm4_gcm_ctx, plain, outlen);
		plainlen = outlen + left;
		print_bytes_ex("gcm plaintext", plain, 0, plainlen);




		long sm2_key;
		long sm2_pub;
		String pass = "123456";
		byte[] z = new byte[32];
		byte[] sig;
		int verify_ret;

		sm2_key = sm2_key_generate();
		sm2_private_key_info_encrypt_to_pem(sm2_key, pass, "sm2.pem");
		sm2_key = sm2_private_key_info_decrypt_from_pem(pass, "sm2.pem");
		sm2_public_key_info_to_pem(sm2_key, "sm2pub.pem");
		sm2_pub = sm2_public_key_info_from_pem("sm2pub.pem");

		sm2_compute_z(sm2_pub, SM2_DEFAULT_ID, z);
		print_bytes("z", z);

		sig = sm2_sign(sm2_key, dgst);
		verify_ret = sm2_verify(sm2_pub, dgst, sig);
		System.out.println(verify_ret);

		long sm2_sign_ctx = sm2_sign_ctx_new();

		sm2_sign_init(sm2_sign_ctx, sm2_key, SM2_DEFAULT_ID);
		sm2_sign_update(sm2_sign_ctx, "abc".getBytes(), 0, 3);
		sig = sm2_sign_finish(sm2_sign_ctx);

		sm2_verify_init(sm2_sign_ctx, sm2_pub, SM2_DEFAULT_ID);
		sm2_verify_update(sm2_sign_ctx, "abc".getBytes(), 0, 3);
		verify_ret = sm2_verify_finish(sm2_sign_ctx, sig);
		System.out.println(verify_ret);

		byte[] sm2_cipher = sm2_encrypt(sm2_pub, "abc".getBytes());
		byte[] sm2_plain = sm2_decrypt(sm2_key, sm2_cipher);
		print_bytes("sm2_plain", sm2_plain);


		long sm9_master;
		long sm9_master_pub;
		long sm9_key;
		long sm9_ctx;
		byte[] sm9_sig;

		sm9_master = sm9_sign_master_key_generate();
		sm9_sign_master_key_info_encrypt_to_pem(sm9_master, "1234", "sm9.pem");
		sm9_master = sm9_sign_master_key_info_decrypt_from_pem("1234", "sm9.pem");
		sm9_sign_master_public_key_to_pem(sm9_master, "sm9pub.pem");
		sm9_master_pub = sm9_sign_master_public_key_from_pem("sm9pub.pem");
		sm9_key = sm9_sign_master_key_extract_key(sm9_master, "Alice");
		sm9_sign_key_info_encrypt_to_pem(sm9_key, "1234", "sm9key.pem");
		sm9_key = sm9_sign_key_info_decrypt_from_pem("1234", "sm9key.pem");
		sm9_ctx = sm9_sign_ctx_new();
		sm9_sign_init(sm9_ctx);
		sm9_sign_update(sm9_ctx, "abc".getBytes(), 0, 3);
		sm9_sig = sm9_sign_finish(sm9_ctx, sm9_key);

		sm9_verify_init(sm9_ctx);
		sm9_verify_update(sm9_ctx, "abc".getBytes(), 0, 3);
		verify_ret = sm9_verify_finish(sm9_ctx, sm9_sig, sm9_master_pub, "Alice");
		System.out.println(verify_ret);

		sm9_master = sm9_enc_master_key_generate();
		sm9_enc_master_key_info_encrypt_to_pem(sm9_master, "1234", "sm9.pem");
		sm9_master = sm9_enc_master_key_info_decrypt_from_pem("1234", "sm9.pem");
		sm9_enc_master_public_key_to_pem(sm9_master, "sm9pub.pem");
		sm9_master_pub = sm9_enc_master_public_key_from_pem("sm9pub.pem");
		sm9_key = sm9_enc_master_key_extract_key(sm9_master, "Alice");
		sm9_enc_key_info_encrypt_to_pem(sm9_key, "1234", "sm9key.pem");
		sm9_key = sm9_enc_key_info_decrypt_from_pem("1234", "sm9key.pem");

		byte[] sm9_cipher = sm9_encrypt(sm9_master_pub, "Alice", "abc".getBytes());
		byte[] sm9_plain = sm9_decrypt(sm9_key, "Alice", sm9_cipher);

		print_bytes("sm9_plain", sm9_plain);

		byte[] cert = cert_from_pem("ROOTCA.pem");
		cert_to_pem(cert, "cert.pem");
		byte[] serial = cert_get_serial_number(cert);
		print_bytes("serialNumber", serial);
		String[] subject = cert_get_subject(cert);
		for (i = 0; i < subject.length; i++) {
			System.out.println("  "+subject[i]);
		}
		String[] issuer = cert_get_subject(cert);
		for (i = 0; i < issuer.length; i++) {
			System.out.println("  "+issuer[i]);
		}
		long not_before = cert_get_not_before(cert);
		long not_after = cert_get_not_after(cert);
		System.out.println(not_before);
		System.out.println("not_before " + new java.util.Date(not_before * 1000));
		System.out.println("not_after " + new java.util.Date(not_after * 1000));
		sm2_pub = cert_get_subject_public_key(cert);
		int cert_verify = cert_verify_by_ca_cert(cert, cert, SM2_DEFAULT_ID);
		System.out.println("verify result " + cert_verify);
	}

	static {
		System.loadLibrary("gmssljni");
	}
}
