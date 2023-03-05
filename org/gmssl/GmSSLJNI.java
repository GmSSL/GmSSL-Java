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

	public final static String GMSSL_JNI_VERSION = "GmSSL-JNI API/2.0"

	public final static int SM3_DIGEST_SIZE = 32;
	public final static int SM3_HMAC_SIZE = 32;
	public final static int SM4_KEY_SIZE = 16;
	public final static int SM4_BLOCK_SIZE = 16;
	public final static int SM4_GCM_MIN_IV_SIZE = 1;
	public final static int SM4_GCM_MAX_IV_SIZE = 64;
	public final static int SM4_GCM_DEFAULT_IV_SIZE = 12;
	public final static int SM4_GCM_DEFAULT_TAG_SIZE = 16;
	public final static int SM4_GCM_MAX_TAG_SIZE = 16;
	public final static int SM2_MIN_PLAINTEXT_SIZE = 1;
	public final static int SM2_MAX_PLAINTEXT_SIZE = 255;
	public final static String SM2_DEFAULT_ID = "1234567812345678";

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
	public final static native int sm4_gcm_encrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, int taglen);
	public final static native int sm4_gcm_encrypt_update(long sm4_gcm_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_gcm_encrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset);
	public final static native int sm4_gcm_decrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, int taglen);
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

	static {
		System.loadLibrary("gmssljni");
	}
}
