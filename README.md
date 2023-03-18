# GmSSL Java

本项目是GmSSL密码库接口的Java语言封装，可以用于Java及Android平台上的应用开发。GmSSL JNI提供了包括随机数生成、对称加解密、哈希、消息认证码(MAC)、公钥加解密、数字签名、密钥交换等基础密码功能的Java语言接口，支持包括SM2/SM3/SM4/ZUC在内的GmSSL密码库的主要密码算法。

GmSSL Java包含的功能如下：

 * 随机数生成
 * SM3哈希、SM3 HMAC 和 SM3 PBKDF2密钥导出
 * SM4分组密码和SM4 CBC/CTR/GCM模式
 * SM2签名、加密
 * SM9签名、加密
 * ZUC序列密码加密
 * SM2证书的解析、验证

## 接口说明

GmSSL Java Wrapper的接口如下：

```java
package org.gmssl;

public class GmSSLJNI {

	public final static String GMSSL_JNI_VERSION = "GmSSL JNI 2.0.0";

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

	static {
		System.loadLibrary("gmssljni");
	}
}
```

### 返回值

Java返回值和GmSSL C函数返回值保持一致

### Roadmap

[] Update C API
[] New Java API
[] Include GmSSL in this repo


