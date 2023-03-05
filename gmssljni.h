/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_gmssl_GmSSLJNI */

#ifndef _Included_org_gmssl_GmSSLJNI
#define _Included_org_gmssl_GmSSLJNI
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    version_num
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_version_1num
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    version_str
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_gmssl_GmSSLJNI_version_1str
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    rand_bytes
 * Signature: ([BIJ)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_rand_1bytes
  (JNIEnv *, jclass, jbyteArray, jint, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm3_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm3_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1init
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1finish
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_init
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1init
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1finish
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_key_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1key_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_set_encrypt_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1set_1encrypt_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_set_decrypt_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1set_1decrypt_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_encrypt
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1encrypt
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_init
 * Signature: (J[B[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_init
 * Signature: (J[B[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1init
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1key_1generate
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm2_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_private_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1private_1key_1info_1encrypt_1to_1pem
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_private_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1private_1key_1info_1decrypt_1from_1pem
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_public_key_info_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1public_1key_1info_1to_1pem
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_public_key_info_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1public_1key_1info_1from_1pem
  (JNIEnv *, jclass, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_compute_z
 * Signature: (JLjava/lang/String;[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1compute_1z
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify
  (JNIEnv *, jclass, jlong, jbyteArray, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_encrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1encrypt
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_decrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1decrypt
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_init
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1init
  (JNIEnv *, jclass, jlong, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_finish
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1finish
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_init
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1init
  (JNIEnv *, jclass, jlong, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1finish
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1generate
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1info_1encrypt_1to_1pem
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1info_1decrypt_1from_1pem
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_public_key_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1public_1key_1to_1pem
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_public_key_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1public_1key_1from_1pem
  (JNIEnv *, jclass, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_extract_key
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1extract_1key
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1info_1encrypt_1to_1pem
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1info_1decrypt_1from_1pem
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1ctx_1new
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1ctx_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1init
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_finish
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1finish
  (JNIEnv *, jclass, jlong, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1init
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1update
  (JNIEnv *, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_finish
 * Signature: (J[BJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1finish
  (JNIEnv *, jclass, jlong, jbyteArray, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1generate
  (JNIEnv *, jclass);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1info_1encrypt_1to_1pem
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1info_1decrypt_1from_1pem
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_public_key_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1public_1key_1to_1pem
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_public_key_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1public_1key_1from_1pem
  (JNIEnv *, jclass, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_extract_key
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1extract_1key
  (JNIEnv *, jclass, jlong, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1free
  (JNIEnv *, jclass, jlong);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1info_1encrypt_1to_1pem
  (JNIEnv *, jclass, jlong, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1info_1decrypt_1from_1pem
  (JNIEnv *, jclass, jstring, jstring);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_encrypt
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1encrypt
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_decrypt
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1decrypt
  (JNIEnv *, jclass, jlong, jstring, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif
