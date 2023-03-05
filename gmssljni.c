#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/sm9.h>
#include <gmssl/zuc.h>
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include <gmssl/aead.h>
#include <gmssl/error.h>
#include <gmssl/version.h>
#include "gmssljni.h"



JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    version_num
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_version_1num(
	JNIEnv *env, jclass this)
{
	return (jint)gmssl_version_num();
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    version_str
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_gmssl_GmSSLJNI_version_1str(
	JNIEnv *env, jclass this)
{
	return NULL;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    rand_bytes
 * Signature: ([BIJ)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_rand_1bytes(
	JNIEnv *env, jclass this,
	jbyteArray out, jint offset, jlong length)
{
	int ret = -1;
	uint8_t *buf = NULL;
	jsize buflen;

	if (!(buf = (uint8_t *)(*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, out)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	if (rand_bytes(buf + offset, length) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, out, (jbyte *)buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm3_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm3_ctx;

	if (!(sm3_ctx = (jlong)malloc(sizeof(SM3_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM3_CTX *)sm3_ctx, 0, sizeof(SM3_CTX));
	return sm3_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm3_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm3_ctx)
{
	if (sm3_ctx) {
		gmssl_secure_clear((SM3_CTX *)sm3_ctx, sizeof(SM3_CTX));
		free((SM3_CTX *)sm3_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1init(
	JNIEnv *env, jclass this,
	jlong sm3_ctx)
{
	if (!sm3_ctx) {
		error_print();
		return -1;
	}
	sm3_init((SM3_CTX *)sm3_ctx);
	return 1;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1update(
	JNIEnv *env, jclass this,
	jlong sm3_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm3_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	sm3_update((SM3_CTX *)sm3_ctx, (uint8_t *)buf + offset, (size_t)length);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1finish(
	JNIEnv *env, jclass this,
	jlong sm3_ctx, jbyteArray dgst)
{
	jint ret = -1;
	jbyte *buf = NULL;

	if (!sm3_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, dgst, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, dgst) < SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}
	sm3_finish((SM3_CTX *)sm3_ctx, (uint8_t *)buf);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, dgst, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm3_hmac_ctx;
	if (!(sm3_hmac_ctx = (jlong)malloc(sizeof(SM3_HMAC_CTX)))) {
		error_print();
		return 0;
	}
	return sm3_hmac_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm3_hmac_ctx)
{
	if (sm3_hmac_ctx) {
		gmssl_secure_clear((SM3_HMAC_CTX *)sm3_hmac_ctx, sizeof(SM3_HMAC_CTX));
		free((SM3_HMAC_CTX *)sm3_hmac_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_init
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1init(
	JNIEnv *env, jclass this,
	jlong sm3_hmac_ctx, jbyteArray key)
{
	int ret = -1;
	jbyte *buf = NULL;
	jlong buflen;

	if (!sm3_hmac_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	buflen = (*env)->GetArrayLength(env, key);
	if (buflen < 1 || buflen > 64) {
		error_print();
		goto end;
	}
	sm3_hmac_init((SM3_HMAC_CTX *)sm3_hmac_ctx, (uint8_t *)buf, (size_t)buflen);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, key, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1update(
	JNIEnv *env, jclass this,
	jlong sm3_hmac_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm3_hmac_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	sm3_hmac_update((SM3_HMAC_CTX *)sm3_hmac_ctx, (uint8_t *)buf + offset, (size_t)length);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm3_hmac_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm3_1hmac_1finish(
	JNIEnv *env, jclass this,
	jlong sm3_hmac_ctx, jbyteArray hmac)
{
	jint ret = -1;
	jbyte *buf = NULL;

	if (!sm3_hmac_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, hmac, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, hmac) < SM3_HMAC_SIZE) {
		error_print();
		goto end;
	}
	sm3_hmac_finish((SM3_HMAC_CTX *)sm3_hmac_ctx, (uint8_t *)buf);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, hmac, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_key_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1key_1new(
	JNIEnv *env, jclass this)
{
	jlong sm4_key;

	if (!(sm4_key = (jlong)malloc(sizeof(SM4_KEY)))) {
		error_print();
		return 0;
	}
	memset((SM4_KEY *)sm4_key, 0, sizeof(SM4_KEY));
	return sm4_key;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm4_key)
{
	if (sm4_key) {
		gmssl_secure_clear((SM4_KEY *)sm4_key, sizeof(SM4_KEY));
		free((SM4_KEY *)sm4_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_set_encrypt_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1set_1encrypt_1key(
	JNIEnv *env, jclass this,
	jlong sm4_key, jbyteArray key)
{
	jint ret = -1;
	jbyte *buf = NULL;

	if (!sm4_key) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	sm4_set_encrypt_key((SM4_KEY *)sm4_key, (uint8_t *)buf);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, key, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_set_decrypt_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1set_1decrypt_1key(
	JNIEnv *env, jclass this,
	jlong sm4_key, jbyteArray key)
{
	jint ret = -1;
	jbyte *buf = NULL;

	if (!sm4_key) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	sm4_set_decrypt_key((SM4_KEY *)sm4_key, (uint8_t *)buf);
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, key, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_encrypt
 * Signature: (J[BI[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1encrypt(
	JNIEnv *env, jclass this,
	jlong sm4_key,
	jbyteArray in, jint in_offset,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	jsize inbuflen, outbuflen;

	if (!sm4_key) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	inbuflen = (*env)->GetArrayLength(env, in);
	if (inbuflen < SM4_BLOCK_SIZE + in_offset) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	outbuflen = (*env)->GetArrayLength(env, out);
	if (outbuflen < SM4_BLOCK_SIZE + out_offset) {
		error_print();
		goto end;
	}
	sm4_encrypt((SM4_KEY *)sm4_key, (uint8_t *)inbuf + in_offset, (uint8_t *)outbuf + out_offset);
	ret = 1;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm4_cbc_ctx;

	if (!(sm4_cbc_ctx = (jlong)malloc(sizeof(SM4_CBC_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM4_CBC_CTX *)sm4_cbc_ctx, 0, sizeof(SM4_CBC_CTX));
	return sm4_cbc_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx)
{
	if (sm4_cbc_ctx) {
		gmssl_secure_clear((SM4_CBC_CTX *)sm4_cbc_ctx, sizeof(SM4_CBC_CTX));
		free((SM4_CBC_CTX *)sm4_cbc_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx, jbyteArray key, jbyteArray iv)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, iv) < SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_encrypt_init((SM4_CBC_CTX *)sm4_cbc_ctx, (uint8_t *)keybuf, (uint8_t *)ivbuf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx,
	jbyteArray in, jint in_offset, jint inlen,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_encrypt_update((SM4_CBC_CTX *)sm4_cbc_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1encrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_encrypt_finish((SM4_CBC_CTX *)sm4_cbc_ctx,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx, jbyteArray key, jbyteArray iv)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, iv) < SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_decrypt_init((SM4_CBC_CTX *)sm4_cbc_ctx, (uint8_t *)keybuf, (uint8_t *)ivbuf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx,
	jbyteArray in, jint in_offset, jint inlen, jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_decrypt_update((SM4_CBC_CTX *)sm4_cbc_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_cbc_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1cbc_1decrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_cbc_ctx, jbyteArray out, jint offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_cbc_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < offset + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_cbc_decrypt_finish((SM4_CBC_CTX *)sm4_cbc_ctx,
		(uint8_t *)outbuf + offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm4_ctr_ctx;

	if (!(sm4_ctr_ctx = (jlong)malloc(sizeof(SM4_CTR_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM4_CTR_CTX *)sm4_ctr_ctx, 0, sizeof(SM4_CTR_CTX));
	return sm4_ctr_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx)
{
	if (sm4_ctr_ctx) {
		gmssl_secure_clear((SM4_CTR_CTX *)sm4_ctr_ctx, sizeof(SM4_CTR_CTX));
		free((SM4_CTR_CTX *)sm4_ctr_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx, jbyteArray key, jbyteArray iv)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, iv) < SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_encrypt_init((SM4_CTR_CTX *)sm4_ctr_ctx, (uint8_t *)keybuf, (uint8_t *)ivbuf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx,
	jbyteArray in, jint in_offset, jint inlen,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_encrypt_update((SM4_CTR_CTX *)sm4_ctr_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1encrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx, jbyteArray out, jint offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < offset + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_encrypt_finish((SM4_CTR_CTX *)sm4_ctr_ctx,
		(uint8_t *)outbuf + offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_init
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx, jbyteArray key, jbyteArray iv)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, iv) < SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_decrypt_init((SM4_CTR_CTX *)sm4_ctr_ctx, (uint8_t *)keybuf, (uint8_t *)ivbuf) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx,
	jbyteArray in, jint in_offset, jint inlen,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_decrypt_update((SM4_CTR_CTX *)sm4_ctr_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_ctr_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1ctr_1decrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_ctr_ctx, jbyteArray out, jint offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_ctr_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < offset + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_ctr_decrypt_finish((SM4_CTR_CTX *)sm4_ctr_ctx,
		(uint8_t *)outbuf + offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm4_gcm_ctx;

	if (!(sm4_gcm_ctx = (jlong)malloc(sizeof(SM4_GCM_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM4_GCM_CTX *)sm4_gcm_ctx, 0, sizeof(SM4_GCM_CTX));
	return sm4_gcm_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx)
{
	if (sm4_gcm_ctx) {
		gmssl_secure_clear((SM4_GCM_CTX *)sm4_gcm_ctx, sizeof(SM4_GCM_CTX));
		free((SM4_GCM_CTX *)sm4_gcm_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_init
 * Signature: (J[B[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx, jbyteArray key, jbyteArray iv, jint taglen)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;
	jsize ivlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	ivlen = (*env)->GetArrayLength(env, iv);
	if (sm4_gcm_encrypt_init((SM4_GCM_CTX *)sm4_gcm_ctx, (uint8_t *)keybuf, SM4_KEY_SIZE, (uint8_t *)ivbuf, (size_t)ivlen, NULL, 0, (size_t)taglen) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx,
	jbyteArray in, jint in_offset, jint inlen,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_gcm_encrypt_update((SM4_GCM_CTX *)sm4_gcm_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_encrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1encrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx, jbyteArray out, jint offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < offset + SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_gcm_encrypt_finish((SM4_GCM_CTX *)sm4_gcm_ctx,
		(uint8_t *)outbuf + offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_init
 * Signature: (J[B[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1init(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx, jbyteArray key, jbyteArray iv, jint taglen)
{
	jint ret = -1;
	jbyte *keybuf = NULL;
	jbyte *ivbuf = NULL;
	jsize ivlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(keybuf = (*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, key) < SM4_KEY_SIZE) {
		error_print();
		goto end;
	}
	if (!(ivbuf = (*env)->GetByteArrayElements(env, iv, 0))) {
		error_print();
		goto end;
	}
	ivlen = (*env)->GetArrayLength(env, iv);
	if (sm4_gcm_decrypt_init((SM4_GCM_CTX *)sm4_gcm_ctx, (uint8_t *)keybuf, SM4_KEY_SIZE, (uint8_t *)ivbuf, (size_t)ivlen, NULL, 0, (size_t)taglen) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, keybuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, ivbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_update
 * Signature: (J[BII[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1update(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx, jbyteArray in, jint in_offset, jint inlen,
	jbyteArray out, jint out_offset)
{
	jint ret = -1;
	jbyte *inbuf = NULL;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, in) < in_offset + inlen) {
		error_print();
		goto end;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < out_offset + inlen + SM4_BLOCK_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_gcm_decrypt_update((SM4_GCM_CTX *)sm4_gcm_ctx, (uint8_t *)inbuf + in_offset, (size_t)inlen,
		(uint8_t *)outbuf + out_offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm4_gcm_decrypt_finish
 * Signature: (J[BI)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm4_1gcm_1decrypt_1finish(
	JNIEnv *env, jclass this,
	jlong sm4_gcm_ctx, jbyteArray out, jint offset)
{
	jint ret = -1;
	jbyte *outbuf = NULL;
	size_t outlen;

	if (!sm4_gcm_ctx) {
		error_print();
		return -1;
	}
	if (!(outbuf = (*env)->GetByteArrayElements(env, out, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, out) < offset + SM4_BLOCK_SIZE + SM4_GCM_MAX_TAG_SIZE) {
		error_print();
		goto end;
	}
	if (sm4_gcm_decrypt_finish((SM4_GCM_CTX *)sm4_gcm_ctx,
		(uint8_t *)outbuf + offset, &outlen) != 1) {
		error_print();
		goto end;
	}
	ret = (jint)outlen;
end:
	if (outbuf) (*env)->ReleaseByteArrayElements(env, out, outbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1key_1generate(
	JNIEnv *env, jclass this)
{
	jlong sm2_key;

	if (!(sm2_key = (jlong)malloc(sizeof(SM2_KEY)))) {
		error_print();
		return 0;
	}
	if (sm2_key_generate((SM2_KEY *)sm2_key) != 1) {
		gmssl_secure_clear((SM2_KEY *)sm2_key, sizeof(SM2_KEY));
		error_print();
		return 0;
	}
	return sm2_key;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm2_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm2_key)
{
	if (sm2_key) {
		gmssl_secure_clear((SM2_KEY *)sm2_key, sizeof(SM2_KEY));
		free((SM2_KEY *)sm2_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_private_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1private_1key_1info_1encrypt_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm2_key, jstring pass, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!sm2_key) {
		error_print();
		return -1;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_encrypt_to_pem((SM2_KEY *)sm2_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_private_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1private_1key_1info_1decrypt_1from_1pem(
	JNIEnv *env, jclass this,
	jstring pass, jstring file)
{
	jlong ret = 0;
	SM2_KEY *sm2_key = NULL;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!(sm2_key = (SM2_KEY *)malloc(sizeof(SM2_KEY)))) {
		error_print();
		return 0;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm2_private_key_info_encrypt_to_pem(sm2_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm2_key;
	sm2_key = NULL;
end:
	if (fp) fclose(fp);
	if (sm2_key) {
		gmssl_secure_clear(sm2_key, sizeof(SM2_KEY));
		free(sm2_key);
	}
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_public_key_info_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1public_1key_1info_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm2_pub, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!sm2_pub) {
		error_print();
		return -1;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm2_public_key_info_to_pem((SM2_KEY *)sm2_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_public_key_info_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1public_1key_1info_1from_1pem(
	JNIEnv *env, jclass this,
	jstring file)
{
	jlong ret = 0;
	SM2_KEY *sm2_pub = NULL;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!(sm2_pub = (SM2_KEY *)malloc(sizeof(SM2_KEY)))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm2_public_key_info_from_pem(sm2_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm2_pub;
	sm2_pub = NULL;
end:
	if (fp) fclose(fp);
	if (sm2_pub) {
		gmssl_secure_clear(sm2_pub, sizeof(SM2_KEY));
		free(sm2_pub);
	}
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_compute_z
 * Signature: (JLjava/lang/String;[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1compute_1z(
	JNIEnv *env, jclass this,
	jlong sm2_pub, jstring id, jbyteArray z)
{
	jint ret = -1;
	const char *id_str = NULL;
	jbyte *zbuf = NULL;

	if (!sm2_pub) {
		error_print();
		return -1;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (!(zbuf = (*env)->GetByteArrayElements(env, z, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, z) < SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}
	sm2_compute_z((uint8_t *)zbuf, &((SM2_KEY *)sm2_pub)->public_key, id_str, strlen(id_str));
	ret = 1;
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	if (zbuf) (*env)->ReleaseByteArrayElements(env, z, zbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign(
	JNIEnv *env, jclass this,
	jlong sm2_key, jbyteArray dgst)
{
	jbyteArray ret = NULL;
	jbyte *buf = NULL;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (!sm2_key) {
		error_print();
		return NULL;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, dgst, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, dgst) != SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}
	if (sm2_sign((SM2_KEY *)sm2_key, (uint8_t *)buf, sig, &siglen) != 1) {
		error_print();
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, siglen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, siglen, (jbyte *)sig);
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, dgst, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify
 * Signature: (J[B[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify(
	JNIEnv *env, jclass this,
	jlong sm2_pub, jbyteArray dgst, jbyteArray sig)
{
	jint ret = -1;
	jbyte *dgstbuf = NULL;
	jbyte *sigbuf = NULL;
	jsize siglen;

	if (!sm2_pub) {
		error_print();
		return ret;
	}
	if (!(dgstbuf = (*env)->GetByteArrayElements(env, dgst, 0))) {
		error_print();
		goto end;
	}
	if ((*env)->GetArrayLength(env, dgst) != SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}
	if (!(sigbuf = (*env)->GetByteArrayElements(env, sig, 0))) {
		error_print();
		goto end;
	}
	siglen = (*env)->GetArrayLength(env, sig);
	if ((ret = sm2_verify((SM2_KEY *)sm2_pub, (uint8_t *)dgstbuf, (uint8_t *)sigbuf, (size_t)siglen)) < 0) {
		error_print();
		goto end;
	}
end:
	if (dgstbuf) (*env)->ReleaseByteArrayElements(env, dgst, dgstbuf, JNI_ABORT);
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, sig, sigbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_encrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1encrypt(
	JNIEnv *env, jclass this,
	jlong sm2_pub, jbyteArray in)
{
	jbyteArray ret = NULL;
	jbyte *inbuf = NULL;
	jsize inlen;
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t outlen;

	if (!sm2_pub) {
		error_print();
		return NULL;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	inlen = (*env)->GetArrayLength(env, in);
	if (sm2_encrypt((SM2_KEY *)sm2_pub, (uint8_t *)inbuf, (size_t)inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_decrypt
 * Signature: (J[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1decrypt(
	JNIEnv *env, jclass this,
	jlong sm2_key, jbyteArray in)
{
	jbyteArray ret = NULL;
	jbyte *inbuf = NULL;
	jsize inlen;
	uint8_t outbuf[SM2_MAX_PLAINTEXT_SIZE];
	size_t outlen;

	if (!sm2_key) {
		error_print();
		return NULL;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	inlen = (*env)->GetArrayLength(env, in);
	if (sm2_decrypt((SM2_KEY *)sm2_key, (uint8_t *)inbuf, (size_t)inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
end:
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm2_sign_ctx;

	if (!(sm2_sign_ctx = (jlong)malloc(sizeof(SM2_SIGN_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM2_SIGN_CTX *)sm2_sign_ctx, 0, sizeof(SM2_SIGN_CTX));
	return sm2_sign_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx)
{
	if (sm2_sign_ctx) {
		gmssl_secure_clear((SM2_SIGN_CTX *)sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		free((SM2_SIGN_CTX *)sm2_sign_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_init
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1init(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx, jlong sm2_key, jstring id)
{
	int ret = -1;
	const char *id_str = NULL;

	if (!sm2_sign_ctx) {
		error_print();
		return -1;
	}
	if (!sm2_key) {
		error_print();
		return -1;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (sm2_sign_init((SM2_SIGN_CTX *)sm2_sign_ctx, (SM2_KEY *)sm2_key, id_str, strlen(id_str)) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1update(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm2_sign_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	if (sm2_sign_update((SM2_SIGN_CTX *)sm2_sign_ctx, (uint8_t *)buf + offset, (size_t)length) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_sign_finish
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm2_1sign_1finish(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx)
{
	jbyteArray ret = NULL;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (!sm2_sign_ctx) {
		error_print();
		return NULL;
	}
	if (sm2_sign_finish((SM2_SIGN_CTX *)sm2_sign_ctx, sig, &siglen) != 1) {
		error_print();
		return NULL;
	}
	if (!(ret = (*env)->NewByteArray(env, siglen))) {
		error_print();
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, siglen, (jbyte *)sig);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_init
 * Signature: (JJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1init(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx, jlong sm2_pub, jstring id)
{
	int ret = -1;
	const char *id_str = NULL;

	if (!sm2_sign_ctx) {
		error_print();
		return -1;
	}
	if (!sm2_pub) {
		error_print();
		return -1;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (sm2_verify_init((SM2_SIGN_CTX *)sm2_sign_ctx, (SM2_KEY *)sm2_pub, id_str, strlen(id_str)) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1update(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm2_sign_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	if (sm2_verify_update((SM2_SIGN_CTX *)sm2_sign_ctx, (uint8_t *)buf + offset, (size_t)length) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm2_verify_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm2_1verify_1finish(
	JNIEnv *env, jclass this,
	jlong sm2_sign_ctx, jbyteArray sig)
{
	jint ret = -1;
	jbyte *sigbuf = NULL;
	jsize siglen;

	if (!sm2_sign_ctx) {
		error_print();
		return ret;
	}
	if (!(sigbuf = (*env)->GetByteArrayElements(env, sig, 0))) {
		error_print();
		goto end;
	}
	siglen = (*env)->GetArrayLength(env, sig);
	if ((ret = sm2_verify_finish((SM2_SIGN_CTX *)sm2_sign_ctx, (uint8_t *)sigbuf, (size_t)siglen)) < 0) {
		error_print();
		goto end;
	}
end:
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, sig, sigbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1generate(
	JNIEnv *env, jclass this)
{
	jlong sm9_sign_master_key;

	if (!(sm9_sign_master_key = (jlong)malloc(sizeof(SM9_SIGN_MASTER_KEY)))) {
		error_print();
		return 0;
	}
	if (sm9_sign_master_key_generate((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key) != 1) {
		gmssl_secure_clear((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key, sizeof(SM9_SIGN_MASTER_KEY));
		error_print();
		return 0;
	}
	return sm9_sign_master_key;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm9_sign_master_key)
{
	if (sm9_sign_master_key) {
		gmssl_secure_clear((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key, sizeof(SM9_SIGN_MASTER_KEY));
		free((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1info_1encrypt_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_sign_master_key, jstring pass, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!sm9_sign_master_key) {
		error_print();
		return -1;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_key_info_encrypt_to_pem((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1info_1decrypt_1from_1pem(
	JNIEnv *env, jclass this,
	jstring pass, jstring file)
{
	jlong ret = 0;
	SM9_SIGN_MASTER_KEY *sm9_sign_master_key = NULL;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!(sm9_sign_master_key = (SM9_SIGN_MASTER_KEY *)malloc(sizeof(SM9_SIGN_MASTER_KEY)))) {
		error_print();
		return 0;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_key_info_encrypt_to_pem(sm9_sign_master_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_sign_master_key;
	sm9_sign_master_key = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_sign_master_key) {
		gmssl_secure_clear(sm9_sign_master_key, sizeof(SM9_SIGN_MASTER_KEY));
		free(sm9_sign_master_key);
	}
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_public_key_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1public_1key_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_sign_master_pub, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!sm9_sign_master_pub) {
		error_print();
		return -1;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_public_key_to_pem((SM9_SIGN_MASTER_KEY *)sm9_sign_master_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_public_key_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1public_1key_1from_1pem(
	JNIEnv *env, jclass this,
	jstring file)
{
	jlong ret = 0;
	SM9_SIGN_MASTER_KEY *sm9_sign_master_pub = NULL;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!(sm9_sign_master_pub = (SM9_SIGN_MASTER_KEY *)malloc(sizeof(SM9_SIGN_MASTER_KEY)))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_public_key_from_pem(sm9_sign_master_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_sign_master_pub;
	sm9_sign_master_pub = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_sign_master_pub) {
		gmssl_secure_clear(sm9_sign_master_pub, sizeof(SM9_SIGN_MASTER_KEY));
		free(sm9_sign_master_pub);
	}
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_master_key_extract_key
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1master_1key_1extract_1key(
	JNIEnv *env, jclass this,
	jlong sm9_sign_master_key, jstring id)
{
	jlong ret = 0;
	SM9_SIGN_KEY *sm9_sign_key = NULL;
	const char *id_str = NULL;

	if (!sm9_sign_master_key) {
		error_print();
		return 0;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (!(sm9_sign_key = (SM9_SIGN_KEY *)malloc(sizeof(SM9_SIGN_KEY)))) {
		error_print();
		goto end;
	}
	if (sm9_sign_master_key_extract_key((SM9_SIGN_MASTER_KEY *)sm9_sign_master_key,
		id_str, strlen(id_str), sm9_sign_key) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_sign_key;
	sm9_sign_key = NULL;
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	if (sm9_sign_key) {
		gmssl_secure_clear(sm9_sign_key, sizeof(SM9_SIGN_KEY));
		free(sm9_sign_key);
	}
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm9_sign_key)
{
	if (sm9_sign_key) {
		gmssl_secure_clear((SM9_SIGN_KEY *)sm9_sign_key, sizeof(SM9_SIGN_KEY));
		free((SM9_SIGN_KEY *)sm9_sign_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1info_1encrypt_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_sign_key, jstring pass, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!sm9_sign_key) {
		error_print();
		return -1;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_key_info_encrypt_to_pem((SM9_SIGN_KEY *)sm9_sign_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1key_1info_1decrypt_1from_1pem(
	JNIEnv *env, jclass this,
	jstring pass, jstring file)
{
	jlong ret = 0;
	SM9_SIGN_KEY *sm9_sign_key = NULL;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!(sm9_sign_key = (SM9_SIGN_KEY *)malloc(sizeof(SM9_SIGN_KEY)))) {
		error_print();
		return 0;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_sign_key_info_decrypt_from_pem(sm9_sign_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_sign_key;
	sm9_sign_key = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_sign_key) {
		gmssl_secure_clear(sm9_sign_key, sizeof(SM9_SIGN_KEY));
		free(sm9_sign_key);
	}
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_ctx_new
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1ctx_1new(
	JNIEnv *env, jclass this)
{
	jlong sm9_sign_ctx;

	if (!(sm9_sign_ctx = (jlong)malloc(sizeof(SM9_SIGN_CTX)))) {
		error_print();
		return 0;
	}
	memset((SM9_SIGN_CTX *)sm9_sign_ctx, 0, sizeof(SM9_SIGN_CTX));
	return sm9_sign_ctx;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_ctx_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1ctx_1free(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx)
{
	if (sm9_sign_ctx) {
		gmssl_secure_clear((SM9_SIGN_CTX *)sm9_sign_ctx, sizeof(SM9_SIGN_CTX));
		free((SM9_SIGN_CTX *)sm9_sign_ctx);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1init(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx)
{
	if (!sm9_sign_ctx) {
		error_print();
		return -1;
	}
	if (sm9_sign_init((SM9_SIGN_CTX *)sm9_sign_ctx) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1update(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm9_sign_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	if (sm9_sign_update((SM9_SIGN_CTX *)sm9_sign_ctx, (uint8_t *)buf + offset, (size_t)length) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_sign_finish
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1sign_1finish(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx, jlong sm9_sign_key)
{
	jbyteArray ret = NULL;
	uint8_t sig[SM9_SIGNATURE_SIZE];
	size_t siglen;

	if (!sm9_sign_ctx) {
		error_print();
		return NULL;
	}
	if (!sm9_sign_key) {
		error_print();
		return NULL;
	}
	if (sm9_sign_finish((SM9_SIGN_CTX *)sm9_sign_ctx, (SM9_SIGN_KEY *)sm9_sign_key, sig, &siglen) != 1) {
		error_print();
		return NULL;
	}
	if (!(ret = (*env)->NewByteArray(env, siglen))) {
		error_print();
		return NULL;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, siglen, (jbyte *)sig);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_init
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1init(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx)
{
	if (!sm9_sign_ctx) {
		error_print();
		return -1;
	}
	if (sm9_verify_init((SM9_SIGN_CTX *)sm9_sign_ctx) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_update
 * Signature: (J[BII)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1update(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx, jbyteArray data, jint offset, jint length)
{
	jint ret = -1;
	jbyte *buf = NULL;
	jsize buflen;

	if (!sm9_sign_ctx) {
		error_print();
		return -1;
	}
	if (!(buf = (*env)->GetByteArrayElements(env, data, 0))) {
		error_print();
		goto end;
	}
	if ((buflen = (*env)->GetArrayLength(env, data)) <= 0) {
		error_print();
		goto end;
	}
	if (offset < 0 || length < 0) {
		error_print();
		goto end;
	}
	if (buflen < offset + length) {
		error_print();
		goto end;
	}
	if (sm9_verify_update((SM9_SIGN_CTX *)sm9_sign_ctx, (uint8_t *)buf + offset, (size_t)length) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (buf) (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_verify_finish
 * Signature: (J[BJLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1verify_1finish(
	JNIEnv *env, jclass this,
	jlong sm9_sign_ctx, jbyteArray sig, jlong sm9_sign_master_pub, jstring id)
{
	jint ret = -1;
	jbyte *sigbuf = NULL;
	jsize siglen;
	const char *id_str = NULL;

	if (!sm9_sign_ctx) {
		error_print();
		return ret;
	}
	if (!sm9_sign_master_pub) {
		error_print();
		return ret;
	}
	if (!(sigbuf = (*env)->GetByteArrayElements(env, sig, 0))) {
		error_print();
		goto end;
	}
	siglen = (*env)->GetArrayLength(env, sig);
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if ((ret = sm9_verify_finish((SM9_SIGN_CTX *)sm9_sign_ctx, (uint8_t *)sigbuf, (size_t)siglen,
		(SM9_SIGN_MASTER_KEY *)sm9_sign_master_pub, id_str, strlen(id_str))) < 0) {
		error_print();
		goto end;
	}
end:
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, sig, sigbuf, JNI_ABORT);
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_generate
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1generate(
	JNIEnv * env, jclass this)
{
	jlong sm9_enc_master_key;

	if (!(sm9_enc_master_key = (jlong)malloc(sizeof(SM9_ENC_MASTER_KEY)))) {
		error_print();
		return 0;
	}
	if (sm9_enc_master_key_generate((SM9_ENC_MASTER_KEY *)sm9_enc_master_key) != 1) {
		gmssl_secure_clear((SM9_ENC_MASTER_KEY *)sm9_enc_master_key, sizeof(SM9_ENC_MASTER_KEY));
		error_print();
		return 0;
	}
	return sm9_enc_master_key;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm9_enc_master_key)
{
	if (sm9_enc_master_key) {
		gmssl_secure_clear((SM9_ENC_MASTER_KEY *)sm9_enc_master_key, sizeof(SM9_ENC_MASTER_KEY));
		free((SM9_ENC_MASTER_KEY *)sm9_enc_master_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1info_1encrypt_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_enc_master_key, jstring pass, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!sm9_enc_master_key) {
		error_print();
		return -1;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_key_info_encrypt_to_pem((SM9_ENC_MASTER_KEY *)sm9_enc_master_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1info_1decrypt_1from_1pem(
	JNIEnv *env, jclass this,
	jstring pass, jstring file)
{
	jlong ret = 0;
	SM9_ENC_MASTER_KEY *sm9_enc_master_key = NULL;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!(sm9_enc_master_key = (SM9_ENC_MASTER_KEY *)malloc(sizeof(SM9_ENC_MASTER_KEY)))) {
		error_print();
		return 0;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_key_info_encrypt_to_pem(sm9_enc_master_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_enc_master_key;
	sm9_enc_master_key = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_enc_master_key) {
		gmssl_secure_clear(sm9_enc_master_key, sizeof(SM9_ENC_MASTER_KEY));
		free(sm9_enc_master_key);
	}
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
	return 0;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_public_key_to_pem
 * Signature: (JLjava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1public_1key_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_enc_master_pub, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!sm9_enc_master_pub) {
		error_print();
		return -1;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_public_key_to_pem((SM9_ENC_MASTER_KEY *)sm9_enc_master_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_public_key_from_pem
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1public_1key_1from_1pem(
	JNIEnv *env, jclass this,
	jstring file)
{
	jlong ret = 0;
	SM9_ENC_MASTER_KEY *sm9_enc_master_pub = NULL;
	FILE *fp = NULL;
	const char *file_str = NULL;

	if (!(sm9_enc_master_pub = (SM9_ENC_MASTER_KEY *)malloc(sizeof(SM9_ENC_MASTER_KEY)))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_public_key_from_pem(sm9_enc_master_pub, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_enc_master_pub;
	sm9_enc_master_pub = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_enc_master_pub) {
		gmssl_secure_clear(sm9_enc_master_pub, sizeof(SM9_ENC_MASTER_KEY));
		free(sm9_enc_master_pub);
	}
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_master_key_extract_key
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1master_1key_1extract_1key(
	JNIEnv *env, jclass this,
	jlong sm9_enc_master_key, jstring id)
{
	jlong ret = 0;
	SM9_ENC_KEY *sm9_enc_key = NULL;
	const char *id_str = NULL;

	if (!sm9_enc_master_key) {
		error_print();
		return 0;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (!(sm9_enc_key = (SM9_ENC_KEY *)malloc(sizeof(SM9_ENC_KEY)))) {
		error_print();
		goto end;
	}
	if (sm9_enc_master_key_extract_key((SM9_ENC_MASTER_KEY *)sm9_enc_master_key,
		id_str, strlen(id_str), sm9_sign_key) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_enc_key;
	sm9_enc_key = NULL;
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	if (sm9_enc_key) {
		gmssl_secure_clear(sm9_enc_key, sizeof(SM9_ENC_KEY));
		free(sm9_sign_key);
	}
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1free(
	JNIEnv *env, jclass this,
	jlong sm9_enc_key)
{
	if (sm9_enc_key) {
		gmssl_secure_clear((SM9_ENC_KEY *)sm9_enc_key);
		free((SM9_ENC_KEY *)sm9_enc_key);
	}
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_info_encrypt_to_pem
 * Signature: (JLjava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1info_1encrypt_1to_1pem(
	JNIEnv *env, jclass this,
	jlong sm9_enc_key, jstring pass, jstring file)
{
	jint ret = -1;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!sm9_enc_key) {
		error_print();
		return -1;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_key_info_encrypt_to_pem((SM9_ENC_KEY *)sm9_enc_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = 1;
end:
	if (fp) fclose(fp);
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_enc_key_info_decrypt_from_pem
 * Signature: (Ljava/lang/String;Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_org_gmssl_GmSSLJNI_sm9_1enc_1key_1info_1decrypt_1from_1pem(
	JNIEnv *env, jclass this,
	jstring pass, jstring file)
{
	jlong ret = 0;
	SM9_ENC_KEY *sm9_enc_key = NULL;
	FILE *fp = NULL;
	const char *pass_str = NULL;
	const char *file_str = NULL;

	if (!(sm9_enc_key = (SM9_ENC_KEY *)malloc(sizeof(SM9_ENC_KEY)))) {
		error_print();
		return 0;
	}
	if (!(pass_str = (*env)->GetStringUTFChars(env, pass, 0))) {
		error_print();
		goto end;
	}
	if (!(file_str = (*env)->GetStringUTFChars(env, file, 0))) {
		error_print();
		goto end;
	}
	if (!(fp = fopen(file_str, "wb"))) {
		error_print();
		goto end;
	}
	if (sm9_enc_key_info_decrypt_from_pem(sm9_enc_key, pass_str, fp) != 1) {
		error_print();
		goto end;
	}
	ret = (jlong)sm9_enc_key;
	sm9_enc_key = NULL;
end:
	if (fp) fclose(fp);
	if (sm9_enc_key) {
		gmssl_secure_clear(sm9_enc_key, sizeof(SM9_ENC_KEY));
		free(sm9_enc_key);
	}
	if (pass_str) (*env)->ReleaseStringUTFChars(env, pass, pass_str);
	if (file_str) (*env)->ReleaseStringUTFChars(env, file, file_str);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_encrypt
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1encrypt(
	JNIEnv *env, jclass this,
	jlong sm9_enc_master_pub, jstring id, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *id_str = NULL;
	jbyte *inbuf = NULL;
	jsize inlen;
	uint8_t outbuf[SM9_MAX_CIPHERTEXT_SIZE];
	size_t outlen;

	if (!sm9_enc_master_pub) {
		error_print();
		return NULL;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	inlen = (*env)->GetArrayLength(env, in);
	if (sm9_encrypt((SM9_ENC_MASTER_KEY *)sm9_enc_master_pub, id_str, strlen(id_str),
		(uint8_t *)inbuf, (size_t)inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	return ret;
}

/*
 * Class:     org_gmssl_GmSSLJNI
 * Method:    sm9_decrypt
 * Signature: (JLjava/lang/String;[B)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSLJNI_sm9_1decrypt(
	JNIEnv *env, jclass this,
	jlong sm9_enc_key, jstring id, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *id_str = NULL;
	jbyte *inbuf = NULL;
	jsize inlen;
	uint8_t outbuf[SM9_MAX_CIPHERTEXT_SIZE];
	size_t outlen;

	if (!sm9_enc_key) {
		error_print();
		return NULL;
	}
	if (!(id_str = (*env)->GetStringUTFChars(env, id, 0))) {
		error_print();
		goto end;
	}
	if (!(inbuf = (*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	inlen = (*env)->GetArrayLength(env, in);
	if (sm9_decrypt((SM9_ENC_KEY *)sm9_enc_key, id_str, strlen(id_str),
		(uint8_t *)inbuf, (size_t)inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}
	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
end:
	if (id_str) (*env)->ReleaseStringUTFChars(env, id, id_str);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, inbuf, JNI_ABORT);
	return ret;
}
