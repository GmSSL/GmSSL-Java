/* ====================================================================
 * Copyright (c) 2014 - 2017 The GmSSL Project.  All rights reserved.
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
#include <gmssl/error.h>
#include <gmssl/version.h>
#include "GmSSL.h"

#define GMSSL_JNI_VERSION	"GmSSL-JNI API/1.2 2022-08-03"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getVersions(JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env, 2,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0, (*env)->NewStringUTF(env, GMSSL_JNI_VERSION));
	(*env)->SetObjectArrayElement(env, ret, 1, (*env)->NewStringUTF(env, GMSSL_VERSION_STR));

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_generateRandom(
	JNIEnv *env, jobject this, jint outlen)
{
	jbyteArray ret = NULL;
	jbyte *outbuf = NULL;

	if (outlen <= 0 || outlen >= INT_MAX) {
		error_print();
		return NULL;
	}
	if (!(outbuf = malloc(outlen))) {
		error_print();
		goto end;
	}

	if (rand_bytes((uint8_t *)outbuf, outlen) != 1) {
		error_print();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (outbuf) {
		gmssl_secure_clear(outbuf, outlen);
		free(outbuf);
	}
	return ret;
}

typedef struct {
	char *name;
	int key_size;
	int iv_size;
	int block_size;
} JNI_CIPHER_INFO;

static JNI_CIPHER_INFO ciphers[] = {
	{ "SM4", SM4_KEY_SIZE, 0, SM4_BLOCK_SIZE },
	{ "SM4-CBC", SM4_KEY_SIZE, SM4_BLOCK_SIZE, SM4_BLOCK_SIZE },
	{ "SM4-CBC-PADDING", SM4_KEY_SIZE, SM4_BLOCK_SIZE, 1 },
	{ "SM4-CTR", SM4_KEY_SIZE, SM4_BLOCK_SIZE, 1 },
	{ "ZUC", ZUC_KEY_SIZE, ZUC_IV_SIZE, 1 },
};

static size_t ciphers_count = sizeof(ciphers)/sizeof(ciphers[0]);

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getCiphers(
	JNIEnv *env, jobject this)
{
	jobjectArray ret;
	int i;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		ciphers_count,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	for (i = 0; i < ciphers_count; i++) {
		(*env)->SetObjectArrayElement(env, ret, i,
			(*env)->NewStringUTF(env, ciphers[i].name));
	}

	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherIVLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	int i;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	for (i = 0; i < ciphers_count; i++) {
		if (strcmp(alg, ciphers[i].name) == 0) {
			ret = ciphers[i].iv_size;
			break;
		}
	}
	if (i >= ciphers_count) {
		error_print();
		goto end;
	}

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherKeyLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg;
	int i;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	for (i = 0; i < ciphers_count; i++) {
		if (strcmp(alg, ciphers[i].name) == 0) {
			ret = ciphers[i].key_size;
			break;
		}
	}
	if (i >= ciphers_count) {
		error_print();
		goto end;
	}

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getCipherBlockSize(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;
	int i;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	for (i = 0; i < ciphers_count; i++) {
		if (strcmp(alg, ciphers[i].name) == 0) {
			ret = ciphers[i].block_size;
			break;
		}
	}
	if (i >= ciphers_count) {
		error_print();
		goto end;
	}

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_symmetricEncrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *keybuf = NULL;
	const uint8_t *ivbuf = NULL;
	const uint8_t *inbuf = NULL;
	jsize inlen, keylen, ivlen;
	uint8_t *outbuf = NULL;
	jsize outlen;
	const JNI_CIPHER_INFO *cipher;
	int i;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	for (i = 0; i < ciphers_count; i++) {
		if (strcmp(alg, ciphers[i].name) == 0) {
			cipher = &ciphers[i];
			break;
		}
	}
	if (i >= ciphers_count) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}
	if (inlen % cipher->block_size != 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != cipher->key_size) {
		error_print();
		goto end;
	}

	/* null IV can be valid input for some ciphers */
	ivbuf = (uint8_t *)(*env)->GetByteArrayElements(env, iv, 0);
	if (!ivbuf && cipher->iv_size) {
		error_print();
		goto end;
	}
	ivlen = (*env)->GetArrayLength(env, iv);
	if (ivlen != cipher->iv_size) {
		error_print();
		goto end;
	}

	// 在增加GCM, CBC+HMAC等加密算法后应该调整缓冲区大小
	if (!(outbuf = malloc(inlen + SM4_BLOCK_SIZE))) {
		error_print();
		goto end;
	}






	switch (i) {
	case 0:
		{
			SM4_KEY sm4_key;
			const uint8_t *inptr = inbuf;
			uint8_t *outptr = outbuf;
			sm4_set_encrypt_key(&sm4_key, (uint8_t *)keybuf);
			while (inlen) {
				sm4_encrypt(&sm4_key, inptr, outptr);
				inptr += SM4_BLOCK_SIZE;
				outptr += SM4_BLOCK_SIZE;
				inlen -= SM4_BLOCK_SIZE;
			}
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		}
		break;
	case 1:
		{
			SM4_KEY sm4_key;
			sm4_set_encrypt_key(&sm4_key, (uint8_t *)keybuf);
			sm4_cbc_encrypt(&sm4_key, ivbuf, inbuf, inlen/SM4_BLOCK_SIZE, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		break;
		}
	case 2:
		{
			SM4_KEY sm4_key;
			size_t len;
			sm4_set_encrypt_key(&sm4_key, keybuf);
			sm4_cbc_padding_encrypt(&sm4_key, ivbuf, inbuf, inlen, outbuf, &len);
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
			outlen = (jsize)len;
		}
		break;
	case 3:
		{
			SM4_KEY sm4_key;
			uint8_t ctr[16];
			sm4_set_encrypt_key(&sm4_key, keybuf);
			memcpy(ctr, ivbuf, ivlen);
			sm4_ctr_encrypt(&sm4_key, ctr, inbuf, inlen, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		}
		break;
	case 4:
		{
			ZUC_STATE zuc_state;
			zuc_init(&zuc_state, keybuf, ivbuf);
			zuc_encrypt(&zuc_state, inbuf, inlen, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&zuc_state, sizeof(zuc_state));
		}
		break;
	default:
		error_print();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);
	free(outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_symmetricDecrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key, jbyteArray iv)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *keybuf = NULL;
	const uint8_t *ivbuf = NULL;
	jsize inlen, keylen, ivlen;
	uint8_t *outbuf = NULL;
	size_t outlen;
	const JNI_CIPHER_INFO *cipher;
	int i;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	for (i = 0; i < ciphers_count; i++) {
		if (strcmp(alg, ciphers[i].name) == 0) {
			cipher = &ciphers[i];
			break;
		}
	}
	if (i >= ciphers_count) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}
	if (inlen % cipher->block_size != 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != cipher->key_size) {
		error_print();
		goto end;
	}

	/* null IV can be valid input for some ciphers */
	ivbuf = (uint8_t *)(*env)->GetByteArrayElements(env, iv, 0);
	if (!ivbuf && cipher->iv_size) {
		error_print();
		goto end;
	}
	ivlen = (*env)->GetArrayLength(env, iv);
	if (ivlen != cipher->iv_size) {
		error_print();
		goto end;
	}

	if (!(outbuf = malloc(inlen))) {
		error_print();
		goto end;
	}


	switch (i) {
	case 0:
		{
			SM4_KEY sm4_key;
			const uint8_t *inptr = inbuf;
			uint8_t *outptr = outbuf;
			sm4_set_decrypt_key(&sm4_key, keybuf);
			while (inlen > 0) {
				sm4_decrypt(&sm4_key, inptr, outptr);
				inptr += SM4_BLOCK_SIZE;
				outptr += SM4_BLOCK_SIZE;
				inlen -= SM4_BLOCK_SIZE;
			}
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		}
		break;
	case 1:
		{
			SM4_KEY sm4_key;
			sm4_set_decrypt_key(&sm4_key, keybuf);
			sm4_cbc_decrypt(&sm4_key, ivbuf, inbuf, inlen/SM4_BLOCK_SIZE, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		break;
		}
	case 2:
		{
			SM4_KEY sm4_key;
			size_t len;
			sm4_set_decrypt_key(&sm4_key, keybuf);
			sm4_cbc_padding_decrypt(&sm4_key, ivbuf, inbuf, inlen, outbuf, &len);
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
			outlen = (jsize)len;
		}
		break;
	case 3:
		{
			SM4_KEY sm4_key;
			uint8_t ctr[16];
			sm4_set_decrypt_key(&sm4_key, keybuf);
			memcpy(ctr, ivbuf, ivlen);
			sm4_ctr_decrypt(&sm4_key, ctr, inbuf, inlen, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&sm4_key, sizeof(sm4_key));
		}
		break;
	case 4:
		{
			ZUC_STATE zuc_state;
			zuc_init(&zuc_state, keybuf, ivbuf);
			zuc_encrypt(&zuc_state, inbuf, inlen, outbuf);
			outlen = inlen;
			gmssl_secure_clear(&zuc_state, sizeof(zuc_state));
		}
		break;
	default:
		error_print();
		goto end;
	}


	if (!(ret = (*env)->NewByteArray(env, outlen))) {
	}

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (ivbuf) (*env)->ReleaseByteArrayElements(env, iv, (jbyte *)ivbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getDigests(
	JNIEnv *env, jobject this)
{
	jobjectArray ret;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		1,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0, (*env)->NewStringUTF(env, "SM3"));

	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_getDigestLength(
	JNIEnv *env, jobject this, jstring algor)
{
	jint ret = -1;
	const char *alg = NULL;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM3") != 0) {
		error_print();
		goto end;
	}

	ret = SM3_DIGEST_SIZE;

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_digest(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	uint8_t outbuf[32];
	jsize inlen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM3") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}

	sm3_digest(inbuf, inlen, outbuf);

	if (!(ret = (*env)->NewByteArray(env, sizeof(outbuf)))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, sizeof(outbuf), (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getMacs(
	JNIEnv *env, jobject this)
{
	jobjectArray ret;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		1,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0, (*env)->NewStringUTF(env, "HMAC-SM3"));

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_mac(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *keybuf = NULL;
	uint8_t outbuf[32];
	jsize inlen, keylen, outlen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "HMAC-SM3") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}

	sm3_hmac(keybuf, keylen, inbuf, inlen, outbuf);
	outlen = SM3_HMAC_SIZE;

	if (!(ret = (*env)->NewByteArray(env, outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getSignAlgorithms(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		1,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0, (*env)->NewStringUTF(env, "SM2"));

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_sign(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *keybuf = NULL;
	jsize inlen, keylen;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM2") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}
	if (inlen != SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != sizeof(SM2_KEY)) {
		error_print();
		goto end;
	}

	if (sm2_sign((SM2_KEY *)keybuf, inbuf, sig, &siglen) != 1) {
		error_print();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, (jsize)siglen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, (jsize)siglen, (jbyte *)sig);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jint JNICALL Java_org_gmssl_GmSSL_verify(JNIEnv *env, jobject this,
	jstring algor, jbyteArray in, jbyteArray sig, jbyteArray key)
{
	jint ret = 0;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *sigbuf = NULL;
	const uint8_t *keybuf = NULL;
	jsize inlen, siglen, keylen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM2") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}
	if (inlen != SM3_DIGEST_SIZE) {
		error_print();
		goto end;
	}

	if (!(sigbuf = (uint8_t *)(*env)->GetByteArrayElements(env, sig, 0))) {
		error_print();
		goto end;
	}
	if ((siglen = (*env)->GetArrayLength(env, sig)) <= 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != sizeof(SM2_KEY)) {
		error_print();
		goto end;
	}

	if ((ret = sm2_verify((SM2_KEY *)keybuf, inbuf, sigbuf, siglen)) < 0) {
		error_print();
		goto end;
	}

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (sigbuf) (*env)->ReleaseByteArrayElements(env, sig, (jbyte *)sigbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getPublicKeyEncryptions(
	JNIEnv *env, jobject this)
{
	jobjectArray ret;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		1,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	(*env)->SetObjectArrayElement(env, ret, 0, (*env)->NewStringUTF(env, "SM2"));

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_publicKeyEncrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *keybuf = NULL;
	jsize inlen, keylen;
	uint8_t outbuf[SM2_MAX_CIPHERTEXT_SIZE];
	size_t outlen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM2") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != sizeof(SM2_KEY)) {
		error_print();
		goto end;
	}

	if (sm2_encrypt((SM2_KEY *)keybuf, inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, (jsize)outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	return ret;

}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_publicKeyDecrypt(
	JNIEnv *env, jobject this, jstring algor,
	jbyteArray in, jbyteArray key)
{
	jbyteArray ret = NULL;
	const char *alg = NULL;
	const uint8_t *inbuf = NULL;
	const uint8_t *keybuf = NULL;
	jsize inlen, keylen;
	uint8_t outbuf[SM2_MAX_PLAINTEXT_SIZE];
	size_t outlen;

	if (!(alg = (*env)->GetStringUTFChars(env, algor, 0))) {
		error_print();
		goto end;
	}
	if (strcmp(alg, "SM2") != 0) {
		error_print();
		goto end;
	}

	if (!(inbuf = (uint8_t *)(*env)->GetByteArrayElements(env, in, 0))) {
		error_print();
		goto end;
	}
	if ((inlen = (*env)->GetArrayLength(env, in)) <= 0) {
		error_print();
		goto end;
	}

	if (!(keybuf = (uint8_t *)(*env)->GetByteArrayElements(env, key, 0))) {
		error_print();
		goto end;
	}
	if ((keylen = (*env)->GetArrayLength(env, key)) <= 0) {
		error_print();
		goto end;
	}
	if (keylen != sizeof(SM2_KEY)) {
		error_print();
		goto end;
	}

	if (sm2_decrypt((SM2_KEY *)keybuf, inbuf, inlen, outbuf, &outlen) != 1) {
		error_print();
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, (jsize)outlen))) {
		error_print();
		goto end;
	}
	(*env)->SetByteArrayRegion(env, ret, 0, (jsize)outlen, (jbyte *)outbuf);

end:
	if (alg) (*env)->ReleaseStringUTFChars(env, algor, alg);
	if (inbuf) (*env)->ReleaseByteArrayElements(env, in, (jbyte *)inbuf, JNI_ABORT);
	if (keybuf) (*env)->ReleaseByteArrayElements(env, key, (jbyte *)keybuf, JNI_ABORT);
	return ret;
}

JNIEXPORT jobjectArray JNICALL Java_org_gmssl_GmSSL_getDeriveKeyAlgorithms(
	JNIEnv *env, jobject this)
{
	jobjectArray ret = NULL;

	if (!(ret = (jobjectArray)(*env)->NewObjectArray(env,
		0,
		(*env)->FindClass(env, "java/lang/String"),
		(*env)->NewStringUTF(env, "")))) {
		error_print();
		return NULL;
	}

	return ret;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_GmSSL_deriveKey(
	JNIEnv *env, jobject this, jstring algor,
	jint length, jbyteArray data, jbyteArray key)
{
	error_print();
	return NULL;
}
