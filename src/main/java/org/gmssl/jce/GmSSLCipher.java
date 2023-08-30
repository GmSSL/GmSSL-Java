/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */

package org.gmssl.jce;

import org.gmssl.GmSSLJNI;

import java.security.Key;
import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.CipherSpi;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;



public class GmSSLCipher extends CipherSpi {

	enum Cipher {
		SM4_CBC_CIPHER,
		SM4_CTR_CIPHER,
		SM4_GCM_CIPHER,
		ZUC_CIPHER
	}

	private Cipher cipher;
	private int opmode;
	private byte[] key;
	private byte[] iv;
	private byte[] aad;
	private int taglen;

	private long cipher_ctx;

	private int state = 0;

	GmSSLCipher(Cipher cipher) {

		this.cipher = cipher;

		switch (cipher) {
		case SM4_CBC_CIPHER:
			this.cipher_ctx = GmSSLJNI.sm4_cbc_ctx_new();
			break;

		case SM4_CTR_CIPHER:
			this.cipher_ctx = GmSSLJNI.sm4_ctr_ctx_new();
			break;

		case SM4_GCM_CIPHER:
			this.cipher_ctx = GmSSLJNI.sm4_gcm_ctx_new();
			break;

		case ZUC_CIPHER:
			this.cipher_ctx = GmSSLJNI.zuc_ctx_new();
			break;
		}
	}

	@Override
	protected int engineGetBlockSize() {

		if (this.cipher == Cipher.SM4_CBC_CIPHER) {
			return GmSSLJNI.SM4_BLOCK_SIZE;
		} else {
			return 0;
		}
	}

	@Override
	protected byte[] engineGetIV() {

		return this.iv;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		return inputLen + GmSSLJNI.SM4_BLOCK_SIZE;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		return null;
	}

	@Override
	protected void engineSetMode(String mode)
		throws NoSuchAlgorithmException {

		if (mode.equals("CBC")) {
			if (this.cipher != Cipher.SM4_CBC_CIPHER) {
				throw new NoSuchAlgorithmException("");
			}
		} else if (mode.equals("CTR")) {
			if (this.cipher != Cipher.SM4_CTR_CIPHER) {
				throw new NoSuchAlgorithmException("");
			}
		} else if (mode.equals("GCM")) {
			if (cipher != Cipher.SM4_GCM_CIPHER) {
				throw new NoSuchAlgorithmException("");
			}
		} else {
			throw new NoSuchAlgorithmException("Only CBC/CTR/GCM mode supported");
		}
	}

	@Override
	protected void engineSetPadding(String padding)
		throws NoSuchPaddingException {

		if (this.cipher == Cipher.SM4_CBC_CIPHER) {
			if (!padding.equals("PKCS5Padding")) {
				throw new NoSuchPaddingException("Only PKCS5Padding supported");
			}
		}

		throw new NoSuchPaddingException("Only CBC support paddding");
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random)
		throws InvalidKeyException {

		throw new InvalidKeyException("No IV given");
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
		throws InvalidKeyException, InvalidAlgorithmParameterException {

		IvParameterSpec ivParams;
		GCMParameterSpec gcmParams;

		switch (opmode) {
		case javax.crypto.Cipher.ENCRYPT_MODE:
		case javax.crypto.Cipher.DECRYPT_MODE:
			this.opmode = opmode;
			break;
		default:
			throw new InvalidKeyException("Only ENCRYPT_MODE, DECRYPT_MODE opmode supported");
		}

		if (!(key instanceof SecretKey)) {
			throw new InvalidKeyException("Key should be SecretKey");
		}
		this.key = key.getEncoded();
		if (this.key == null) {
			throw new InvalidKeyException("");
		}
		switch (this.cipher) {
		case SM4_CBC_CIPHER:
		case SM4_CTR_CIPHER:
		case SM4_GCM_CIPHER:
			if (this.key.length != GmSSLJNI.SM4_KEY_SIZE) {
				throw new InvalidKeyException("");
			}
			break;
		case ZUC_CIPHER:
			if (this.key.length != GmSSLJNI.ZUC_KEY_SIZE) {
				throw new InvalidKeyException("");
			}
			break;
		}

		switch (this.cipher) {
		case SM4_CBC_CIPHER:
		case SM4_CTR_CIPHER:
			if (!(params instanceof IvParameterSpec)) {
				throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec should be IvParameterSpec");
			}
			ivParams = (IvParameterSpec)params;
			if (ivParams.getIV().length != GmSSLJNI.SM4_BLOCK_SIZE) {
				throw new InvalidAlgorithmParameterException("");
			}
			this.iv = ivParams.getIV();
			break;

		case SM4_GCM_CIPHER:
			if (!(params instanceof GCMParameterSpec)) {
				throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec should be GCMParameterSpec");
			}
			gcmParams = (GCMParameterSpec)params;
			if (gcmParams.getIV().length > GmSSLJNI.SM4_GCM_MAX_IV_SIZE
				|| gcmParams.getIV().length < GmSSLJNI.SM4_GCM_MIN_IV_SIZE) {
				throw new InvalidAlgorithmParameterException("Invalid IV length");
			}
			this.iv = gcmParams.getIV();
			this.taglen = gcmParams.getTLen();
			break;

		case ZUC_CIPHER:
			if (!(params instanceof IvParameterSpec)) {
				throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec should be IvParameterSpec");
			}
			ivParams = (IvParameterSpec)params;
			if (ivParams.getIV().length != GmSSLJNI.ZUC_IV_SIZE) {
				throw new InvalidAlgorithmParameterException("");
			}
			this.iv = ivParams.getIV();
			break;
		}

	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
		throws InvalidKeyException, InvalidAlgorithmParameterException {

		AlgorithmParameterSpec spec;

		switch (cipher) {
		case SM4_CBC_CIPHER:
		case SM4_CTR_CIPHER:
		case ZUC_CIPHER:
			try {
				spec = params.getParameterSpec(IvParameterSpec.class);
			} catch (InvalidParameterSpecException e) {
				throw new InvalidAlgorithmParameterException(e);
			}
			engineInit(opmode, key, spec, random);
			break;
		case SM4_GCM_CIPHER:
			try {
				spec = params.getParameterSpec(GCMParameterSpec.class);
			} catch (InvalidParameterSpecException e) {
				throw new InvalidAlgorithmParameterException(e);
			}
			engineInit(opmode, key, spec, random);
			break;
		}
	}

	@Override
	protected void engineUpdateAAD(byte[] src, int offset, int len) {

		if (cipher != Cipher.SM4_GCM_CIPHER) {
			throw new UnsupportedOperationException("");
		}
		if (state > 0) {
			throw new IllegalStateException("");
		}
	}


	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {

		if (state == 0) {
			switch (this.cipher) {
			case SM4_CBC_CIPHER:
				if (this.opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
					GmSSLJNI.sm4_cbc_encrypt_init(this.cipher_ctx, this.key, this.iv);
				} else {
					GmSSLJNI.sm4_cbc_decrypt_init(this.cipher_ctx, this.key, this.iv);
				}
				break;

			case SM4_CTR_CIPHER:
				GmSSLJNI.sm4_ctr_encrypt_init(this.cipher_ctx, this.key, this.iv);
				break;

			case SM4_GCM_CIPHER:
				if (this.opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
					GmSSLJNI.sm4_gcm_encrypt_init(this.cipher_ctx, this.key, this.iv, this.aad, this.taglen);
				} else {
					GmSSLJNI.sm4_gcm_decrypt_init(this.cipher_ctx, this.key, this.iv, this.aad, this.taglen);
				}
				break;

			case ZUC_CIPHER:
				GmSSLJNI.zuc_encrypt_init(this.cipher_ctx, this.key, this.iv);
				break;
			}
			state = 1;
		} else {
			throw new IllegalStateException("");
		}

		switch (this.cipher) {
		case SM4_CBC_CIPHER:
			if (this.opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
				return GmSSLJNI.sm4_cbc_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			} else {
				return GmSSLJNI.sm4_cbc_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			}

		case SM4_CTR_CIPHER:
			return GmSSLJNI.sm4_ctr_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);

		case SM4_GCM_CIPHER:
			if (this.opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
				return GmSSLJNI.sm4_gcm_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			} else {
				return GmSSLJNI.sm4_gcm_decrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			}

		case ZUC_CIPHER:
			return GmSSLJNI.zuc_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
		}

		return 0;
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

		int outLen = 0;

		byte[] buffer = new byte[inputLen + 32];
		outLen = engineUpdate(input, inputOffset, inputLen, buffer, 0);

		byte[] output = new byte[outLen];
		System.arraycopy(buffer, 0, output, 0, outLen);
		return output;
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) {

		int outLen = 0;

		switch (this.cipher) {
		case SM4_CBC_CIPHER:
			if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
				outLen = GmSSLJNI.sm4_cbc_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
				outLen += GmSSLJNI.sm4_cbc_encrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
			} else {
				outLen = GmSSLJNI.sm4_cbc_decrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
				outLen += GmSSLJNI.sm4_cbc_decrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
			}
			break;

		case SM4_CTR_CIPHER:
			outLen = GmSSLJNI.sm4_ctr_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			outLen += GmSSLJNI.sm4_ctr_encrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
			break;

		case SM4_GCM_CIPHER:
			if (opmode == javax.crypto.Cipher.ENCRYPT_MODE) {
				outLen = GmSSLJNI.sm4_gcm_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
				outLen += GmSSLJNI.sm4_gcm_encrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
			} else {
				outLen = GmSSLJNI.sm4_gcm_decrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
				outLen += GmSSLJNI.sm4_gcm_decrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
			}
			break;

		case ZUC_CIPHER:
			outLen = GmSSLJNI.zuc_encrypt_update(this.cipher_ctx, input, inputOffset, inputLen, output, outputOffset);
			outLen += GmSSLJNI.zuc_encrypt_finish(this.cipher_ctx, output, outputOffset + outLen);
		}

		return outLen;
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {

		int outLen = 0;

		byte[] buffer = new byte[inputLen + 32];
		outLen = engineDoFinal(input, inputOffset, inputLen, buffer, 0);

		byte[] output = new byte[outLen];
		System.arraycopy(buffer, 0, output, 0, outLen);
		return output;
	}

	public static final class sm4CbcCipher extends GmSSLCipher {
		public sm4CbcCipher() {
			super(Cipher.SM4_CBC_CIPHER);
		}
	}

	public static final class sm4CtrCipher extends GmSSLCipher {
		public sm4CtrCipher() {
			super(Cipher.SM4_CTR_CIPHER);
		}
	}

	public static final class sm4GcmCipher extends GmSSLCipher {
		public sm4GcmCipher() {
			super(Cipher.SM4_GCM_CIPHER);
		}
	}

	public static final class zucCipher extends GmSSLCipher {
		public zucCipher() {
			super(Cipher.ZUC_CIPHER);
		}
	}
}

