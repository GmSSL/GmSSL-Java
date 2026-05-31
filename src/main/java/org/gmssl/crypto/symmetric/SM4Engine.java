/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.symmetric;

import org.gmssl.GmSSLJNI;
import org.gmssl.crypto.PaddingScheme;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public abstract class SM4Engine {

    public static final int KEY_SIZE = SM4Cipher.KEY_SIZE;

    public static final int BLOCK_SIZE = SM4Cipher.BLOCK_SIZE;

    protected PaddingScheme paddingScheme;

    protected abstract void init(int opmode, Key key, SecureRandom random) throws InvalidKeyException;

    protected abstract void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random);

    protected abstract byte[] engineGetIV();

    protected abstract byte[] processUpdate(byte[] input, int inputOffset, int inputLen);

    protected abstract int processUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;

    protected abstract int processBlock(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    protected abstract byte[] processBlock(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException;
    protected void processUpdateAAD(byte[] src, int offset, int len){};

}
