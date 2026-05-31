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

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 * CBC、CTR、ECB、GCM
 */
public class SM4Cipher extends CipherSpi {

    public static final int KEY_SIZE = GmSSLJNI.SM4_KEY_SIZE;

    public static final int BLOCK_SIZE = GmSSLJNI.SM4_BLOCK_SIZE;

    private SM4Engine sm4Engine;

    public SM4Cipher() {
        super();
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        this.sm4Engine = SM4CipherFactory.createCipher(mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        SM4CipherFactory.setPaddingScheme(sm4Engine, padding);
    }

    @Override
    protected int engineGetBlockSize() {
        return SM4Engine.BLOCK_SIZE;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return sm4Engine.engineGetIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        sm4Engine.init(opmode,key,random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        sm4Engine.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] result = sm4Engine.processUpdate(input,inputOffset,inputLen);
        return result;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        int outLen = sm4Engine.processUpdate(input, inputOffset, inputLen, output, outputOffset);
        return outLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] result = sm4Engine.processBlock(input, inputOffset, inputLen);
        return result;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int outLen = sm4Engine.processBlock(input, inputOffset, inputLen, output, outputOffset);
        return outLen;
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        sm4Engine.processUpdateAAD(src, offset, len);
    }

}
