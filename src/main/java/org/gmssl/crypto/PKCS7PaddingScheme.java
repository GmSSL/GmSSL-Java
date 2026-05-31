/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto;

import java.util.Arrays;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description PKCS#7
 *
 */
public class PKCS7PaddingScheme implements PaddingScheme{
    @Override
    public String getPaddingName() {
        return "PKCS#7";
    }

    @Override
    public byte[] pad(byte[] input, int blockSize) {
        int paddingLength = blockSize - (input.length % blockSize);
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) paddingLength);
        byte[] result = new byte[input.length + padding.length];
        System.arraycopy(input, 0, result, 0, input.length);
        System.arraycopy(padding, 0, result, input.length, padding.length);
        return result;
    }

    @Override
    public byte[] unpad(byte[] input) {
        int paddingSize = input[input.length - 1];
        if (paddingSize <= 0 || paddingSize > input.length) {
            throw new IllegalArgumentException("Invalid pkcs#7 padding!");
        }
        for (int i = input.length - paddingSize; i < input.length; i++) {
            if (input[i] != paddingSize) {
                throw new IllegalArgumentException("Invalid pkcs#7 padding!");
            }
        }
        return Arrays.copyOfRange(input, 0, input.length - paddingSize);
    }

}
