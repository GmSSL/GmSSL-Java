/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/07/27
 * @description
 *
 */
public interface PaddingScheme {

    /**
     * get padding name
     * @return paddingName
     */
    String getPaddingName();

    /**
     * Pad according to fixed block size
     * @param input Data to be padded
     * @param blockSize block size
     * @return padded data
     */
    byte[] pad(byte[] input, int blockSize);

    /**
     * Unpad according to fixed block size
     * @param input Data to be unpadded
     * @return unpadded data
     */
    byte[] unpad(byte[] input);
}
