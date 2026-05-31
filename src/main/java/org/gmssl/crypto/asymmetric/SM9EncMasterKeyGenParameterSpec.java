/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLJNI;

import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM9EncMasterKeyGenParameterSpec implements AlgorithmParameterSpec {

    private String id;

    protected SM9EncMasterKeyGenParameterSpec() {

    }

    public SM9EncMasterKeyGenParameterSpec(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}

