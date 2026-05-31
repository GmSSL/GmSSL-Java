/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import java.security.spec.KeySpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public abstract class SM9UserKey implements KeySpec {

    protected long sm9_key;

    protected String id;

    protected SM9PrivateKey privateKey;

    protected SM9UserKey(long key, String id) {
        this.sm9_key = key;
        this.id = id;
    }

    public String getId() {
        return this.id;
    }

    public SM9PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
