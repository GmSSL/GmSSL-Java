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
public abstract class SM9MasterKey implements KeySpec {

    protected long master_key;

    protected boolean has_private_key;

    protected SM9PublicKey publicKey;

    protected SM9PrivateKey privateKey;

    public abstract void generateMasterKey();

    public abstract long getSecretKey();

    public abstract SM9UserKey extractKey(String id);

    public SM9PublicKey getPublicKey() {
        return this.publicKey;
    }

    public SM9PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
