/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM9KeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private SM9MasterKey masterKey;

    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("The parameter must not be null");
        }
        if (params instanceof SM9SignMasterKeyGenParameterSpec) {
            SM9SignMasterKeyGenParameterSpec spec = (SM9SignMasterKeyGenParameterSpec) params;
            this.masterKey = new SM9SignMasterKey();
        } else if (params instanceof SM9EncMasterKeyGenParameterSpec) {
            SM9EncMasterKeyGenParameterSpec spec = (SM9EncMasterKeyGenParameterSpec) params;
            this.masterKey = new SM9EncMasterKey();
        } else {
           throw new InvalidAlgorithmParameterException("");
        }
        masterKey.generateMasterKey();
    }

    @Override
    public KeyPair generateKeyPair() {
        return new KeyPair(masterKey.publicKey, masterKey.privateKey);
    }

}
