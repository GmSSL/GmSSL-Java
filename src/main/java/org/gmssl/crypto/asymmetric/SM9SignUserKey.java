/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl.crypto.asymmetric;

import org.gmssl.GmSSLException;
import org.gmssl.GmSSLJNI;
import org.gmssl.Sm9SignKey;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM9SignUserKey extends SM9UserKey{
    protected SM9SignUserKey(long sm9_key, String id) {
        super(sm9_key, id);
        this.privateKey = new SM9SignPrivateKey();
    }

    class SM9SignPrivateKey extends SM9PrivateKey {

        public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (sm9_key == 0) {
                throw new GmSSLException("Key not initialized");
            }
            if (GmSSLJNI.sm9_sign_key_info_encrypt_to_pem(sm9_key, pass, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (sm9_key != 0) {
                GmSSLJNI.sm9_sign_key_free(sm9_key);
            }
            if ((sm9_key = GmSSLJNI.sm9_sign_key_info_decrypt_from_pem(pass, file)) == 0) {
                throw new GmSSLException("Import key failure");
            }
        }

        public byte[] sign(long sm9_sign_ctx) {
            byte[] signature;
            if ((signature = GmSSLJNI.sm9_sign_finish(sm9_sign_ctx, sm9_key)) == null) {
                throw new GmSSLException("");
            }
            return signature;
        }

        public SM9SignUserKey getSecretKey() {
            return SM9SignUserKey.this;
        }

    }

}
