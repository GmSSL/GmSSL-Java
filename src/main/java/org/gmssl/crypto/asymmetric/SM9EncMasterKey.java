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

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2024/08/11
 * @description
 *
 */
public class SM9EncMasterKey extends SM9MasterKey{

    public final static int MAX_PLAINTEXT_SIZE = GmSSLJNI.SM9_MAX_PLAINTEXT_SIZE;

    public SM9EncMasterKey(){
        publicKey = new SM9EncPublicKey();
        privateKey = new SM9EncPrivateKey();
    }

    class SM9EncPublicKey extends SM9PublicKey {

        public long getPublicKey() {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            return master_key;
        }

        public void importPublicKeyPem(String file) {
            if (master_key != 0) {
                GmSSLJNI.sm9_enc_master_key_free(master_key);
            }
            if ((master_key = GmSSLJNI.sm9_enc_master_public_key_from_pem(file)) == 0) {
                throw new GmSSLException("");
            }
            has_private_key = false;
        }

        public void exportPublicKeyPem(String file) {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            if (GmSSLJNI.sm9_enc_master_public_key_to_pem(master_key, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public byte[] encrypt(byte[] plaintext, String id) {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            if (plaintext == null
                    || plaintext.length > MAX_PLAINTEXT_SIZE) {
                throw new GmSSLException("");
            }

            byte[] ciphertext;
            if ((ciphertext = GmSSLJNI.sm9_encrypt(master_key, id, plaintext)) == null) {
                throw new GmSSLException("");
            }
            return ciphertext;
        }

    }

    class SM9EncPrivateKey extends SM9PrivateKey{
        public void importEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (master_key != 0) {
                GmSSLJNI.sm9_enc_master_key_free(master_key);
            }
            if ((master_key = GmSSLJNI.sm9_enc_master_key_info_decrypt_from_pem(pass, file)) == 0) {
                throw new GmSSLException("");
            }
            has_private_key = true;
        }

        public void exportEncryptedPrivateKeyInfoPem(String pass, String file) {
            if (master_key == 0) {
                throw new GmSSLException("");
            }
            if (has_private_key == false) {
                throw new GmSSLException("");
            }
            if (GmSSLJNI.sm9_enc_master_key_info_encrypt_to_pem(master_key, pass, file) != 1) {
                throw new GmSSLException("");
            }
        }

        public SM9EncMasterKey getSecretKey() {
            return SM9EncMasterKey.this;
        }

    }

    public void generateMasterKey() {
        if (master_key != 0) {
            GmSSLJNI.sm9_enc_master_key_free(master_key);
        }
        if ((master_key = GmSSLJNI.sm9_enc_master_key_generate()) == 0) {
            throw new GmSSLException("");
        }
        has_private_key = true;
    }

    public long getSecretKey() {
        if (master_key == 0) {
            throw new GmSSLException("");
        }
        if (has_private_key == false) {
            throw new GmSSLException("");
        }
        return master_key;
    }

    public SM9UserKey extractKey(String id) {
        if (this.master_key == 0) {
            throw new GmSSLException("");
        }
        if (this.has_private_key == false) {
            throw new GmSSLException("");
        }
        long key;
        if ((key = GmSSLJNI.sm9_enc_master_key_extract_key(this.master_key, id)) == 0) {
            throw new GmSSLException("");
        }
        return new SM9EncUserKey(key, id);
    }

}
