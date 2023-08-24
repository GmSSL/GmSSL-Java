# GmSSL Java

本项目是GmSSL密码库接口的Java语言封装，可以用于Java及Android平台上的应用开发。GmSSL JNI提供了包括随机数生成、对称加解密、哈希、消息认证码(MAC)、公钥加解密、数字签名、密钥交换等基础密码功能的Java语言接口，支持包括SM2/SM3/SM4/ZUC在内的GmSSL密码库的主要密码算法。

GmSSL Java包含的功能如下：

 * 随机数生成
 * SM3哈希、SM3 HMAC 和 SM3 PBKDF2密钥导出
 * SM4分组密码和SM4 CBC/CTR/GCM模式
 * SM2签名、加密
 * SM9签名、加密
 * ZUC序列密码加密
 * SM2证书的解析、验证

### 编译

首先需要在系统上安装基础的GCC编译工具链、CMake和Java环境，在Ubuntu/Debian系统上可以执行如下命令安装依赖的工具。

```bash
sudo apt update
sudo apt install build-essential cmake default-jdk
```

安装完成后可以通过CMake编译

```bash
mkdir build
cd build
cmake ..
make
make test
```

编译并测试成功后可以显示

```bash
$ make test
Running tests...
Test project /path/to/GmSSL-Java/build
    Start 1: main
1/1 Test #1: main .............................   Passed    2.27 sec

100% tests passed, 0 tests failed out of 1

Total Test time (real) =   2.27 sec
```

此时查看`build`目录下可以看到生成的本地动态库`libgmssljni`和GmSSLJNI的Jar包`GmSSLJNI.jar`、`GmSSLJNI-2.0.0.jar`。

### 手动编译

首先在源代码目录下创建编译目录`build`

```
mkdir build
```

在编译目录下，通过CMake编译JNI本地代码

```
cd build
cmake ..
make
cd ..
```

在编译完成后，会在`build`目录下生成`libgmssljni.so`动态库。

然后编译项目中的Java代码并生成JAR包

```
javac org/gmssl/GmSSLJNI.java
jar cf GmSSLJNI.jar org/gmssl/GmSSLJNI.class
```

现在已经生成了`GmSSLJNI.jar`，注意这个JAR包依赖`build`目录下的libgmssljni动态库，因为JAR包中的Java代码只提供了接口，而功能实现都是由libgmssljni的C代码实现的。

为了测试功能，还需要准备一个测试用的证书文件，GmSSL-Java目前支持PEM格式的证书文件。将下面的文本复制到文件`ROOTCA.PEM`文件中并保存。

```
-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----
```

现在可执行程序和测试文件都准备好了，可以执行下面的命令进行测试

```
java -cp GmSSLJNI.jar -Djava.library.path=build org.gmssl.GmSSLJNI
```

## 接口说明

GmSSL Java Wrapper的接口如下：

```java
package org.gmssl;

public class GmSSLJNI {

	public final static String GMSSL_JNI_VERSION = "GmSSL JNI 2.0.0";

	public final static int SM3_DIGEST_SIZE = 32;
	public final static int SM3_HMAC_SIZE = 32;
	public final static int SM3_HMAC_MIN_KEY_SIZE = 16;
	public final static int SM4_KEY_SIZE = 16;
	public final static int SM4_BLOCK_SIZE = 16;
	public final static int SM4_GCM_MIN_IV_SIZE = 1;
	public final static int SM4_GCM_MAX_IV_SIZE = 64;
	public final static int SM4_GCM_DEFAULT_IV_SIZE = 12;
	public final static int SM4_GCM_MAX_TAG_SIZE = 16;
	public final static String SM2_DEFAULT_ID = "1234567812345678";
	public final static int SM2_MAX_PLAINTEXT_SIZE = 255;
	public final static int SM9_MAX_PLAINTEXT_SIZE = 255;
	public final static int ZUC_KEY_SIZE = 16;
	public final static int ZUC_IV_SIZE = 16;

	public final static native int version_num();
	public final static native String version_str();

	public final static native int rand_bytes(byte[] buf, int offset, long nbytes);

	public final static native long sm3_ctx_new();
	public final static native void sm3_ctx_free(long sm3_ctx);
	public final static native int sm3_init(long sm3_ctx);
	public final static native int sm3_update(long sm3_ctx, byte[] data, int offset, int datalen);
	public final static native int sm3_finish(long sm3_ctx, byte[] dgst);
	public final static native long sm3_hmac_ctx_new();
	public final static native void sm3_hmac_ctx_free(long sm3_hmac_ctx);
	public final static native int sm3_hmac_init(long sm3_hmac_ctx, byte[] key);
	public final static native int sm3_hmac_update(long sm3_hmac_ctx, byte[] data, int offset, int datalen);
	public final static native int sm3_hmac_finish(long sm3_hmac_ctx, byte[] hmac);

	public final static native long sm4_key_new();
	public final static native void sm4_key_free(long sm4_key);
	public final static native int sm4_set_encrypt_key(long sm4_key, byte[] key);
	public final static native int sm4_set_decrypt_key(long sm4_key, byte[] key);
	public final static native int sm4_encrypt(long sm4_key, byte[] in, int in_offset, byte[] out, int out_offset);
	public final static native long sm4_cbc_ctx_new();
	public final static native void sm4_cbc_ctx_free(long sm4_cbc_ctx);
	public final static native int sm4_cbc_encrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv);
	public final static native int sm4_cbc_encrypt_update(long sm4_cbc_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_cbc_encrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset);
	public final static native int sm4_cbc_decrypt_init(long sm4_cbc_ctx, byte[] key, byte[] iv);
	public final static native int sm4_cbc_decrypt_update(long sm4_cbc_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_cbc_decrypt_finish(long sm4_cbc_ctx, byte[] out, int out_offset);
	public final static native long sm4_ctr_ctx_new();
	public final static native void sm4_ctr_ctx_free(long sm4_ctr_ctx);
	public final static native int sm4_ctr_encrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv);
	public final static native int sm4_ctr_encrypt_update(long sm4_ctr_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_ctr_encrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset);
	public final static native int sm4_ctr_decrypt_init(long sm4_ctr_ctx, byte[] key, byte[] iv);
	public final static native int sm4_ctr_decrypt_update(long sm4_ctr_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_ctr_decrypt_finish(long sm4_ctr_ctx, byte[] out, int out_offset);
	public final static native long sm4_gcm_ctx_new();
	public final static native void sm4_gcm_ctx_free(long sm4_gcm_ctx);
	public final static native int sm4_gcm_encrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int taglen);
	public final static native int sm4_gcm_encrypt_update(long sm4_gcm_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_gcm_encrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset);
	public final static native int sm4_gcm_decrypt_init(long sm4_gcm_ctx, byte[] key, byte[] iv, byte[] aad, int taglen);
	public final static native int sm4_gcm_decrypt_update(long sm4_gcm_ctx, byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public final static native int sm4_gcm_decrypt_finish(long sm4_gcm_ctx, byte[] out, int out_offset);

	public final static native long sm2_key_generate();
	public final static native void sm2_key_free(long sm2_key);
	public final static native int sm2_private_key_info_encrypt_to_pem(long sm2_key, String pass, String file);
	public final static native long sm2_private_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm2_public_key_info_to_pem(long sm2_key, String file);
	public final static native long sm2_public_key_info_from_pem(String file);
	public final static native int sm2_compute_z(long sm2_key, String id, byte[] z);
	public final static native byte[] sm2_sign(long sm2_key, byte[] dgst);
	public final static native int sm2_verify(long sm2_key, byte[] dgst, byte[] sig);
	public final static native byte[] sm2_encrypt(long sm2_key, byte[] in);
	public final static native byte[] sm2_decrypt(long sm2_key, byte[] in);
	public final static native long sm2_sign_ctx_new();
	public final static native void sm2_sign_ctx_free(long sm2_sign_ctx);
	public final static native int sm2_sign_init(long sm2_sign_ctx, long sm2_key, String id);
	public final static native int sm2_sign_update(long sm2_sign_ctx, byte[] data, int offset, int length);
	public final static native byte[] sm2_sign_finish(long sm2_sign_ctx);
	public final static native int sm2_verify_init(long sm2_sign_ctx, long sm2_key, String id);
	public final static native int sm2_verify_update(long sm2_sign_ctx, byte[] data, int offset, int length);
	public final static native int sm2_verify_finish(long sm2_sign_ctx, byte[] sig);

	public final static native long sm9_sign_master_key_generate();
	public final static native void sm9_sign_master_key_free(long sm9_sign_master_key);
	public final static native int sm9_sign_master_key_info_encrypt_to_pem(long sm9_sign_master_key, String pass, String file);
	public final static native long sm9_sign_master_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm9_sign_master_public_key_to_pem(long sm9_sign_master_pub, String file);
	public final static native long sm9_sign_master_public_key_from_pem(String file);
	public final static native long sm9_sign_master_key_extract_key(long sm9_sign_master_key, String id);
	public final static native void sm9_sign_key_free(long sm9_sign_key);
	public final static native int sm9_sign_key_info_encrypt_to_pem(long sm9_sign_key, String pass, String file);
	public final static native long sm9_sign_key_info_decrypt_from_pem(String pass, String file);
	public final static native long sm9_sign_ctx_new();
	public final static native void sm9_sign_ctx_free(long sm9_sign_ctx);
	public final static native int sm9_sign_init(long sm9_sign_ctx);
	public final static native int sm9_sign_update(long sm9_sign_ctx, byte[] data, int offset, int length);
	public final static native byte[] sm9_sign_finish(long sm9_sign_ctx, long sm9_sign_key);
	public final static native int sm9_verify_init(long sm9_sign_ctx);
	public final static native int sm9_verify_update(long sm9_sign_ctx, byte[] data, int offset, int length);
	public final static native int sm9_verify_finish(long sm9_sign_ctx, byte[] sig, long sm9_sign_master_pub, String id);
	public final static native long sm9_enc_master_key_generate();
	public final static native void sm9_enc_master_key_free(long sm9_enc_master_key);
	public final static native int sm9_enc_master_key_info_encrypt_to_pem(long sm9_enc_master_key, String pass, String file);
	public final static native long sm9_enc_master_key_info_decrypt_from_pem(String pass, String file);
	public final static native int sm9_enc_master_public_key_to_pem(long sm9_enc_master_pub, String file);
	public final static native long sm9_enc_master_public_key_from_pem(String file);
	public final static native long sm9_enc_master_key_extract_key(long sm9_enc_master_key, String id);
	public final static native void sm9_enc_key_free(long sm9_sign_key);
	public final static native int sm9_enc_key_info_encrypt_to_pem(long sm9_enc_key, String pass, String file);
	public final static native long sm9_enc_key_info_decrypt_from_pem(String pass, String file);
	public final static native byte[] sm9_encrypt(long sm9_enc_master_pub, String id, byte[] in);
	public final static native byte[] sm9_decrypt(long sm9_enc_key, String id, byte[] in);

	public final static native byte[] cert_from_pem(String file);
	public final static native int cert_to_pem(byte[] cert, String file);
	public final static native byte[] cert_get_serial_number(byte[] cert);
	public final static native String[] cert_get_issuer(byte[] cert);
	public final static native String[] cert_get_subject(byte[] cert);
	public final static native long cert_get_not_before(byte[] cert);
	public final static native long cert_get_not_after(byte[] cert);
	public final static native long cert_get_subject_public_key(byte[] cert);
	public final static native int cert_verify_by_ca_cert(byte[] cert, byte[] cacert, String ca_sm2_id);

	static {
		System.loadLibrary("gmssljni");
	}
}
```

### 返回值

Java返回值和GmSSL C函数返回值保持一致

### Roadmap

[] Update C API
[] New Java API
[] Include GmSSL in this repo

