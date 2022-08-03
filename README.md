# GmSSL JNI

本项目是GmSSL密码库接口的Java语言封装，可以用于Java及Android平台上的应用开发。GmSSL JNI提供了包括随机数生成、对称加解密、哈希、消息认证码(MAC)、公钥加解密、数字签名、密钥交换等基础密码功能的Java语言接口，支持包括SM2/SM3/SM4/ZUC在内的GmSSL密码库的主要密码算法。

## 接口说明

GmSSL Java Wrapper的接口如下：

```java
public class GmSSL {

	public native String getVersion(int type);
	public native byte [] generateRandom(int length);
	public native String [] getCiphers(boolean aliases);
	public native int getCipherIVLength(String cipher);
	public native int getCipherKeyLength(String cipher);
	public native int getCipherBlockSize(String cipher);
	public native byte [] symmetricEncrypt(String cipher, int flag, byte [] in, byte [] key, byte [] iv);
	public native byte [] symmetricDecrypt(String cipher, int flag, byte [] in, byte [] key, byte [] iv);
	public native String [] getDigests(boolean aliases);
	public native int getDigestLength(String digestAlgor);
	public native int getDigestBlockSize(String digestAlgor);
	public native byte [] digest(String algor, int flag, byte [] data);
	public native String [] getMacs(boolean aliases);
	public native String [] getMacLength(String algor);
	public native byte [] mac(String algor, int flag, byte [] data, byte [] key);
	public native String [] getSignAlgorithms(boolean aliases);
	public native byte [] sign(String algor, int flag, byte [] data, byte [] privateKey);
	public native int verify(String algor, int flag, byte [] digest, byte [] signature, byte [] publicKey);
	public native String [] getPublicKeyEncryptions(boolean aliases);
	public native byte [] publicKeyEncrypt(String algor, int flag, byte [] in, byte [] publicKey);
	public native byte [] publicKeyDecrypt(String algor, int falg, byte [] in, byte [] privateKey);
	public native String [] getDeriveKeyAlgorithms(boolean aliases);
	public native byte [] deriveKey(String algor, int flag, int keyLength, byte [] peerPublicKey, byte [] privateKey);

	static {
		System.loadLibrary("gmssl");
	}
}
```

GmSSL-JNI的实现依赖链接的GmSSL库，应用程序在运行时可以通过`getVersion()`接口获取GmSSL库的版本号。通过`getCiphers()`、`getDigests()`、`getMacs()`、`getSignAlgorithms()`、`getPublicKeyEncryptions()`和`getKeyDeriveAlgorithms()`获取当前GmSSL支持的算法，这些接口返回以`:`字符分隔的算法名称字符串，这些算法名称字符串可以用于密码操作接口的输入参数。在GmSSL中，部分算法有别名，通过`aliases`参数可以设定是否输出算法别名。

GmSSL Java Wrapper支持如下密码功能：

* 随机数生成：`generateRandom()`
* 对称加解密：`symmetricEncrypt()`、`symmetricDecrypt()`
* 哈希：`digest()`
* 消息认证码：`mac()`
* 数字签名：`sign()`、`verify()`
* 公钥加解密：`publicKeyEncrypt()`、`publicKeyDecrypt()`
* 密钥交换：`deriveKey()`

除了随机数生成之外，其他的接口都需要提供字符串格式的算法名称。

### 返回值

应用应该总是检查返回值。

* 如果返回值为整数，仅当返回值为大于0时正确，小于等于0时错误。
* 如果返回值为字符串或字节数组，返回空表示错误

