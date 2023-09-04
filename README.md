# GmSSL-Java

本项目是GmSSL密码库的Java语言封装，可以用于Java环境和Android系统上的应用开发。GmSSL-Java目前提供了随机数生成器、SM3哈希、SM3消息认证码(SM3-HMAC)、SM4加密（包括分组加密和CBC/CTR/GCM加密模式）、ZUC加密、SM2加密/签名、SM9加密/签名、SM2证书解析等功能，可以覆盖目前国密算法主要应用开发场景。

GmSSL-Java是采用JNI (Java Native Interface)方式实现的，也就是说所有底层密码功能（以及消息、文件的编解码等）均为调用GmSSL库实现，因此在功能、标准、性能上和GmSSL的C库、命令行工具几乎一致。GmSSL-Java将各种算法封装为独立的Java类，方便应用调用。包含的具体类及功能参见下面的接口说明一节。

因为GmSSL-Java以JNI方式实现，GmSSL-Java不仅包含Java语言实现的Java类库（Jar包），还包括C语言实现的本地库（libgmssljni动态库），其中libgmssljni这个本地库是Java接口类库和GmSSL库(libgmssl)之间的胶水层，应用部署时还需要保证系统中已经安全了GmSSL库。虽然看起来这种实现方式比纯Java实现的类似更麻烦，而且因为包含C编译的本地代码，这个类库也失去了Java代码一次编译到处运行的跨平台能力，但是这是密码库的主流实现方式。相对于纯Java实现来说，GmSSL-Java可以充分利用成熟和功能丰富的GmSSL库，在性能、标准兼容性上都更有优势，并且可以随着GmSSL主项目的升级获得功能和性能上的升级。

## 项目组成

GmSSL的项目组成主要包括C语言的本地代码、`src`目录下的Java类库代码、`examples`目录下面的例子代码。其中只有本地代码和`src`下面的Java类库代码会参与默认的编译，生成动态库和Jar包，而`examples`下的例子默认不编译也不进入Jar包。

## 编译和安装

GmSSL-Java依赖GmSSL项目，在编译前需要先在系统上编译、安装并测试通过GmSSL库及工具。请在https://github.com/guanzhi/GmSSL 项目上下载最新的GmSSL代码，并完成编译、测试和安装。

首先下载最新的GmSSL-Java代码，然后安装编译工具链。

GmSSL-Java的当前版本采用CMake编译工具链，需要在系统上安装基础的GCC编译工具链、CMake和Java环境，在Ubuntu/Debian系统上可以执行如下命令安装依赖的工具。

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

此时查看`build`目录下可以看到生成的本地动态库`libgmssljni`和GmSSLJNI的Jar包`GmSSLJNI.jar`、`GmSSLJNI-2.1.0-dev.jar`。

## 接口说明

GmSSL-Java包含如下密码算法类

* org.gmssl.Random
* org.gmssl.Sm3
* org.gmssl.Sm3Hmac
* org.gmssl.Sm4
* org.gmssl.Sm4Cbc
* org.gmssl.Sm4Ctr
* org.gmssl.Sm4Gcm
* org.gmssl.Zuc
* org.gmssl.Sm2Key
* org.gmssl.Sm2Signature
* org.gmssl.Sm9SignMasterKey
* org.gmssl.Sm9SignKey
* org.gmssl.Sm9Signature
* org.gmssl.Sm9EncMasterKey
* org.gmssl.Sm9EncKey
* org.gmssl.Certificate
* org.gmssl.GmSSLException



####随机数生成器

类`Random`实现随机数生成功能，通过`randBytes`方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的随机种子。

```java
public class Random {
	public Random();
	public byte[] randBytes(int len);
	public void randBytes(byte[] out, int offset, int len);
}
```

`Random`是通过调用操作系统的密码随机数生成器（如`/dev/urandom`）实现的。由于底层操作系统的限制，在一次调用`randBytes`时不要指定明显超过密钥长度的输出长度，例如参数`len`的值不要超过128，否则可能导致阻塞，或者产生错误和异常。如果应用需要大量的随机数据，不应使用`Random`，而是应该考虑其他伪随机数生成算法。

需要注意的是，`Random`类的安全性依赖于底层的操作系统随机数生成器的安全性。在服务器、笔记本等主流硬件和Windows、Linux、Mac主流服务器、桌面操作系统环境上，当计算机已经启动并且经过一段时间的用户交互和网络通信后，`randBytes`可以输出高质量的随机数。但是在缺乏用户交互和网络通信的嵌入式设备中，`randBytes`返回的随机数可能存在随机性不足的问题，在这些特殊的环境中，开发者需要提前或在运行时检测`Random`是否能够提供具有充分的随机性。

#### SM3哈希

SM3密码杂凑函数可以将任意长度的输入数据计算为固定32字节长度的哈希值。在国密系列算法中，所有需要输入哈希值的场景中，默认的生成算法也是SM3。类`Sm3`实现了SM3的功能。

```java
public class Sm3 {
  public final static int DIGEST_SIZE;
	public Sm3();
	public void reset();
	public void update(byte[] data, int offset, int len);
	public void update(byte[] data);
	public byte[] digest();
}
```

在需要计算SM3哈希值时，在生成`Sm3`对象实例之后，可以多次调用`update`方法来提供输入数据，在输入完所有的数据之后，通过调用`digest`方法就可以获得所有输入数据的SM3哈希值了。`digest`方法输出的是长度为`DIGEST_SIZE`字节（即32字节）的二进制哈希值。

如果应用要计算多组数据的不同SM3哈希值，可以通过`reset`方法重置`Sm3`对象的状态，然后可以再次调用`update`和`digest`方法计算新一组数据的哈希值。这样只需要一个`Sm3`对象就可以完成多组哈希值的计算。

#### HMAC-SM3

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，`Sm3Hmac`类实现了基于SM3的HMAC消息认证码算法。HMAC-SM3算法需要一个密钥作为输入，虽然HMAC算法通常对密钥长度没有限制，但是出于安全性、效率等方面的考虑，HMAC-SM3算法的密钥长度建议采用32字节，不应少于16字节，HMAC-SM3支持比32字节更长的密钥长度，但是会增加计算开销而不会增加安全性。

HMAC-SM3输出为固定32字节长度的消息认证码，应用在通过`update`完成数据输入后，调用`generateMac`可以获得消息认证码。

```java
public class Sm3Hmac {
	public final static int MAC_SIZE;

	public Sm3Hmac(byte[] key);
	public void reset(byte[] key);
	public void update(byte[] data, int offset, int len);
  public void update(byte[] data);
  public byte[] generateMac();
}
```

#### SM4

SM4算法是一个分组密码算法，其密钥长度为128比特（16字节），分组长度为128比特（16字节）。SM4算法每次只能加密或者解密一个固定16字节长度的分组，不支持加解密任意长度的消息，通常作为更高层密码方案的一个底层模块，不适合普通应用来调用。如果应用需要保护数据和消息，那么应该优先选择采用SM4-GCM模式，或者为了兼容已有的系统，也可以使用SM4-CBC或SM4-CTR模式。

类`Sm4`实现了基本的SM4分组密码算法。

```java
public class Sm4 {
	public final static int KEY_SIZE = 16;
	public final static int BLOCK_SIZE = 16;
	public Sm4(byte[] key, boolean do_encrypt);
	public void encrypt(byte[] in, int in_offset, byte[] out, int out_offset);
}
```

`Sm4`对象在创建时需要提供`KEY_SIZE`字节长度的密钥，以及一个布尔值`do_encrypt`表示是用于加密还是解密。方法`encrypt`根据创建时的选择进行加密或解密，每次调用`encrypt`只处理一个分组，即读入`BLOCK_SIZE`长度的输入，向`out`的`outOffset`偏移地址写入16字节的输出。

#### SM4-CBC

CBC模式是应用最广泛的分组密码加密模式之一，虽然目前不建议在新的应用中继续使用CBC默认，为了保证兼容性，应用仍然可能需要使用CBC模式。

`Sm4Cbc`类实现了SM4的带填充CBC模式，可以实现对任意长度数据的加密。在JCE等Java密码实现中，带填充的CBC模式通常被表示为`CBC/PKCS5Padding`，注意，`Sm4Cbc`类不支持不带填充的CBC模式，即JCE中的`CBC/NoPadding`。由于需要对明文进行填充，因此`Sm4Cbc`输出的密文长度总是长于明文长度，并且密文的长度是整数个分组长度。

```java
public class Sm4Cbc {
	public final static int KEY_SIZE = 16;
	public final static int IV_SIZE = 16;
	public final static int BLOCK_SIZE = 16;
	
	public Sm4Cbc();
	public void init(byte[] key, byte[] iv, boolean do_encrypt);
	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public int doFinal(byte[] out, int out_offset);
}
```

通过`Sm4Cbc`加密时，需要首先调用`init`进行初始化，其中`key`和`iv`都必须为16字节长度。由于CBC模式中加密和解密的计算过程不同，因此在调用`init`初始化时，必须通过布尔值`do_encrypt`指定是加密还是解密。

由于`Sm4Cbc`在加解密时维护了内部的缓冲区，因此`update`的输出长度可能不等于输入长度，应该保证输出缓冲区的长度至少比输入长度长一个`BLOCK_SIZE`长度。

#### SM4-CTR

CTR加密模式可以加密任意长度的消息，和CBC模式不同，并不需要采用填充方案，因此SM4-CTR加密输出的密文长度和输入的明文等长。对于存储或传输带宽有限的应用场景，SM4-CTR相对SM4-CBC模式，密文不会增加格外长度。

```java
public class Sm4Ctr {
	public final static int KEY_SIZE;
	public final static int IV_SIZE;
	public final static int BLOCK_SIZE;
	
	public Sm4Ctr();
	public void init(byte[] key, byte[] iv);
	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public int doFinal(byte[] out, int out_offset);
}
```

由于`Sm4Ctr`在加解密时维护了内部的缓冲区，因此`update`的输出长度可能不等于输入长度，应该保证输出缓冲区的长度至少比输入长度长一个`BLOCK_SIZE`长度。

注意 ，SM4-CBC和SM4-CTR模式都不能保证消息的完整性，在使用这两个模式时，应用还需要生成一个独立的HMAC-SM3密钥，并且生成密文的MAC值。

#### SM4-GCM

SM4的GCM模式是一种认证加密模式，和CBC、CTR等加密模式的主要区别在于，GCM模式的加密过程默认在密文最后添加完整性标签，也就是MAC标签，因此应用在采用SM4-GCM模式时，没有必要再计算并添加SM3-HMAC了。在有的应用场景中，比如对消息报文进行加密，对于消息头部的一段数据（报头字段）只需要做完整性保护，不需要加密，SM4-GCM支持这种场景。在`Sm4Gcm`类的`init`方法中，除了`key`、`iv`参数，还可以提供`aad`字节数字用于提供不需要加密的消息头部数据。

```
public class Sm4Gcm {
	public final static int KEY_SIZE;
	public final static int MIN_IV_SIZE;
	public final static int MAX_IV_SIZE;
	public final static int DEFAULT_IV_SIZE;
	public final static int BLOCK_SIZE;
	
	public Sm4Gcm();
	public void init(byte[] key, byte[] iv, byte[] aad, int taglen, boolean do_encrypt);
	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public int doFinal(byte[] out, int out_offset);
}
```

GCM模式和CBC、CTR、HMAC不同之处还在于可选的IV长度和MAC长度，其中IV的长度必须在`MIN_IV_SIZE`和`MAX_IV_SIZE`之间，长度为`DEFAULT_IV_SIZE`有最佳的计算效率。MAC的长度也是可选的，通过`init`方法中的`taglen`设定，其长度不应低于8字节，不应长于`BLOCK_SIZE = 16`字节。

#### Zuc

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，可以加解密任意长度数据。`Zuc`类实现了ZUC算法的加解密。

```java
public class Zuc {
	public final static int KEY_SIZE;
	public final static int IV_SIZE;
	public final static int BLOCK_SIZE;
	
	public Zuc();
	public void init(byte[] key, byte[] iv);
	public int update(byte[] in, int in_offset, int inlen, byte[] out, int out_offset);
	public int doFinal(byte[] out, int out_offset);
}
```

由于`Zuc`实现加解密中有内部的缓冲区，因此`update`的输出长度可能和输入长度不一致。

#### SM2

SM2是国密标准中的椭圆曲线公钥密码，包含数字签名算法和公钥加密算法。SM2相关的功能由类`Sm2Key`和`Sm2Signature`实现，其中`Sm2Key`实现了SM2密钥对的生成、基础的加密和签名方案，`Sm2Signature`类实现了对任意长度消息签名的签名方案。

```java
public class Sm2Key {
	public final static int MAX_PLAINTEXT_SIZE;
	public final static String DEFAULT_ID;
	
	public Sm2Key();
	public void generateKey();
  
	public void importPrivateKeyInfoDer(byte[] der);
	public byte[] exportPrivateKeyInfoDer();
	public void importPublicKeyInfoDer(byte[] der);
	public byte[] exportPublicKeyInfoDer();
  
	public void importEncryptedPrivateKeyInfoPem(String pass, String file);
	public void exportEncryptedPrivateKeyInfoPem(String pass, String file);
	public void importPublicKeyInfoPem(String file);
	public void exportPublicKeyInfoPem(String file);
	
  public byte[] computeZ(String id);
	public byte[] sign(byte[] dgst);
	public boolean verify(byte[] dgst, byte[] signature);
	public byte[] encrypt(byte[] plaintext);
	public byte[] decrypt(byte[] ciphertext);
}
```

需要注意的是，通过构造函数生成的新`Sm2Key`对象是一个空白的对象，可以通过`generateKey`方法生成一个新的密钥对，或者通过导入函数从外部导入密钥。`Sm2Key`一共提供了4个不同的导入方法：

* `importPrivateKeyInfoDer` 从字节数组中导入SM2私钥，因此导入密钥后这个`Sm2Key`对象可以执行签名操作和解密操作，也可以执行验证签名和加密。
* `importEncryptedPrivateKeyInfoPem` 从加密的PEM文件中导入SM2私钥，因此调用时需要提供PEM文件的路径和解密的口令(Password)。
* `importPublicKeyInfoDer`从字节数组中导入SM2公钥，因为其中没有私钥，因此这个`Sm2Key`对象不能执行签名和解密操作，只能执行验证签名和加密操作。
* `importPublicKeyInfoPem`从PEM文件中导入SM2公钥，只需要提供文件的路径，不需要提供口令。

上面四个导入函数也都有对应的导出函数。从字节数组中导入导出DER编码的公钥和私钥和JCE兼容，但是因为私钥需要以明文的方式写入到字节数组中，因此安全性比较低。从PEM文件中导入导出公钥私钥和`gmssl`命令行工具的默认密钥格式一致，并且在处理私钥时安全性更高。因此建议在默认情况下，在导入导出私钥时默认采用加密的PEM文件格式。

`Sm2Key`类除了`generateKey`方法之外，提供了`computeZ`、`sign`、`verify`、`encrypt`、`decrypt`这几个密码计算相关的方法。

其中`computeZ`是由公钥和用户的字符串ID值计算出一个称为“Z值”的哈希值，用于对消息的签名。由于`Sm2Signature`类中提供了SM2消息签名的完整功能，因此这个`computeZ`方法只是用于实验验证。由于这个计算只需要公钥，因此如果密钥值是通过`importPublicKeyInfoDer`等导入的，也可以成功计算出32字节的哈希值结果。

类`Sm2Key`的`sign`和`verify`方法实现了SM2签名的底层功能，这两个方法不支持对数据或消息的签名，只能实现对SM3哈希值的签名和验证，并没有实现SM2签名的完整功能。应用需要保证调用时提供的`dgst`参数的字节序列长度为32。只有密码协议的底层开发者才需要调用`computeZ`、`sign`、`verify`这几个底层方法。

类`Sm2Key`的`encrypt`和`decrypt`方法实现了SM2加密和解密功能。注意，虽然SM2标准中没有限制加密消息的长度，但是公钥加密应该主要用于加密较短的对称密钥、主密钥等密钥数据，因此GmSSL库中限制了SM2加密消息的最大长度。应用在调用`encrypt`时，需要保证输入的明文长度不超过`MAX_PLAINTEXT_SIZE`的限制。如果需要加密引用层的消息，应该首先生成对称密钥，用SM4-GCM加密消息，再用SM2加密对称密钥。

类`Sm2Signatue`提供了对任意长消息的签名、验签功能。

在生成`Sm2Signature`对象时，不仅需要提供`Sm2Key`，还需要提供签名方的字符串ID，以满足SM2签名的标准。如果提供的`Sm2Key`来自于导入的公钥，那么这个`Sm2Signature`对象只能进行签名验证操作，即在构造时`do_sign = false`，并且只能调用`verify`方法，不能调用`sign`方法。

```
public class Sm2Signature {
	public final static String DEFAULT_ID;
	
	public Sm2Signature(Sm2Key key, String id, boolean do_sign);
	public void reset(Sm2Key key, String id, boolean do_sign);
	public void update(byte[] data, int offset, int len);
	public void update(byte[] data);
	public byte[] sign();
	public boolean verify(byte[] signature);
}
```

不管是`Sm2Key`的`sign`还是`Sm2Signature`的`sign`方法输出的都是DER编码的签名值。这个签名值的第一个字节总是`0x30`，并且长度是可变的，常见的长度包括70字节、71字节、72字节，也可能短于70字节。一些SM2的实现不能输出DER编码的签名，只能输出固定64字节长度的签名值。可以通过签名值的长度以及首字节的值来判断SM2签名值的格式。

#### SM9

SM9是国密标准中的身份密码，包括基于身份的加密和基于身份的签名，SM9方案中用户的签名、解密私钥也不是自己生成的，而是从主密钥(MasterKey)中导出的。SM9签名方案和加密方案中的主密钥、用户密钥的类型并不相同，GmSSL-Java中提供了不同的类来实现这些密钥类型。

```java
public class Sm9EncMasterKey {
  public final static int MAX_PLAINTEXT_SIZE;
  
	public Sm9SEncMasterKey();
	public void generateMasterKey();
	public Sm9EncKey extractKey(String id);
	public void importEncryptedMasterKeyInfoPem(String pass, String file);
	public void exportEncryptedMasterKeyInfoPem(String pass, String file);
	public void importPublicMasterKeyPem(String file);
	public void exportPublicMasterKeyPem(String file);
	public byte[] encrypt(byte[] plaintext, String id);
}
```



```java
public class Sm9EncKey {
	public Sm9EncKey(String id);
	public String getId();
  public void exportEncryptedPrivateKeyInfoPem(String pass, String file);
  public void importEncryptedPrivateKeyInfoPem(String pass, String file);
  public byte[] decrypt(byte[] ciphertext);
}
```



```java
public class Sm9SignMasterKey {
	public Sm9SignMasterKey();
	public void generateMasterKey();
	public Sm9SignKey extractKey(String id);
	public void importEncryptedMasterKeyInfoPem(String pass, String file);
	public void exportEncryptedMasterKeyInfoPem(String pass, String file);
	public void importPublicMasterKeyPem(String file);
	public void exportPublicMasterKeyPem(String file);
}
```



```java
public class Sm9SignKey {
	public Sm9SignKey(String id);
	public String getId();
  public void exportEncryptedPrivateKeyInfoPem(String pass, String file);
  public void importEncryptedPrivateKeyInfoPem(String pass, String file);
}
```



```java
public class Sm9Signature {
	public Sm9Signature(boolean do_sign);
	public void reset(boolean do_sign);
	public void update(byte[] data, int offset, int len);
	public void update(byte[] data);
	public byte[] sign(Sm9SignKey signKey);
	public boolean verify(byte[] signature, Sm9SignMasterKey masterPublicKey, String id);
}
```




