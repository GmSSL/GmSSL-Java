# GmSSL-Java

本项目是GmSSL密码库的Java语言封装，可以用于Java环境和Android系统上的应用开发。GmSSL-Java目前提供了随机数生成器、SM3哈希、SM3消息认证码(HMAC-SM3)、SM4加密（包括分组加密和CBC/CTR/GCM加密模式）、ZUC加密、SM2加密/签名、SM9加密/签名、SM2证书解析等功能，可以覆盖目前国密算法主要应用开发场景。

GmSSL-Java是采用JNI (Java Native Interface)方式实现的，也就是说所有底层密码功能（以及消息、文件的编解码等）均为调用GmSSL库实现，因此在功能、标准、性能上和GmSSL的C库、命令行工具几乎完全一致。GmSSL-Java将各种算法封装为独立的Java类，方便应用调用。包含的具体类及功能参见接口说明一节。

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

SM3密码杂凑函数可以将任意长度的输入数据计算为固定32字节长度的哈希值。

类`Sm3`实现了SM3的功能。

```java
public class Sm3 {
  public final static int DIGEST_SIZE = 32;
	public Sm3();
	public void reset();
	public void update(byte[] data, int offset, int len);
	public void update(byte[] data);
	public byte[] digest();
}
```

下面的例子展示了如何通过类`Sm3`计算字符串的SM3哈希值。

```java
import org.gmssl.Sm3;

public class Sm3Example {

	public static void main(String[] args) {

		Sm3 sm3 = new Sm3();
		sm3.update("abc".getBytes());
		byte[] dgst = sm3.digest();

		int i;
		System.out.printf("sm3('abc'): ");
		for (i = 0; i < dgst.length; i++) {
			System.out.printf("%02x", dgst[i]);
		}
		System.out.print("\n");
	}
}
```

这个例子的源代码在`examples/Sm3Example.java`文件中，编译并运行这个例子。

```bash
$ javac -cp /path/to/jar/GmSSLJNI.jar Sm3Example.java
$ java -Djava.library.path=/path/to/dylib/ -cp /path/to/jar/GmSSLJNI.jar:. Sm3Example
sm3('abc'): 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

打印出的`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`就是字符串`abc`的哈希值。字符串`abc`的哈希值也是SM3标准文本中给出的第一个测试数据，通过对比标准文本可以确定这个哈希值是正确的。

也可以通过`gmssl`命令行来验证`Sm3`类的计算是正确的。

```bash
$ echo -n abc | gmssl sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

可以看到输出的结果是一样。

注意，如果将字符串`abc`写入到文本文件中，文本编辑器通常会在文本结尾处增加格外的结束符，如`0x0a`字符，那么计算出的哈希值将不是上面的结果，比如可能是`12d4e804e1fcfdc181ed383aa07ba76cc69d8aedcbb7742d6e28ff4fb7776c34`。如果命令`echo`不使用`-n`的参数，也会出现同样的错误。这是很多开发者在初次进行哈希函数开发时容易遇到的错误，哈希函数的安全性质保证，即使输入的消息只差一个比特，那么输出的哈希值也完全不同。

如果需要哈希的数据来自于网络或者文件，那么应用可能需要多次读取才能获得全部的数据。在通过`Sm3`计算哈希值时，应用不需要通过保存一个缓冲区来保存全部的数据，而是可以通过多次调用`update`方法，将数据输入给`Sm3`对象，在数据全都输入完之后，最后调用`digest`方法得到全部数据的SM3哈希值。下面的代码片段展示了这一用法。

```java
Sm3 sm3 = new Sm3();
sm3.update("Hello ".getBytes());
sm3.update("world!".getBytes());
byte[] dgst = sm3.digest();
```

这个例子中两次调用了`update`方法，效果等同于

```java
sm3.update("Hello world!".getBytes());
```

如果需要哈希的数据来自于某个字节数据的一部分（比如某个数据报文的正文部分），那么可以使用`public void update(byte[] data, int offset, int len)`这个接口，可以通过提供字节数组的便宜量、长度来表示要计算哈希的数据片段。使用这个接口可以避免复制内存的开销。

注意，SM3算法也支持生成空数据的哈希值，因此下面的代码片段也是合法的。

```java
Sm3 sm3 = new Sm3();
byte[] dgst = sm3.digest();
```

GmSSL-Java其他类的`update`方法通常也都提供了这种形式的接口。在输入完所有的数据之后，通过调用`digest`方法就可以获得所有输入数据的SM3哈希值了。`digest`方法输出的是长度为`DIGEST_SIZE`字节（即32字节）的二进制哈希值。

如果应用要计算多组数据的不同SM3哈希值，可以通过`reset`方法重置`Sm3`对象的状态，然后可以再次调用`update`和`digest`方法计算新一组数据的哈希值。这样只需要一个`Sm3`对象就可以完成多组哈希值的计算。

```java
Sm3 sm3 = new Sm3();
sm3.update("abc".getBytes());
byte[] dgst1 = sm3.digest();

sm3.reset();
sm3.update("Hello ".getBytes());
sm3.update("world!".getBytes());
byte[] dgst2 = sm3.digest();
```

GmSSL-Java的部分其他类也提供了`reset`方法。

#### HMAC-SM3

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，消息认证码算法可以看作带密钥的哈希函数，主要用于保护消息不受篡改。通信双方需要事先协商出一个密钥，比如32字节的随机字节序列，数据的发送方用这个密钥对消息计算MAC值，并且把MAC值附在消息后面。消息的接收方在收到消息后，用相同的密钥计算消息的MAC值，并且和发送消息附带的MAC值做对比，如果一致说明消息没有被篡改，如果不一致，说明消息被篡改了。

`Sm3Hmac`类实现了基于SM3的HMAC消息认证码算法。

```java
public class Sm3Hmac {
	public final static int MAC_SIZE = 32;

  public Sm3Hmac(byte[] key);
	public void reset(byte[] key);
	public void update(byte[] data, int offset, int len);
  public void update(byte[] data);
  public byte[] generateMac();
}
```

HMAC-SM3算法可以看作是带密钥的SM3算法，因此在生成`Sm3Hmac`对象时需要传入一个密钥作为输入参数。虽然HMAC-SM3在算法和实现上对密钥长度没有限制，但是出于安全性、效率等方面的考虑，HMAC-SM3算法的密钥长度建议采用32字节（等同于SM3哈希值的长度），不应少于16字节，采用比32字节更长的密钥长度会增加计算开销而不会增加安全性。

下面的例子显示了如何用HMAC-SM3生成消息`abc`的MAC值。

```java
import org.gmssl.Sm3Hmac;
import org.gmssl.Random;

public class Sm3HmacExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

		Sm3Hmac sm3hmac = new Sm3Hmac(key);
		sm3hmac.update("abc".getBytes(), 0, 3);
		byte[] mac = sm3hmac.generateMac();
	}
}
```

`Sm3Hmac`也通过`update`方法来提供输入消息，应用可以多次调用`update`。

应用在通过`update`完成数据输入后，调用`generateMac`可以获得消息认证码，HMAC-SM3输出为固定32字节，即`MAC_SIZE`长度的二进制消息认证码。

#### SM4

SM4算法是分组密码算法，其密钥长度为128比特（16字节），分组长度为128比特（16字节）。SM4算法每次只能加密或者解密一个固定16字节长度的分组，不支持加解密任意长度的消息。分组密码通常作为更高层密码方案的一个组成部分，不适合普通上层应用调用。如果应用需要保护数据和消息，那么应该优先选择采用SM4-GCM模式，或者为了兼容已有的系统，也可以使用SM4-CBC或SM4-CTR模式。

类`Sm4`实现了基本的SM4分组密码算法。

```java
public class Sm4 {
	public final static int KEY_SIZE = 16;
	public final static int BLOCK_SIZE = 16;
	public Sm4(byte[] key, boolean do_encrypt);
	public void encrypt(byte[] in, int inOffset, byte[] out, int outOffset);
}
```

`Sm4`对象在创建时需要提供`KEY_SIZE`字节长度的密钥，以及一个布尔值`do_encrypt`表示是用于加密还是解密。方法`encrypt`根据创建时的选择进行加密或解密，每次调用`encrypt`只处理一个分组，即读入`BLOCK_SIZE`长度的输入，向`out`的`outOffset`偏移量写入16字节的输出。

下面的例子展示SM4分组加密

```java
import org.gmssl.Sm4;
import org.gmssl.Random;
import java.util.Arrays;

public class Sm4Example {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4.KEY_SIZE);
		byte[] plaintext1 = rng.randBytes(Sm4.BLOCK_SIZE);
		byte[] ciphertext = new byte[Sm4.BLOCK_SIZE];
		byte[] plaintext2 = new byte[Sm4.BLOCK_SIZE];

		Sm4 sm4enc = new Sm4(key, true);
		sm4enc.encrypt(plaintext1, 0, ciphertext, 0);

		Sm4 sm4dec = new Sm4(key, false);
		sm4dec.encrypt(ciphertext, 0, plaintext2, 0);
    
    System.out.println("Decryption success : " + Arrays.equals(plaintext1, plaintext2));
	}
}
```



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
	public int update(byte[] in, int inOffset, int inlen, byte[] out, int outOffset);
	public int doFinal(byte[] out, int outOffset);
}
```

通过`Sm4Cbc`加密时，需要首先调用`init`进行初始化，其中`key`和`iv`都必须为16字节长度。由于CBC模式中加密和解密的计算过程不同，因此在调用`init`初始化时，必须通过布尔值`do_encrypt`指定是加密还是解密。

由于`Sm4Cbc`在加解密时维护了内部的缓冲区，因此`update`的输出长度可能不等于输入长度，应该保证输出缓冲区的长度至少比输入长度长一个`BLOCK_SIZE`长度。

下面的例子显示了采用SM4-CBC加密和解密的过程。

```java
import org.gmssl.Sm4Cbc;
import org.gmssl.Random;

public class Sm4CbcExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4Cbc.KEY_SIZE);
		byte[] iv = rng.randBytes(Sm4Cbc.IV_SIZE);
		byte[] ciphertext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
		byte[] plaintext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
		int cipherlen;
		int plainlen;
		boolean encrypt = true;
		boolean decrypt = false;

		Sm4Cbc sm4cbc = new Sm4Cbc();

    // Encrypt
		sm4cbc.init(key, iv, encrypt);
		cipherlen = sm4cbc.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += sm4cbc.doFinal(ciphertext, cipherlen);

    // Decrypt
		sm4cbc.init(key, iv, decrypt);
		plainlen = sm4cbc.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += sm4cbc.doFinal(plaintext, plainlen);
	}
}
```

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

SM4-CTR在加密和解密时计算过程一样，因此`init`方法在初始化时不需要指定加密或解密，因此没有`Sm4Cbc`的`init`方法中的`do_encrypt`参数。其他过程和SM4-CBC是一样的。

由于`Sm4Ctr`在加解密时维护了内部的缓冲区，因此`update`的输出长度可能不等于输入长度，应该保证输出缓冲区的长度至少比输入长度长一个`BLOCK_SIZE`长度。

注意 ，SM4-CBC和SM4-CTR模式都不能保证消息的完整性，在使用这两个模式时，应用还需要生成一个独立的HMAC-SM3密钥，并且生成密文的MAC值。

#### SM4-GCM

SM4的GCM模式是一种认证加密模式，和CBC、CTR等加密模式的主要区别在于，GCM模式的加密过程默认在密文最后添加完整性标签，也就是MAC标签，因此应用在采用SM4-GCM模式时，没有必要再计算并添加SM3-HMAC了。在有的应用场景中，比如对消息报文进行加密，对于消息头部的一段数据（报头字段）只需要做完整性保护，不需要加密，SM4-GCM支持这种场景。在`Sm4Gcm`类的`init`方法中，除了`key`、`iv`参数，还可以提供`aad`字节数字用于提供不需要加密的消息头部数据。

```java
public class Sm4Gcm {
	public final static int KEY_SIZE;
	public final static int MIN_IV_SIZE;
	public final static int MAX_IV_SIZE;
	public final static int DEFAULT_IV_SIZE;
	public final static int BLOCK_SIZE;
	
	public Sm4Gcm();
	public void init(byte[] key, byte[] iv, byte[] aad, int taglen, boolean do_encrypt);
	public int update(byte[] in, int inOffset, int inlen, byte[] out, int outOffset);
	public int doFinal(byte[] out, int outOffset);
}
```

GCM模式和CBC、CTR、HMAC不同之处还在于可选的IV长度和MAC长度，其中IV的长度必须在`MIN_IV_SIZE`和`MAX_IV_SIZE`之间，长度为`DEFAULT_IV_SIZE`有最佳的计算效率。MAC的长度也是可选的，通过`init`方法中的`taglen`设定，其长度不应低于8字节，不应长于`BLOCK_SIZE = 16`字节。

下面例子展示SM4-GCM加密和解密的过程。

```java
import org.gmssl.Sm4Gcm;
import org.gmssl.Random;

public class Sm4GcmExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Sm4Gcm.KEY_SIZE);
		byte[] iv = rng.randBytes(Sm4Gcm.DEFAULT_IV_SIZE);
		byte[] aad = "Hello:".getBytes();
		int taglen = Sm4Gcm.MAX_TAG_SIZE;
		byte[] ciphertext = new byte[64];
		byte[] plaintext = new byte[64];
		int cipherlen;
		int plainlen;
		boolean encrypt = true;
		boolean decrypt = false;

		Sm4Gcm sm4gcm = new Sm4Gcm();

		sm4gcm.init(key, iv, aad, taglen, encrypt);
		cipherlen = sm4gcm.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += sm4gcm.doFinal(ciphertext, cipherlen);

		sm4gcm.init(key, iv, aad, taglen, decrypt);
		plainlen = sm4gcm.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += sm4gcm.doFinal(plaintext, plainlen);
	}
}
```

#### Zuc

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，可以加解密任意长度数据。`Zuc`类实现了ZUC算法的加解密。

```java
public class Zuc {
	public final static int KEY_SIZE = 16;
	public final static int IV_SIZE = 16;
	public final static int BLOCK_SIZE = 4;
	
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



和`Sm2Key`不同，`Sm9SignKey`和`Sm9EncKey`中总是包含私钥。



```java
public class Sm9SignKey {
	public Sm9SignKey(String id);
	public String getId();
  public void exportEncryptedPrivateKeyInfoPem(String pass, String file);
  public void importEncryptedPrivateKeyInfoPem(String pass, String file);
}
```





类`Sm9Signature`实现对数据的SM9签名和验证功能。SM9签名时需要提供`Sm9SignKey`类型的签名方私钥（其中包含签名者的ID），在验证签名时需要提供`Sm9SignMasterKey`格式的系统主公钥和签名方的ID。

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



#### Certificate

类`Certificate`实现了SM2证书的导入、导出、解析和验证等功能。这里的“SM2证书”含义和“RSA证书”类似，是指证书中的公钥字段是SM2公钥，证书中签名字段是SM2签名，证书格式就是标准的X.509v3证书。由于GmSSL库目前只支持SM2签名算法，不支持ECDSA、RSA、DSA等签名算法，因此`Certificate`类无法支持其他公钥类型的证书。注意，有一种不常见的情况，一个证书可以公钥是SM2公钥而数字签名是RSA签名，这种证书可能是采用RSA公钥的CA中心对SM2证书请求签发而产生的，由于目前GmSSL不支持SM2之外的签名算法，因此`Certificate`不支持此类证书。

类`Certificate`只支持SM2证书的解析和验证等功能，不支持SM2证书的签发和生成，如果应用需要实现证书申请（即生成CSR文件）或者自建CA签发证书功能，那么可以通过GmSSL库或者`gmssl`命令行工具实现，GmSSL-Java目前不考虑支持证书签发、生成的相关功能。

```java
public class Certificate {
	public Certificate();
	public byte[] getBytes();
	public void importPem(String file);
	public void exportPem(String file);
	public byte[] getSerialNumber();
	public String[] getIssuer();
	public String[] getSubject();
	public java.util.Date getNotBefore();
	public java.util.Date getNotAfter();
	public Sm2Key getSubjectPublicKey();
	public boolean verifyByCaCertificate(Certificate caCert, String sm2Id);
}
```

新生成的`Certificate`对象中的证书数据为空，必须通过导入证书数据才能实现真正的初始化。证书有很多种不同格式的编码，如二进制DER编码的`crt`文件或者文本PEM编码的`cer`文件或者`pem`文件，有的证书也会把二进制的证书数据编码为一串连续的十六进制字符串，也有的CA会把多个证书构成的证书链封装在一个PKCS#7格式的密码消息中，而这个密码消息可能是二进制的，也可能是PEM编码的。

在这些格式中最常用的格式是本文的PEM格式，这也是`Certificate`类默认支持的证书格式。下面这个例子中就是一个证书的PEM文件内容，可以看到内容是由文本构成的，并且总是以`-----BEGIN CERTIFICATE-----`一行作为开头，以`-----END CERTIFICATE-----`一行作为结尾。PEM格式的好处是很容易用文本编辑器打开来，容易作为文本被复制、传输，一个文本文件中可以依次写入多个证书，从而在一个文件中包含多个证书或证书链。因此PEM格式也是CA签发生成证书使用的最主流的格式。由于PEM文件中头尾之间的文本就是证书二进制DER数据的BASE64编码，因此PEM文件也很容易和二进制证书进行手动或自动的互相转换。

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

