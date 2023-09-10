# GmSSL-Java

## 简介

本项目是GmSSL密码库的Java语言封装，可以用于Java环境和Android系统上的应用开发。GmSSL-Java目前提供了随机数生成器、SM3哈希、SM3消息认证码(HMAC-SM3)、SM4加密（包括分组加密和CBC/CTR/GCM加密模式）、ZUC加密、SM2加密/签名、SM9加密/签名、SM2证书解析等功能，可以覆盖目前国密算法主要应用开发场景。

GmSSL-Java是采用JNI (Java Native Interface)方式实现的，也就是说所有底层密码功能（以及消息、文件的编解码等）均为调用GmSSL库实现，因此在功能、标准、性能上和GmSSL的C库、命令行工具几乎完全一致。GmSSL-Java将各种算法封装为独立的Java类，方便应用调用。包含的具体类及功能参见接口说明一节。

因为GmSSL-Java以JNI方式实现，GmSSL-Java不仅包含Java语言实现的Java类库（Jar包），还包括C语言实现的本地库（libgmssljni动态库），其中libgmssljni这个本地库是Java接口类库和GmSSL库(libgmssl)之间的胶水层，应用部署时还需要保证系统中已经安全了GmSSL库。虽然看起来这种实现方式比纯Java实现的类似更麻烦，而且因为包含C编译的本地代码，这个类库也失去了Java代码一次编译到处运行的跨平台能力，但是这是密码库的主流实现方式。相对于纯Java实现来说，GmSSL-Java可以充分利用成熟和功能丰富的GmSSL库，在性能、标准兼容性上都更有优势，并且可以随着GmSSL主项目的升级获得功能和性能上的升级。

## 下载

* GmSSL-Java主分支源代码 [GmSSL-Java-main.zip](https://github.com/GmSSL/GmSSL-Java/archive/refs/heads/main.zip) (版本号：2.1.0 dev)
* 依赖的GmSSL库主分支源代码 [GmSSL-master.zip](https://github.com/guanzhi/GmSSL/archive/refs/heads/master.zip) (版本号：3.1.1 Dev)]
* GitHub主页：https://github.com/GmSSL/GmSSL-Java

## 项目构成

GmSSL的项目组成主要包括C语言的本地代码、`src`目录下的Java类库代码、`examples`目录下面的例子代码。其中只有本地代码和`src`下面的Java类库代码会参与默认的编译，生成动态库和Jar包，而`examples`下的例子默认不编译也不进入Jar包。

GmSSL-Java提供一个包`org.gmssl`，其中包含如下密码算法类

* org.gmssl.Random
* org.gmssl.Sm3
* org.gmssl.Sm3Hmac
* org.gmssl.Sm3Pbkdf2
* org.gmssl.Sm4
* org.gmssl.Sm4Gcm
* org.gmssl.Sm4Cbc
* org.gmssl.Sm4Ctr
* org.gmssl.Zuc
* org.gmssl.Sm2Key
* org.gmssl.Sm2Signature
* org.gmssl.Sm2Certificate
* org.gmssl.Sm9EncMasterKey
* org.gmssl.Sm9EncKey
* org.gmssl.Sm9SignMasterKey
* org.gmssl.Sm9SignKey
* org.gmssl.Sm9Signature
* org.gmssl.GmSSLException

其中还有一个特殊的`org.gmssl.GmSSLJNI`类，这是底层的JNI封装，不建议用户调用。

## 开发者

<a href="https://github.com/GmSSL/GmSSL-Java/graphs/contributors">
	<img src="https://contrib.rocks/image?repo=GmSSL/GmSSL-Java" />
</a>


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


## 开发手册

### 随机数生成器

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

### SM3哈希

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

### HMAC-SM3消息认证码

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

### 基于口令的密钥导出函数 PBKDF2

常用软件如Word、PDF、WinRAR等支持基于口令的文件加密，字符串形式的口令相对于随机的密钥字节序列对用户来说更容易记忆和输入，对用户更加友好。但是由于口令中存在的信息熵远低于随机的二进制密钥，直接将口令字符串作为密钥，甚至无法抵御来自个人计算机的暴力破解攻击。一种典型的错误用法是直接用哈希函数计算口令的哈希值，将看起来随机的哈希值作为密钥使用。但是由于口令的空间相对较小，攻击者仍然可以尝试所有可能口令的哈希值，对于暴力破解来说，破解口令的哈希值和原始口令，在攻击难度上没有太大差别。

安全和规范的做法是采用一个基于口令的密钥导出函数(Password-Based Key Derivation Function, PBKDF)从口令中导出密钥。通过PBKDF导出密钥并不会降低攻击者在暴力破解时尝试的口令数量，但是可以防止攻击者通过查预计算表的方式来加速破解，并且可以大大增加攻击者尝试每一个可能口令的计算时间。PBKDF2是安全的并且使用广泛的PBKDF算法标准之一，算法采用哈希函数作为将口令映射为密钥的主要部件，通过加入随机并且公开的盐值(Salt)来抵御预计算，通过增加多轮的循环计算来增加在线破解的难度，并且支持可变的导出密钥长度。

类`Sm3Pbkdf2`实现了基于SM3的PBKDF2算法。

```java
public class Sm3Pbkdf2 {

	public final static int MAX_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_SALT_SIZE;
	public final static int DEFAULT_SALT_SIZE = GmSSLJNI.SM3_PBKDF2_DEFAULT_SALT_SIZE;
	public final static int MIN_ITER = GmSSLJNI.SM3_PBKDF2_MIN_ITER;
	public final static int MAX_ITER = GmSSLJNI.SM3_PBKDF2_MAX_ITER;
	public final static int MAX_KEY_SIZE = GmSSLJNI.SM3_PBKDF2_MAX_KEY_SIZE;

	public Sm3Pbkdf2();
	public byte[] deriveKey(String pass, byte[] salt, int iter, int keylen);
}
```

其中核心的密钥导出功能是通过`deriveKey`方法实现的。

* `pass`用于导出密钥的用户口令。
* `salt`是用于抵御与计算的盐值。这个值需要用随机生成（比如通过`Random`类），并且具有一定的长度。Salt值不需要保密，因此在口令加密数据时，可以直接将这个值附在密文前，传输给接收方。Salt值越长，抵御预计算攻击的效果就更好。例如当Salt为8字节（64比特）长的随机值时，攻击者预计算表就要扩大$2^{64}$倍。`Sm3Pbkdf2`提供一个推荐的Salt值长度`DEFAULT_SALT_SIZE`常量，并且在实现上不支持超过`MAX_SALT_SIZE`长度的Salt值。
* `iter`参数用于表示在导出密钥时调用SM3算法的循环次数，`iter`值越大，暴力破解的难度越大，但是同时用户在调用这个函数时的开销也增大了。一般来说`iter`值的应该选择在用户可接收延迟情况下的最大值，比如当`iter = 10000`时，用户延迟为100毫秒，但是对于用户来说延迟感受不明显，但是对于暴力攻击者来说`iter = 10000`意味着攻击的开销增加了大约1万倍。`Sm3Pbkdf2`通过`MIN_ITER`和`MAX_ITER`两个常量给出了`iter`值的范围，用户可以根据当前计算机的性能及用户对延迟的可感知度，在这个范围内选择合适的值。
* `keylen`参数表示希望导出的密钥长度，这个长度不可超过常量`MAX_KEY_SIZE`。

下面的例子展示了如何从口令字符串导出一个密钥。

```java
import org.gmssl.Sm3Pbkdf2;
import org.gmssl.Random;
import org.gmssl.Sm4;

public class Sm3Pbkdf2Example {

	public static void main(String[] args) {

		Sm3Pbkdf2 kdf = new Sm3Pbkdf2();

		Random rng = new Random();
		byte[] salt = rng.randBytes(Sm3Pbkdf2.DEFAULT_SALT_SIZE);

		String pass = "P@ssw0rd";
		byte[] key = kdf.deriveKey(pass, salt, Sm3Pbkdf2.MIN_ITER * 2, Sm4.KEY_SIZE);
	}
}
```


### SM4分组密码

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

多次调用`Sm4`的分组加密解密功能可以实现ECB模式，由于ECB模式在消息加密应用场景中并不安全，因此GmSSL中没有提供ECB模式。如果应用需要开发SM4的其他加密模式，也可可以基于`Sm4`类来开发这些模式。



### SM4-CBC加密模式

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

### SM4-CTR加密模式

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

### SM4-GCM认证加密模式

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

通过上面的例子可以看出，SM4-GCM加密模式中可以通过`init`指定了一个不需要加密的字段`aad`，注意`aad`是不会在`update`中输出的。由于GCM模式输出个外的完整性标签，因此`update`和`doFinal`输出的总密文长度会比总的输入明文长度多`taglen`个字节。



### Zuc序列密码

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，密钥和IV长度均为16字节。作为序列密码ZUC可以加密可变长度的输入数据，并且输出的密文数据长度和输入数据等长，因此适合不允许密文膨胀的应用场景。在国密算法体系中，ZUC算法的设计晚于SM4，在32位通用处理器上通常比SM4-CBC明显要快。

在安全性方面，不建议在一组密钥和IV的情况下用ZUC算法加密大量的数据（比如GB级或TB级），避免序列密码超长输出时安全性降低。另外ZUC算法本身并不支持数据的完整性保护，因此在采用ZUC算法加密应用数据时，应考虑配合HMAC-SM3提供完整性保护。ZUC的标准中还包括针对移动通信底层数据报文加密的128-EEA3方案和用于消息完整性保护的128-EIA3算法，目前GmSSL-Java中不支持这两个算法。

`Zuc`类实现了ZUC加密、解密功能。

```java
public class Zuc {
	public final static int KEY_SIZE = 16;
	public final static int IV_SIZE = 16;
	public final static int BLOCK_SIZE = 4;

	public Zuc();
	public void init(byte[] key, byte[] iv);
	public int update(byte[] in, int inOffset, int inlen, byte[] out, int outOffset);
	public int doFinal(byte[] out, int outOffset);
}
```

`Zuc`类的接口说明如下：

* 序列密码通过生成密钥序列和输入数据进行异或操作的方式来加密或解密，因此序列密码的加密和解密的过程一致，因此`Zuc`的`init`方法中不需要格外的参数表明加密还是解密。
* 由于CTR模式实际上是以分组密码实现了序列密码的能力，因此可以发现`Zuc`和`Sm4Cbc`的接口是完全一致的。
* ZUC算法内部实现是以32比特字（4字节）为单位进行处理，因此`Zuc`实现加解密过程中也有内部的状态缓冲区，因此`update`的输出长度可能和输入长度不一致，调用方应该保证输出缓冲区长度比输入长度长`BLOCK_SIZE`个字节。注意，`BLOCK_SIZE`的实际值在未来也有可能会变化。

下面的例子展示了`Zuc`的加密和解密过程。

```java
import org.gmssl.Zuc;
import org.gmssl.Random;

public class ZucExample {

	public static void main(String[] args) {

		Random rng = new Random();
		byte[] key = rng.randBytes(Zuc.KEY_SIZE);
		byte[] iv = rng.randBytes(Zuc.IV_SIZE);
		byte[] ciphertext = new byte[32];
		byte[] plaintext = new byte[32];
		int cipherlen;
		int plainlen;

		Zuc zuc = new Zuc();

		zuc.init(key, iv);
		cipherlen = zuc.update("abc".getBytes(), 0, 3, ciphertext, 0);
		cipherlen += zuc.doFinal(ciphertext, cipherlen);

		zuc.init(key, iv);
		plainlen = zuc.update(ciphertext, 0, cipherlen, plaintext, 0);
		plainlen += zuc.doFinal(plaintext, plainlen);
	}
}
```



### SM2

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

下面的代码片段展示了`Sm2Key`密钥对和公钥的DER导入导出。

```java
Sm2Key sm2_key = new Sm2Key();
sm2_key.generateKey();

byte[] privateKeyInfo = sm2_key.exportPrivateKeyInfoDer();
byte[] publicKeyInfo = sm2_key.exportPublicKeyInfoDer();

Sm2Key priKey = new Sm2Key();
priKey.importPrivateKeyInfoDer(privateKeyInfo);

Sm2Key pubKey = new Sm2Key();
pubKey.importPublicKeyInfoDer(publicKeyInfo);
```

下面的代码片段展示了`Sm2Key`导出为加密的PEM私钥文件

```java
priKey.exportEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
priKey.importEncryptedPrivateKeyInfoPem("Password", "sm2.pem");

```

用文本编辑器打开`sm2.pem`文件可以看到如下内容

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBBjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQxShg35gP7+BVnsLo
NzYroAIDAQAAAgEQMAsGCSqBHM9VAYMRAjAcBggqgRzPVQFoAgQQrZf0pC2mC52m
cEaC9goJUQSBoGENSQLgigHQUFF7qAOnJQP6erD1vTBQYWWD1aiXGFpLvhPunZ3m
oWOagyqiGmsoV9aSTWMp20ZLiDR+s7pRv8NM0+vspmDUvmb+LUh0zjrrtJqkzr+Q
kdfrXD9Utsqx+PqrzBw/PRMDIRKrJeUtqtkerCnsSUN3CpnpAMSTnQUrTt1mQXyU
dDj7NnOwCbab9km8fzbaXfJlWZYZPsyFJqw=
-----END ENCRYPTED PRIVATE KEY-----
```

下面的代码片段展示了`Sm2Key`导出为PEM公钥文件，这是一个标准的PKCS #8 EncryptPrivateKeyInfo类型并且PEM编码的私钥文件格式，`openssl pkeyutil`命令行工具也默认采用这个格式的私钥，但是由于GmSSL在私钥文件中采用SM4-CBC、HMAC-SM3组合加密了SM2的私钥，因此对于默认使用3DES的`openssl`等工具可能无法解密这个私钥（即使这个工具包含SM2算法的实现）。

```java
pubKey.exportPublicKeyInfoPem("sm2pub.pem");
pubKey.importPublicKeyInfoPem("sm2pub.pem");
```

用文本编辑器打开`sm2pub.pem`文件可以看到如下内容

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQ05FKjcbwu2LwLHp2bvacYUBUopR
h143PrNMFNT0lIN5j+5G+sJcgi5UrzmGEZ3mhXtYBTiWhkYaATXLRqygeg==
-----END PUBLIC KEY-----
```

由于公钥文件是不加密的，因此这个公钥可以被支持SM2的第三方工具、库打开和访问。

`Sm2Key`类除了`generateKey`方法之外，提供了`computeZ`、`sign`、`verify`、`encrypt`、`decrypt`这几个密码计算相关的方法。

其中`computeZ`是由公钥和用户的字符串ID值计算出一个称为“Z值”的哈希值，用于对消息的签名。由于`Sm2Signature`类中提供了SM2消息签名的完整功能，因此这个`computeZ`方法只是用于实验验证。由于这个计算只需要公钥，因此如果密钥值是通过`importPublicKeyInfoDer`等导入的，也可以成功计算出32字节的哈希值结果。

```java
byte[] z = pubKey.computeZ(Sm2Key.DEFAULT_ID);
```

类`Sm2Key`的`sign`和`verify`方法实现了SM2签名的底层功能，这两个方法不支持对数据或消息的签名，只能实现对SM3哈希值的签名和验证，并没有实现SM2签名的完整功能。应用需要保证调用时提供的`dgst`参数的字节序列长度为32。只有密码协议的底层开发者才需要调用`computeZ`、`sign`、`verify`这几个底层方法。

```java
Random rng = new Random();
byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);

byte[] sig = priKey.sign(dgst);

boolean verify_ret = pubKey.verify(dgst, sig);
System.out.println("Verify result = " + verify_ret);
```

类`Sm2Key`的`encrypt`和`decrypt`方法实现了SM2加密和解密功能。注意，虽然SM2标准中没有限制加密消息的长度，但是公钥加密应该主要用于加密较短的对称密钥、主密钥等密钥数据，因此GmSSL库中限制了SM2加密消息的最大长度。应用在调用`encrypt`时，需要保证输入的明文长度不超过`MAX_PLAINTEXT_SIZE`的限制。如果需要加密引用层的消息，应该首先生成对称密钥，用SM4-GCM加密消息，再用SM2加密对称密钥。

```java
byte[] ciphertext = pubKey.encrypt("abc".getBytes());

byte[] plaintext = priKey.decrypt(ciphertext);

System.out.printf("Plaintext : ");
for (i = 0; i < plaintext.length; i++) {
	System.out.printf("%02x", plaintext[i]);
}
System.out.print("\n");
```

类`Sm2Signatue`提供了对任意长消息的签名、验签功能。

```java
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

在生成`Sm2Signature`对象时，不仅需要提供`Sm2Key`，还需要提供签名方的字符串ID，以满足SM2签名的标准。如果提供的`Sm2Key`来自于导入的公钥，那么这个`Sm2Signature`对象只能进行签名验证操作，即在构造时`do_sign = false`，并且只能调用`verify`方法，不能调用`sign`方法。

```java
Sm2Signature sign = new Sm2Signature(priKey, Sm2Key.DEFAULT_ID, true);
sign.update("abc".getBytes());
sig = sign.sign();

Sm2Signature verify = new Sm2Signature(pubKey, Sm2Key.DEFAULT_ID, false);
verify.update("abc".getBytes());
verify_ret = verify.verify(sig);
System.out.println("Verify result = " + verify_ret);
```

不管是`Sm2Key`的`sign`还是`Sm2Signature`的`sign`方法输出的都是DER编码的签名值。这个签名值的第一个字节总是`0x30`，并且长度是可变的，常见的长度包括70字节、71字节、72字节，也可能短于70字节。一些SM2的实现不能输出DER编码的签名，只能输出固定64字节长度的签名值。可以通过签名值的长度以及首字节的值来判断SM2签名值的格式。

### SM2数字证书

类`Sm2Certificate`实现了SM2证书的导入、导出、解析和验证等功能。这里的“SM2证书”含义和“RSA证书”类似，是指证书中的公钥字段是SM2公钥，证书中签名字段是SM2签名，证书格式就是标准的X.509v3证书。由于GmSSL库目前只支持SM2签名算法，不支持ECDSA、RSA、DSA等签名算法，因此`Sm2Certificate`类无法支持其他公钥类型的证书。注意，有一种不常见的情况，一个证书可以公钥是SM2公钥而数字签名是RSA签名，这种证书可能是采用RSA公钥的CA中心对SM2证书请求签发而产生的，由于目前GmSSL不支持SM2之外的签名算法，因此`Sm2Certificate`不支持此类证书。

类`Sm2Certificate`只支持SM2证书的解析和验证等功能，不支持SM2证书的签发和生成，如果应用需要实现证书申请（即生成CSR文件）或者自建CA签发证书功能，那么可以通过GmSSL库或者`gmssl`命令行工具实现，GmSSL-Java目前不考虑支持证书签发、生成的相关功能。

```java
public class Sm2Certificate {
	public Sm2Certificate();
	public byte[] getBytes();
	public void importPem(String file);
	public void exportPem(String file);
	public byte[] getSerialNumber();
	public String[] getIssuer();
	public String[] getSubject();
	public java.util.Date getNotBefore();
	public java.util.Date getNotAfter();
	public Sm2Key getSubjectPublicKey();
	public boolean verifyByCaCertificate(Sm2Certificate caCert, String sm2Id);
}
```

新生成的`Sm2Certificate`对象中的证书数据为空，必须通过导入证书数据才能实现真正的初始化。证书有很多种不同格式的编码，如二进制DER编码的`crt`文件或者文本PEM编码的`cer`文件或者`pem`文件，有的证书也会把二进制的证书数据编码为一串连续的十六进制字符串，也有的CA会把多个证书构成的证书链封装在一个PKCS#7格式的密码消息中，而这个密码消息可能是二进制的，也可能是PEM编码的。

在这些格式中最常用的格式是本文的PEM格式，这也是`Sm2Certificate`类默认支持的证书格式。下面这个例子中就是一个证书的PEM文件内容，可以看到内容是由文本构成的，并且总是以`-----BEGIN CERTIFICATE-----`一行作为开头，以`-----END CERTIFICATE-----`一行作为结尾。PEM格式的好处是很容易用文本编辑器打开来，容易作为文本被复制、传输，一个文本文件中可以依次写入多个证书，从而在一个文件中包含多个证书或证书链。因此PEM格式也是CA签发生成证书使用的最主流的格式。由于PEM文件中头尾之间的文本就是证书二进制DER数据的BASE64编码，因此PEM文件也很容易和二进制证书进行手动或自动的互相转换。

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

通过`gmssl certparse`命令可以打印这个证书的内容

```bash
$ gmssl certparse -in ROOTCA.pem
Certificate
    tbsCertificate
        version: v3 (2)
        serialNumber: 69E2FEC0170AC67B
        signature
            algorithm: sm2sign-with-sm3
            parameters: NULL
        issuer
            countryName: CN
            organizationName: NRCAC
            commonName: ROOTCA
        validity
            notBefore: Sat Jul 14 11:11:59 2012
            notAfter: Mon Jul  7 11:11:59 2042
        subject
            countryName: CN
            organizationName: NRCAC
            commonName: ROOTCA
        subjectPulbicKeyInfo
            algorithm
                algorithm: ecPublicKey
                namedCurve: sm2p256v1
            subjectPublicKey
                ECPoint: 0430F09C6BAA6681C721B137F652705E2FDAEDA789F0FA2B64D4ACEB99B9EAA34E655309309562BEE0E22BB45740AA745357B43DBF586D92FE364EC22EB73775DB
        extensions
            Extension
                extnID: AuthorityKeyIdentifier (2.5.29.35)
                AuthorityKeyIdentifier
                    keyIdentifier: 4C32B197D9331BC4A605C1C6E58B625BF0977658
            Extension
                extnID: BasicConstraints (2.5.29.19)
                BasicConstraints
                    cA: true
            Extension
                extnID: KeyUsage (2.5.29.15)
                KeyUsage: keyCertSign,cRLSign
            Extension
                extnID: SubjectKeyIdentifier (2.5.29.14)
                SubjectKeyIdentifier: 4C32B197D9331BC4A605C1C6E58B625BF0977658
    signatureAlgorithm
        algorithm: sm2sign-with-sm3
        parameters: NULL
    signatureValue: 304502201B56D22DE397A77A01F07EDBE775BE08A38F9763E49E6584ABF94C86D9F6E479022100DA1C3816C5616D9C2AC18C7D7AFD6DC4CE7EFF53F563A39C48A43A22561B0BC2
```

可以看到一个证书的主要内容是包含证书持有者信息的tbsCertificate字段，以及权威机构对tbsCertificate字段的签名算法signatureAlgorithm和签名值signatureValue。因为这个证书是SM2证书，因此其中的签名算法是`sm2sign-with-sm3`，签名值是`0x30`开头的DER编码的可变长度签名值。

证书中持有者信息包含如下字段：

* 证书格式的版本号 version，目前版本号应该是第3版，即`v3`。
* 证书的序列号 serialNumber，早期证书中的序列号是一个递增的整数，但是近年来的证书必须是随机值。、
* 证书的签名算法 signature，这个字段的值必须和最后的signatureAlgorithm保持一致。
* 证书签发机构的名字 issuer，通常是一个CA中心，issuer的内容是由多个Key-Value格式的多个字段组合而成，其中的Key包括国家countryName、省stateOrProvinceName、城市localityName、组织organizationName、组织内单位organizationUnitName、常用名commonName等，其中commonName应该是CA机构的名字。
* 证书的有效期 validity，有效期是由起始时间notBefore和终止时间notAfter两个时间构成的，如果当前时间早于notBefore，说明证书还没有启用，如果当前时间晚于notAfter，说明证书已经过期作废。
* 证书持有者（证书主体）的名字 subject，这个字段的数据类型和issuer是一样的，一般对于网站服务器证书来说，subject的commonName应该是服务器的域名。
* 证书持有者的公钥信息subjectPulbicKeyInfo，对于SM2证书来说，公钥算法必须是ecPublicKey并且曲线必须是sm2p256v1，公钥的值是一个编码的椭圆曲线点，这个值总是以`0x04`开头，后跟总共64字节的点的X、Y坐标。
* 证书中通常还有多个扩展，其中有的扩展是关键的(critical)扩展，有些则不重要，只是提供了参考信息，这里介绍两个比较重要的扩展：
  * BasicConstraints (2.5.29.19) 扩展，这个扩展标明证书是权威机构的CA证书（比如北京市CA中心）还是普通用户的证书（比如某个网站的证书），如果一个证书中没有包含这个扩展，或者扩展中的`cA: true`字段不存在，那么这个证书不能作为CA证书使用。
  * KeyUsage (2.5.29.15) 扩展，这个扩展表明证书持有者公钥的用途，类似于驾驶证中的A照、B照、C照等划分大客车、大货车、小客车准驾车型，密钥用途表明证书是否可以签名、加密、签发证书等用途。如果一个数字签名附带的证书中有KeyUsage扩展并且扩展包含的密钥用途只有加密，没有签名，那么这个证书对于这个签名来说就是无效的。

`Sm2Certificate`类只支持第3版证书的解析，因此没有提供`getVersion`方法获取证书的版本号。GmSSL支持常用扩展的解析和验证，如果某个证书中有GmSSL不支持的非关键扩展，那么GmSSL会忽略这个扩展，如果存在GmSSL不识别或无法验证的关键性扩展，那么GmSSL在解析证书的时候会返回失败，因此如果`Sm2Certificate`类`importPem`成功，说明证书的格式、内容是可以识别的并且是正确的。

拿他其他人提供的证书还必须验证该证书是否有效，首先需要检查证书的有效期。目前很多CA中心的策略是颁发有效期尽可能短的证书（比如3个月有效期），因此拿到的证书很有可能已经过期了。可以通过`getNotBefore`和`getNotAfter`方法获得有效期时间，判断当前时间点是否在有效期范围内。如果要验证过去某个时间点证书支持者的操作是否合法，那么应该检查那个时间点是否在证书的有效期范围内。

对证书最重要的验证之一是这个证书是否是由权威机构签发的。证书用户需要先通过`getIssuer`方法获得签发机构的名字，确认这个签发机构是否可信。例如，如果一个北京市政府机构的证书中的签发机构是一个商业性CA中心，那么这个证书的有效性就是存疑的。在确认CA中心名字（即整个issuer字段）无误之后，还需要通过Issuer字段从可信的渠道获得这个CA中心的证书，然后调用`verifyByCaCertificate`方法，用获得的CA证书验证当前证书中的签名是否正确。在典型的应用中，开发者和软件发行方应该将所有可信的CA中心的证书硬编码到软件中，或者内置到软件或系统的证书库中，避免应用的用户需要手动添加、导入CA证书。

所有的私钥都有泄露的可能，安全性不佳的自建CA有被攻击者渗透的可能，商业性的小CA甚至有被收购、收买的可能，因此有效期范围内的证书也存在被作废的可能。检查证书是否作废主要是通过证书作废列表CRL文件检查，或者通过证书状态在线检查协议OCSP来在线查询。目前`Sm2Certificate`类没有支持证书作为查询的功能，开发者暂时可以通过`GmSSL`库或者`gmssl`命令行工具进行CRL的检查。

在完成所有证书检查之后，应用可以完全信任从证书中读取的持有者身份信息(subject)和支持有的公钥了，这两个信息分别通过`getSubject`和`getSubjectPublicKey`方法获得。



### SM9 基于身份的密码

SM9算法属于基于身份的密码。基于身份的密码是一种“高级”的公钥密码方案，在具备常规公钥密码加密、签名等密码功能的同时，基于身份的密码体系不需要CA中心和数字证书体系。SM9方案的基本原理是，可以由用户的唯一身份ID（如对方的电子邮件地址、域名或ID号等），从系统的全局主密钥中导出对应的私钥或公钥，导出密钥的正确性是由算法保证的，因此在进行加密、验签的时候，只需要获得解密方或签名方的ID即可，不再需要对方的数字证书了。因此如果应用面对的是一个内部的封闭环境，所有参与用户都是系统内用户，那么采用SM9方案而不是SM2证书和CA的方案，可以简化系统的开发、设计和使用，并降低后续CA体系的维护成本。

对应数字证书体系中的CA中心，SM9体系中也存在一个权威中心，用于生成全局的主密钥(MasterKey)，并且为系统中的每个用户生成、分配用户的私钥。和SM2密钥对一样，SM9的主密钥也包含私钥和公钥，其中主公钥(PublicMasterKey)是可以导出并公开给系统中全体用户的。而SM9中用户的密钥对比较特殊，其中的公钥并不能从私钥中导出，SM9用户密钥需要包含用户的ID起到公钥的作用，在加密和验证签名等密码计算中，真正的用户公钥是在计算中，在运行时通过用户ID从主公钥中导出的。因此从应用的角度看，SM9中用户的公钥就是一个字符串形式的ID。

SM9算法体系中包括SM9加密、SM9签名和SM9密钥交换协议，GmSSL-Java中实现了SM9加密和SM9签名，没有实现SM9密钥交换。其中SM9加密功能包含`Sm9EncMasterKey`类和`Sm9EncKey`类，分别实现了SM9加密主密钥和SM9加密用户密钥，SM9签名功能包含`Sm9SignMasterKey`类、`Sm9SignKey`类和`Sm9Signature`类，分别实现了SM9签名主密钥、SM9签名用户密钥和SM9签名功能。

和SM2算法中相同的密钥对既可以用于加密又可以用于签名不同，SM9中加密、签名的主密钥、用户密钥的组成是完全不同的，因此GmSSL中分别实现为不同的类。SM9签名由于需要特殊的哈希过程，因此SM9用户签名私钥不提供直接签哈希值的底层签名功能实现，只能通过`Sm9Signature`实现对消息的签名、验证。

SM9加密主密钥由类`Sm9EncMasterKey`实现。

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

`Sm9EncMasterKey`的接口包括：

* 主密钥的生成`generateMasterKey`
* 主密钥的导入`importEncryptedMasterKeyInfoPem`和导出`exportEncryptedMasterKeyInfoPem`，注意`Sm2Key`的对应接口类似，这里主密钥都是以口令加密的方式导出到文件上的
* 主公钥（主密钥的公钥部分）的导入`importPublicMasterKeyPem`和导出`exportPublicMasterKeyPem`
* 用户私钥的生成`extractKey`
* 数据加密`encrypt`

这个类的用户包括两个不同角色，权威中心和用户。其中权威中心调用主密钥的生成、主密钥的导入导出、主公钥导出和用户私钥生成这几个接口，而用户调用主公钥导入和加密这两个接口。

类`Sm9EncKey`对象是由`Sm9SEncMasterKey`的`extractKey`方法生成的。

```java
public class Sm9EncKey {
	public Sm9EncKey(String id);
	public String getId();
	public void exportEncryptedPrivateKeyInfoPem(String pass, String file);
	public void importEncryptedPrivateKeyInfoPem(String pass, String file);
	public byte[] decrypt(byte[] ciphertext);
}
```

类`Sm9EncKey`提供了解密、导入导出等接口，由于在SM9中用户密钥总是包含私钥的，因此导出的是经过口令加密的密钥。

下面的例子中给出了SM9加密方案的主密钥生成、用户密钥导出、加密、解密的整个过程。

```java
import org.gmssl.Sm9EncMasterKey;
import org.gmssl.Sm9EncKey;

public class Sm9EncExample {

	public static void main(String[] args) {

		Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
		enc_master_key.generateMasterKey();
		enc_master_key.exportPublicMasterKeyPem("sm9enc.mpk");

		Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
		enc_master_pub_key.importPublicMasterKeyPem("sm9enc.mpk");

		byte[] ciphertext = enc_master_pub_key.encrypt("abc".getBytes(), "Bob");

		Sm9EncKey enc_key = enc_master_key.extractKey("Bob");
		byte[] plaintext = enc_key.decrypt(ciphertext);
	}
}
```

SM9签名功能由`Sm9SignMasterKey`、`Sm9SignKey`和`Sm9Signature`几个类实现，前两者在接口上和SM9加密非常类似，只是这两个类不直接提供签名、验签的功能。

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

类`Sm9Signature`实现对数据的SM9签名和验证功能。SM9签名时需要提供`Sm9SignKey`类型的签名方私钥（其中包含签名者的ID），在验证签名时需要提供`Sm9SignMasterKey`格式的系统主公钥和签名方的ID。`Sm9Signature`和`Sm2Signature`提供类似的`update`、`sign`、`verify`接口，只是在验证的时候需要提供的不是公钥，而是系统的主公钥和签名方的ID。

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

下面的例子展示了SM9签名的主密钥生成、用户私钥生成、签名、验证的过程。

```java
import org.gmssl.Sm9SignMasterKey;
import org.gmssl.Sm9SignKey;
import org.gmssl.Sm9Signature;

public class Sm9SignExample {

	public static void main(String[] args) {

		Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
		sign_master_key.generateMasterKey();

		Sm9SignKey sign_key = sign_master_key.extractKey("Alice");

		Sm9Signature sign = new Sm9Signature(true);
		sign.update("abc".getBytes());
		byte[] sig = sign.sign(sign_key);

		sign_master_key.exportPublicMasterKeyPem("sm9sign.mpk");
		Sm9SignMasterKey sign_master_pub_key = new Sm9SignMasterKey();
		sign_master_pub_key.importPublicMasterKeyPem("sm9sign.mpk");

		Sm9Signature verify = new Sm9Signature(false);
		verify.update("abc".getBytes());
		boolean verify_ret = verify.verify(sig, sign_master_pub_key, "Alice");
		System.out.println("Verify result = " + verify_ret);
	}
}
```

### GmSSLException

GmSSL-Java在遇到错误和异常时，会抛出`GmSSLException`异常。

