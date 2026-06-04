# GmSSL-Java

[![Maven CI Linux](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-ubuntu.yml/badge.svg)](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-ubuntu.yml)
[![Maven CI macOS ARM64](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-macos.yml/badge.svg)](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-macos.yml)
[![Maven CI Windows](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-windows.yml/badge.svg)](https://github.com/GmSSL/GmSSL-Java/actions/workflows/maven-ci-windows.yml)

## 简介

本项目是 [GmSSL](https://github.com/guanzhi/GmSSL) 密码库的Java语言封装，可以用于Java环境和Android系统上的应用开发。GmSSL-Java目前提供了随机数生成器、SM3哈希、SM3消息认证码(HMAC-SM3)、基于SM3的PBKDF2密钥导出、SM4分组加密（支持ECB/CBC/CTR/GCM加密模式）、ZUC序列密码加密、SM2加密/签名、SM2数字证书解析、SM9基于身份加密/签名等功能，可以覆盖目前国密算法主要应用开发场景。

GmSSL-Java是采用JNI (Java Native Interface)方式实现的，所有底层密码功能（以及消息、文件的编解码等）均为调用GmSSL C库实现，因此在功能、标准、性能上和GmSSL的C库、命令行工具几乎完全一致。

GmSSL-Java提供**两种调用方式**：

1. **基础实现** (`org.gmssl` 包)：直接封装的Java类，API简洁直观，不依赖JCE框架，适用于所有JDK发行版。
2. **JCE实现** (`org.gmssl.crypto` 包)：基于Java Cryptography Extension (JCE) 标准框架实现，可无缝集成到Spring Security、Tomcat、WebLogic等支持JCE的Java生态组件中。注意：JCE方式需要使用 [OpenJDK](https://jdk.java.net/archive/)。

## 算法支持总览

| 算法类别 | 算法 | 基础实现类 | JCE实现 |
|---------|------|-----------|---------|
| 随机数 | 密码安全随机数 | `org.gmssl.Random` | `SecureRandom.Random` |
| 哈希 | SM3 | `org.gmssl.Sm3` | `MessageDigest.SM3` |
| 消息认证码 | HMAC-SM3 | `org.gmssl.Sm3Hmac` | `Mac.SM3` |
| 密钥导出 | SM3-PBKDF2 | `org.gmssl.Sm3Pbkdf2` | `SecretKeyFactory.SM3Pbkdf2` |
| 分组密码 | SM4 | `org.gmssl.Sm4` | — |
| 加密模式 | SM4-ECB (PKCS7) | 基于`Sm4`实现 | `Cipher.SM4/ECB/PKCS7Padding` |
| 加密模式 | SM4-CBC (PKCS5) | `org.gmssl.Sm4Cbc` | `Cipher.SM4/CBC/PKCS5Padding` |
| 加密模式 | SM4-CTR | `org.gmssl.Sm4Ctr` | `Cipher.SM4/CTR/NoPadding` |
| 认证加密 | SM4-GCM | `org.gmssl.Sm4Gcm` | `Cipher.SM4/GCM/NoPadding` |
| 序列密码 | ZUC | `org.gmssl.Zuc` | `Cipher.ZUC` |
| 公钥密码 | SM2 加密/解密 | `org.gmssl.Sm2Key` | `Cipher.SM2` |
| 数字签名 | SM2 签名/验签 | `org.gmssl.Sm2Signature` | `Signature.SM2` / `KeyPairGenerator.SM2` |
| 数字证书 | SM2 证书解析 | `org.gmssl.Sm2Certificate` | 支持 |
| 基于身份加密 | SM9 加密 | `org.gmssl.Sm9EncMasterKey` / `Sm9EncKey` | `Cipher.SM9` / `KeyPairGenerator.SM9` |
| 基于身份签名 | SM9 签名 | `org.gmssl.Sm9SignMasterKey` / `Sm9SignKey` / `Sm9Signature` | `Signature.SM9` |

## 平台支持

GmSSL-Java通过GitHub Actions在以下平台上进行持续集成构建和测试：

- **Ubuntu** (Linux x86_64)
- **macOS** (Apple Silicon ARM64, macos-14)
- **Windows** (x86_64, MSVC)

同时支持 **Android** 平台（通过 `Dalvik/ART` 运行时检测和 `.so` 动态库加载）。

## 项目构成

```
GmSSL-Java/
├── src/main/
│   ├── c/              C语言本地JNI胶水代码 (libgmssljni)
│   ├── java/org/gmssl/
│   │   ├── *.java      基础密码类库
│   │   └── crypto/     JCE Provider实现
│   │       ├── asymmetric/   SM2/SM9 非对称算法
│   │       ├── symmetric/    SM4/ZUC 对称算法
│   │       └── digest/       SM3 摘要算法
│   └── resources/
│       └── config.properties  本地库配置
├── examples/           示例代码（不进入Jar包）
├── src/test/           单元测试
├── build/              C编译配置文件
└── pom.xml             Maven项目配置
```

## 开发者

<a href="https://github.com/GmSSL/GmSSL-Java/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=GmSSL/GmSSL-Java" />
</a>

## 下载

### 主页
- GmSSL-Java主页 [GmSSL-Java](https://github.com/GmSSL/GmSSL-Java)
- 依赖的GmSSL库主页 [GmSSL](https://github.com/guanzhi/GmSSL)

### 最新发布
- GmSSL-Java发布页 [Releases](https://github.com/GmSSL/GmSSL-Java/releases)
- 依赖的GmSSL发布页 [GmSSL Releases](https://github.com/guanzhi/GmSSL/releases)
- 当前版本 **1.0.0**

## 编译和安装

### 前置依赖：编译安装GmSSL

GmSSL-Java依赖GmSSL C库。编译前需要在系统上先编译安装GmSSL。请从 https://github.com/guanzhi/GmSSL 下载对应版本的GmSSL源码并完成编译和安装。

```shell
# 示例：从源码编译安装GmSSL
git clone https://github.com/guanzhi/GmSSL.git
cd GmSSL
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build --config Release --parallel
sudo cmake --install build --config Release
gmssl version
```

### 通过Maven编译安装GmSSL-Java

确保Java开发环境和Maven已安装，并验证环境变量：

```shell
$ java -version
$ echo $JAVA_HOME
$ mvn -v
$ gmssl version
```

**macOS额外配置**：在 `src/main/resources/config.properties` 中可设置 `macReferencedLib` 参数指定GmSSL引用库路径。也可以通过以下命令修正动态库引用路径：

```shell
install_name_tool -change /path/xxx/libgmssl.3.dylib @rpath/libgmssl.3.dylib /project/xxx/libgmssljni.dylib
```

此时 `macReferencedLib` 参数可不必配置。

执行Maven编译打包命令：

```shell
mvn clean install
```

此命令会：
1. 通过CMake编译C语言的JNI本地库 (`libgmssljni`)
2. 编译Java类库
3. 执行单元测试
4. 在 `target` 目录下生成Jar包

## 使用

### Maven依赖

以上步骤操作完成后会在本地Maven仓库生成项目相应Jar包。在其他项目中使用GmSSL-Java，只需在 `pom.xml` 中添加如下依赖：

```xml
<dependency>
    <groupId>org.gmssl</groupId>
    <artifactId>GmSSLJNI</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Native库自动加载

GmSSL-Java 1.0.0 内置了智能的 `NativeLoader` 机制，具备以下特性：

- **自动加载**：从Jar包的 `lib/` 资源目录自动提取并加载对应平台的本地动态库（`.dll` / `.so` / `.dylib`）
- **防重复加载**：通过 `loadedLibraries` 映射缓存已加载的库，避免重复 `System.load` 导致错误
- **macOS引用库处理**：自动检测并加载GmSSL依赖库 (`libgmssl.3.dylib`)，支持通过 `gmssl.root` 系统属性或 `GMSSL_ROOT` 环境变量配置路径
- **异常处理完善**：针对文件不存在、链接错误等场景提供明确的异常信息
- **外部项目兼容**：修复了从外部项目调用时的路径读取错误

### JCE Provider注册

使用JCE方式时，需要先注册GmSSL安全提供者：

```java
import java.security.Security;
import org.gmssl.crypto.GmSSLProvider;

// 注册GmSSL Provider
Security.addProvider(new GmSSLProvider());

// 之后即可通过标准JCE API调用国密算法
KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM2", "GmSSL");
Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "GmSSL");
Signature signature = Signature.getInstance("SM9", "GmSSL");
```

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

如果需要哈希的数据来自于某个字节数据的一部分（比如某个数据报文的正文部分），那么可以使用`public void update(byte[] data, int offset, int len)`这个接口，可以通过提供字节数组的偏移量、长度来表示要计算哈希的数据片段。使用这个接口可以避免复制内存的开销。

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

- `pass`用于导出密钥的用户口令。
- `salt`是用于抵御预计算的盐值。这个值需要用随机生成（比如通过`Random`类），并且具有一定的长度。Salt值不需要保密，因此在口令加密数据时，可以直接将这个值附在密文前，传输给接收方。Salt值越长，抵御预计算攻击的效果就更好。例如当Salt为8字节（64比特）长的随机值时，攻击者预计算表就要扩大$2^{64}$倍。`Sm3Pbkdf2`提供一个推荐的Salt值长度`DEFAULT_SALT_SIZE`常量，并且在实现上不支持超过`MAX_SALT_SIZE`长度的Salt值。
- `iter`参数用于表示在导出密钥时调用SM3算法的循环次数，`iter`值越大，暴力破解的难度越大，但是同时用户在调用这个函数时的开销也增大了。一般来说`iter`值的应该选择在用户可接收延迟情况下的最大值，比如当`iter = 10000`时，用户延迟为100毫秒，但是对于用户来说延迟感受不明显，但是对于暴力攻击者来说`iter = 10000`意味着攻击的开销增加了大约1万倍。`Sm3Pbkdf2`通过`MIN_ITER`和`MAX_ITER`两个常量给出了`iter`值的范围，用户可以根据当前计算机的性能及用户对延迟的可感知度，在这个范围内选择合适的值。
- `keylen`参数表示希望导出的密钥长度，这个长度不可超过常量`MAX_KEY_SIZE`。

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

下面的例子展示SM4分组加密：

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

多次调用`Sm4`的分组加密解密功能可以实现ECB模式（参见下方 SM4-ECB 章节）。由于ECB模式在消息加密应用场景中并不安全，因此GmSSL基础实现中没有提供独立的ECB模式类。如果应用需要开发SM4的其他加密模式，也可基于`Sm4`类来开发这些模式。

### SM4-ECB加密模式

ECB（电子密码本）模式是最基础的分组密码工作模式，将明文按分组大小分块后独立加密。由于相同明文块会生成相同密文块，不适合加密具有重复模式的数据，主要用于密钥加密等特定场景。

GmSSL-Java 在**JCE实现**中提供了带PKCS7填充的SM4-ECB模式：

```java
Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "GmSSL");
```

在**基础实现**中，可以通过多次调用`Sm4`类的`encrypt`方法来实现ECB模式。示例代码见 `examples/Sm4EcbExample.java`：

```java
// 加密：逐分组调用Sm4
Sm4 sm4enc = new Sm4(key, true);
for (int i = 0; i < nblocks; i++) {
    sm4enc.encrypt(plaintext, plaintextOffset, ciphertext, ciphertextOffset);
    plaintextOffset += Sm4.BLOCK_SIZE;
    ciphertextOffset += Sm4.BLOCK_SIZE;
}

// 解密：逐分组调用Sm4
Sm4 sm4dec = new Sm4(key, false);
for (int i = 0; i < nblocks; i++) {
    sm4dec.encrypt(ciphertext, ciphertextOffset, decrypted, decryptedOffset);
    ciphertextOffset += Sm4.BLOCK_SIZE;
    decryptedOffset += Sm4.BLOCK_SIZE;
}
```

注意：JCE的ECB模式使用PKCS7填充（功能等同于PKCS5Padding），基础实现的ECB方式需要自行处理数据填充和分组对齐。

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

CTR加密模式可以加密任意长度的消息，和CBC模式不同，并不需要采用填充方案，因此SM4-CTR加密输出的密文长度和输入的明文等长。对于存储或传输带宽有限的应用场景，SM4-CTR相对SM4-CBC模式，密文不会增加额外长度。

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

注意，SM4-CBC和SM4-CTR模式都不能保证消息的完整性，在使用这两个模式时，应用还需要生成一个独立的HMAC-SM3密钥，并且生成密文的MAC值。

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

通过上面的例子可以看出，SM4-GCM加密模式中可以通过`init`指定了一个不需要加密的字段`aad`，注意`aad`是不会在`update`中输出的。由于GCM模式输出额外的完整性标签，因此`update`和`doFinal`输出的总密文长度会比总的输入明文长度多`taglen`个字节。

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

- 序列密码通过生成密钥序列和输入数据进行异或操作的方式来加密或解密，因此序列密码的加密和解密的过程一致，因此`Zuc`的`init`方法中不需要额外的参数表明加密还是解密。
- 由于CTR模式实际上是以分组密码实现了序列密码的能力，因此可以发现`Zuc`和`Sm4Ctr`的接口是完全一致的。
- ZUC算法内部实现是以32比特字（4字节）为单位进行处理，因此`Zuc`实现加解密过程中也有内部的状态缓冲区，因此`update`的输出长度可能和输入长度不一致，调用方应该保证输出缓冲区长度比输入长度长`BLOCK_SIZE`个字节。注意，`BLOCK_SIZE`的实际值在未来也有可能会变化。

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

- `importPrivateKeyInfoDer` 从字节数组中导入SM2私钥，导入密钥后这个`Sm2Key`对象可以执行签名操作和解密操作，也可以执行验证签名和加密。
- `importEncryptedPrivateKeyInfoPem` 从加密的PEM文件中导入SM2私钥，调用时需要提供PEM文件的路径和解密的口令(Password)。
- `importPublicKeyInfoDer`从字节数组中导入SM2公钥，因为其中没有私钥，因此这个`Sm2Key`对象不能执行签名和解密操作，只能执行验证签名和加密操作。
- `importPublicKeyInfoPem`从PEM文件中导入SM2公钥，只需要提供文件的路径，不需要提供口令。

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

下面的代码片段展示了`Sm2Key`导出为加密的PEM私钥文件：

```java
priKey.exportEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
priKey.importEncryptedPrivateKeyInfoPem("Password", "sm2.pem");
```

用文本编辑器打开`sm2.pem`文件可以看到如下内容：

```
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBBjBhBgkqhkiG9w0BBQ0wVDA0BgkqhkiG9w0BBQwwJwQQxShg35gP7+BVnsLo
...
-----END ENCRYPTED PRIVATE KEY-----
```

下面的代码片段展示了`Sm2Key`导出为PEM公钥文件：

```java
pubKey.exportPublicKeyInfoPem("sm2pub.pem");
pubKey.importPublicKeyInfoPem("sm2pub.pem");
```

用文本编辑器打开`sm2pub.pem`文件可以看到如下内容：

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEQ05FKjcbwu2LwLHp2bvacYUBUopR
...
-----END PUBLIC KEY-----
```

由于公钥文件是不加密的，因此这个公钥可以被支持SM2的第三方工具、库打开和访问。

`Sm2Key`类除了`generateKey`方法之外，提供了`computeZ`、`sign`、`verify`、`encrypt`、`decrypt`这几个密码计算相关的方法。

其中`computeZ`是由公钥和用户的字符串ID值计算出一个称为"Z值"的哈希值，用于对消息的签名。由于`Sm2Signature`类中提供了SM2消息签名的完整功能，因此这个`computeZ`方法只是用于实验验证。

```java
byte[] z = pubKey.computeZ(Sm2Key.DEFAULT_ID);
```

类`Sm2Key`的`sign`和`verify`方法实现了SM2签名的底层功能，这两个方法不支持对数据或消息的签名，只能实现对SM3哈希值的签名和验证。应用需要保证调用时提供的`dgst`参数的字节序列长度为32。

```java
Random rng = new Random();
byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);

byte[] sig = priKey.sign(dgst);
boolean verify_ret = pubKey.verify(dgst, sig);
System.out.println("Verify result = " + verify_ret);
```

类`Sm2Key`的`encrypt`和`decrypt`方法实现了SM2加密和解密功能。注意，虽然SM2标准中没有限制加密消息的长度，但是公钥加密应该主要用于加密较短的对称密钥、主密钥等密钥数据，因此GmSSL库中限制了SM2加密消息的最大长度（`MAX_PLAINTEXT_SIZE = 255`字节）。如果需要加密应用层的消息，应该首先生成对称密钥，用SM4-GCM加密消息，再用SM2加密对称密钥。

```java
byte[] ciphertext = pubKey.encrypt("abc".getBytes());
byte[] plaintext = priKey.decrypt(ciphertext);
```

类`Sm2Signature`提供了对任意长消息的签名、验签功能。

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

类`Sm2Certificate`实现了SM2证书的导入、导出、解析和验证等功能。这里的"SM2证书"含义和"RSA证书"类似，是指证书中的公钥字段是SM2公钥，证书中签名字段是SM2签名，证书格式就是标准的X.509v3证书。由于GmSSL库目前只支持SM2签名算法，不支持ECDSA、RSA、DSA等签名算法，因此`Sm2Certificate`类无法支持其他公钥类型的证书。

类`Sm2Certificate`只支持SM2证书的解析和验证等功能，不支持SM2证书的签发和生成。如果应用需要实现证书申请（即生成CSR文件）或者自建CA签发证书功能，可以通过GmSSL库或者`gmssl`命令行工具实现。

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

新生成的`Sm2Certificate`对象中的证书数据为空，必须通过导入证书数据才能实现真正的初始化。证书最常用的格式是PEM格式，这也是`Sm2Certificate`类默认支持的证书格式。PEM文件内容总是以`-----BEGIN CERTIFICATE-----`一行作为开头，以`-----END CERTIFICATE-----`一行作为结尾。

```
-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
...
-----END CERTIFICATE-----
```

通过`gmssl certparse`命令可以打印证书内容：

```bash
$ gmssl certparse -in ROOTCA.pem
Certificate
    tbsCertificate
        version: v3 (2)
        serialNumber: 69E2FEC0170AC67B
        signature
            algorithm: sm2sign-with-sm3
        issuer
            countryName: CN
            organizationName: NRCAC
            commonName: ROOTCA
        validity
            notBefore: Sat Jul 14 11:11:59 2012
            notAfter: Mon Jul  7 11:11:59 2042
        subject
            ...
        subjectPulbicKeyInfo
            algorithm: ecPublicKey
            namedCurve: sm2p256v1
        extensions
            ...
```

证书中持有者信息包含如下字段：

- 证书格式的版本号 version
- 证书的序列号 serialNumber
- 证书的签名算法 signature
- 证书签发机构的名字 issuer（由countryName、organizationName、commonName等组成）
- 证书的有效期 validity（notBefore和notAfter）
- 证书持有者的名字 subject
- 证书持有者的公钥信息 subjectPulbicKeyInfo
- 多个扩展字段（BasicConstraints、KeyUsage等）

证书验证时需要检查有效期（`getNotBefore` / `getNotAfter`）、签发机构（`getIssuer` + `verifyByCaCertificate`），并建议通过CRL或OCSP检查证书是否被作废。在完成所有证书检查之后，应用可以从证书中读取持有者身份信息（`getSubject`）和公钥（`getSubjectPublicKey`）。

### SM9 基于身份的密码

SM9算法属于基于身份的密码。基于身份的密码是一种"高级"的公钥密码方案，在具备常规公钥密码加密、签名等密码功能的同时，基于身份的密码体系不需要CA中心和数字证书体系。SM9方案的基本原理是，可以由用户的唯一身份ID（如对方的电子邮件地址、域名或ID号等），从系统的全局主密钥中导出对应的私钥或公钥，导出密钥的正确性是由算法保证的，因此在进行加密、验签的时候，只需要获得解密方或签名方的ID即可，不再需要对方的数字证书了。因此如果应用面对的是一个内部的封闭环境，所有参与用户都是系统内用户，那么采用SM9方案而不是SM2证书和CA的方案，可以简化系统的开发、设计和使用，并降低后续CA体系的维护成本。

对应数字证书体系中的CA中心，SM9体系中也存在一个权威中心，用于生成全局的主密钥(MasterKey)，并且为系统中的每个用户生成、分配用户的私钥。SM9算法体系中包括SM9加密、SM9签名和SM9密钥交换协议，GmSSL-Java中实现了SM9加密和SM9签名，没有实现SM9密钥交换。其中SM9加密功能包含`Sm9EncMasterKey`类和`Sm9EncKey`类，分别实现了SM9加密主密钥和SM9加密用户密钥，SM9签名功能包含`Sm9SignMasterKey`类、`Sm9SignKey`类和`Sm9Signature`类，分别实现了SM9签名主密钥、SM9签名用户密钥和SM9签名功能。

和SM2算法中相同的密钥对既可以用于加密又可以用于签名不同，SM9中加密、签名的主密钥、用户密钥的组成是完全不同的，因此GmSSL中分别实现为不同的类。

SM9加密主密钥由类`Sm9EncMasterKey`实现。

```java
public class Sm9EncMasterKey {

  public final static int MAX_PLAINTEXT_SIZE;

  public Sm9EncMasterKey();
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

- 主密钥的生成`generateMasterKey`
- 主密钥的导入`importEncryptedMasterKeyInfoPem`和导出`exportEncryptedMasterKeyInfoPem`
- 主公钥（主密钥的公钥部分）的导入`importPublicMasterKeyPem`和导出`exportPublicMasterKeyPem`
- 用户私钥的生成`extractKey`
- 数据加密`encrypt`

这个类的用户包括两个不同角色，权威中心和用户。其中权威中心调用主密钥的生成、主密钥的导入导出、主公钥导出和用户私钥生成这几个接口，而用户调用主公钥导入和加密这两个接口。

类`Sm9EncKey`对象是由`Sm9EncMasterKey`的`extractKey`方法生成的。

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
