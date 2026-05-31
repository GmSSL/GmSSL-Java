package org.gmssl;

import org.gmssl.crypto.asymmetric.*;
import org.gmssl.crypto.digest.SM3Hmac;
import org.gmssl.crypto.digest.SM3Pbkdf2;
import org.gmssl.crypto.symmetric.*;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

/**
 * @author yongfeili
 * @date 2024/8/2
 * @description you must need to use openjdk!
 * https://jdk.java.net/archive/
 * https://stackoverflow.com/questions/1756801/how-to-sign-a-custom-jce-security-provider
 */
public class JceTest {

    @Before
    public void beforeTest(){
        Security.addProvider(new org.gmssl.crypto.GmSSLProvider());
    }

    @Test
    public void SM2_test() throws Exception{
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM2", "GmSSL");
        keyPairGen.initialize(256);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        byte[] pub= keyPair.getPublic().getEncoded();
        System.out.println(byteToHex(pub));
        byte[] pri= keyPair.getPrivate().getEncoded();
        // export private key
        SM2PrivateKey SM2PrivateKey= (SM2PrivateKey)keyPair.getPrivate();
        SM2PrivateKey.exportEncryptedPrivateKeyInfoPem("123456", "D:\\private.key.pem");
        System.out.println(byteToHex(pri));

        //Test "Z-value" hash
        SM2PublicKey sm2PublicKey = new SM2PublicKey(pub);
        byte[] zHash = sm2PublicKey.computeZ("Hello, GmSSL");
        System.out.println("zHash："+byteToHex(zHash));

        Cipher cipher = Cipher.getInstance("SM2", "GmSSL");
        // Test encryption
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] plaintext = "Hello, GmSSL".getBytes();
        byte[] ciphertext = cipher.doFinal(plaintext);
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // Test decryption
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);
        System.out.println("Decrypted: " + new String(decrypted));

        Signature signature = Signature.getInstance("SM2", "GmSSL");
        // Test signature
        signature.initSign(keyPair.getPrivate());
        byte[] signatureText = "Hello, GmSSL".getBytes();
        signature.update(signatureText);
        byte[] signatureByte = signature.sign();
        System.out.println("Signature:"+byteToHex(signatureByte));
        // Test signature verification
        signature.initVerify(keyPair.getPublic());
        signature.update(signatureText);
        boolean signatureResult = signature.verify(signatureByte);
        System.out.println("SignatureResult:"+signatureResult);


        Signature signatureImport = Signature.getInstance("SM2", "GmSSL");
        // import private key
        String privateKeyInfoHex="308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104207fef3e258348873c47117c15093266e9dad99e131f1778e53d362b2b70649f85a00a06082a811ccf5501822da14403420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
        byte[] privateKeyInfo = hexToByte(privateKeyInfoHex);
        signatureImport.initSign(new SM2PrivateKey(privateKeyInfo));
        signatureImport.update(signatureText);
        byte[] signatureByteImport = signatureImport.sign();
        System.out.println("Signature:"+byteToHex(signatureByteImport));
        // export public key
        String publicKeyInfoHex = "3059301306072a8648ce3d020106082a811ccf5501822d03420004f94c0abb6cd00c6f0918cb9c54162213501d5cc278f5d3fcf63886f4e1dc6322b1b110e33a25216f258c4cce5fd52ab320d3b086ee5390f7387218c92578c3ab";
        byte[] publicKeyInfo = hexToByte(publicKeyInfoHex);
        signatureImport.initVerify(new SM2PublicKey(publicKeyInfo));
        signatureImport.update(signatureText);
        boolean signatureResultImport = signatureImport.verify(signatureByteImport);
        System.out.println("SignatureResult:"+signatureResultImport);
    }

    @Test
    public void sm2_certificate_test() throws Exception{
        SM2Certificate sm2Cert = new SM2Certificate();
        //sm2Cert.importPem("D:\\cert.pem");
        //System.out.println("NotAfter:"+sm2Cert.getNotAfter());
    }

    @Test
    public void SM3_test() throws Exception{
        String text="Hello, GmSSL";
        // hash
        MessageDigest sm3Digest = MessageDigest.getInstance("SM3","GmSSL");
        sm3Digest.update("abc".getBytes());
        sm3Digest.reset();
        sm3Digest.update(text.getBytes());
        byte[] digest = sm3Digest.digest();
        System.out.println("digest:"+byteToHex(digest));

        //HMAC Message Authentication Code Algorithm Based on SM3
        Mac hmac = Mac.getInstance("SM3", "GmSSL");
        hmac.init(new SecretKeySpec(new Random().randBytes(SM3Hmac.MAC_SIZE), "SM3"));
        hmac.update(text.getBytes());
        byte[] hmacFinal = hmac.doFinal();
        System.out.println("hmac:"+byteToHex(hmacFinal));

        //Password-Based Key Derivation Function PBKDF2
        char[] password = "P@ssw0rd".toCharArray();
        byte[] salt = new Random().randBytes(SM3Pbkdf2.DEFAULT_SALT_SIZE);
        int iterations = SM3Pbkdf2.MIN_ITER * 2;
        int keyLength = SM3Pbkdf2.MAX_KEY_SIZE;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("SM3Pbkdf2");
        SecretKey key = skf.generateSecret(spec);
        byte[] keyBytes = key.getEncoded();
        System.out.println("DerivedKey: " + byteToHex(keyBytes));
    }

    @Test
    public void SM4_ECB_test() throws Exception{
        String text="Hello, GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        // encryption
        Cipher sm4Cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "GmSSL");
        SecretKeySpec sm4Key = new SecretKeySpec(secureRandom.generateSeed(SM4ECB.KEY_SIZE), "SM4");
        sm4Cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
        sm4Cipher.update(text.getBytes());
        sm4Cipher.update("cipher.".getBytes(),0, 6);
        byte[] ciphertext = sm4Cipher.doFinal();
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // decryption
        sm4Cipher.init(Cipher.DECRYPT_MODE, sm4Key);
        byte[] plaintext = sm4Cipher.doFinal(ciphertext);
        System.out.println("plaintext: " + new String(plaintext));
    }

    @Test
    public void SM4_CBC_test1() throws Exception{
        String text="Hello,GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        System.out.println("Generated Random Bytes: " + byteToHex(randomBytes));
        // encryption
        Cipher sm4cbcCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4CBC.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4CBC.IV_SIZE);
        sm4cbcCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        sm4cbcCipher.update(text.getBytes());
        sm4cbcCipher.update(text.getBytes());
        sm4cbcCipher.update(text.getBytes());
        byte[] ciphertext = sm4cbcCipher.doFinal();
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // decryption
        sm4cbcCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        sm4cbcCipher.update(ciphertext);
        byte[] plaintext2 = sm4cbcCipher.doFinal();
        String plaintextStr=new String(plaintext2);
        System.out.println("plaintext: " + plaintextStr);
    }

    @Test
    public void SM4_CBC_test2() throws Exception{
        String text="Hello,GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        System.out.println("Generated Random Bytes: " + byteToHex(randomBytes));
        // encryption
        Cipher sm4cbcCipher = Cipher.getInstance("SM4/CBC/PKCS5Padding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4CBC.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4CBC.IV_SIZE);
        sm4cbcCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        byte[] ciphertext = new byte[100];
        int cipherlen = sm4cbcCipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, 0);
        cipherlen += sm4cbcCipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += sm4cbcCipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += sm4cbcCipher.doFinal(text.getBytes(), 0, text.getBytes().length,ciphertext, cipherlen);
        byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
        System.out.println("Ciphertext: " + byteToHex(ciphertext1));
        // decryption
        byte[] plaintext = new byte[ciphertext1.length + SM4CBC.BLOCK_SIZE];
        sm4cbcCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        int plainLen = sm4cbcCipher.doFinal(ciphertext1, 0,ciphertext1.length, plaintext,0);
        byte[] plaintext1 =Arrays.copyOfRange(plaintext,0,plainLen);
        String plaintextStr=new String(plaintext1);
        System.out.println("plaintext: " + plaintextStr);
    }

    @Test
    public void SM4_CTR_test1() throws Exception{
        String text="Hello, GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher sm4Cipher = Cipher.getInstance("SM4/CTR/NoPadding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4CTR.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4CTR.IV_SIZE);
        // encryption
        sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        byte[] ciphertext = new byte[100];
        int cipherlen = sm4Cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, 0);
        cipherlen += sm4Cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += sm4Cipher.doFinal(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
        System.out.println("Ciphertext: " + byteToHex(ciphertext1));
        // decryption
        byte[] plaintext = new byte[ciphertext1.length+SM4CTR.BLOCK_SIZE];
        sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        int plainLen = sm4Cipher.doFinal(ciphertext1, 0, ciphertext1.length, plaintext, 0);
        byte[] plaintext1 = Arrays.copyOfRange(plaintext,0,plainLen);
        System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM4_CTR_test2() throws Exception{
        String text="Hello, GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher sm4Cipher = Cipher.getInstance("SM4/CTR/NoPadding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4CTR.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4CTR.IV_SIZE);
        // encryption
        sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        sm4Cipher.update(text.getBytes());
        sm4Cipher.update(text.getBytes());
        sm4Cipher.update(text.getBytes());
        byte[] ciphertext = sm4Cipher.doFinal();
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // decryption
        sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new IvParameterSpec(iv));
        sm4Cipher.update(ciphertext);
        byte[] plaintext1=sm4Cipher.doFinal();
        System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM4_GCM_test1() throws Exception {
        String text="Hello, GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher sm4Cipher = Cipher.getInstance("SM4/GCM/NoPadding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4GCM.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4GCM.DEFAULT_IV_SIZE);
        byte[] aad = "Hello: ".getBytes();
        // encryption
        sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        byte[] ciphertext = new byte[100];
        int cipherlen = sm4Cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, 0);
        cipherlen += sm4Cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += sm4Cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += sm4Cipher.doFinal(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
        System.out.println("Ciphertext: " + byteToHex(ciphertext1));
        // decryption
        byte[] plaintext = new byte[ciphertext1.length+SM4GCM.MAX_TAG_SIZE];
        sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        int plainlen =sm4Cipher.doFinal(ciphertext1, 0, ciphertext1.length, plaintext, 0);
        byte[] plaintext1 = Arrays.copyOfRange(plaintext,0,plainlen);
        System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM4_GCM_test2() throws Exception {
        String text="Hello,GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher sm4Cipher = Cipher.getInstance("SM4/GCM/NoPadding", "GmSSL");
        byte[] key = secureRandom.generateSeed(SM4GCM.KEY_SIZE);
        byte[] iv = secureRandom.generateSeed(SM4GCM.DEFAULT_IV_SIZE);
        byte[] aad = "Hello: ".getBytes();
        // encryption
        sm4Cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        sm4Cipher.updateAAD(aad);
        sm4Cipher.update(text.getBytes());
        sm4Cipher.update(text.getBytes());
        sm4Cipher.update(text.getBytes());
        byte[] ciphertext = sm4Cipher.doFinal();
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // decryption
        sm4Cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "SM4"), new GCMParameterSpec(SM4GCM.MAX_TAG_SIZE,iv));
        sm4Cipher.updateAAD(aad);
        sm4Cipher.updateAAD(aad);
        sm4Cipher.update(ciphertext);
        byte[] plaintext1=sm4Cipher.doFinal();
        System.out.println("plaintext: " + new String(plaintext1));
    }

    @Test
    public void SM9_cipher_test() throws Exception{
        String text="Hello, GmSSL";
        SM9EncMasterKeyGenParameterSpec sm9EncMasterKeyGenParameterSpec = new SM9EncMasterKeyGenParameterSpec("bob");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM9", "GmSSL");
        keyPairGen.initialize(sm9EncMasterKeyGenParameterSpec);
        keyPairGen.generateKeyPair();
        // encryption
        PublicKey publicKey = keyPairGen.genKeyPair().getPublic();
        // export public key
        SM9PublicKey SM9PublicKey = (SM9PublicKey)publicKey;
        SM9PublicKey.exportPublicKeyPem("SM9Public.enc.mpk");
        Cipher sm9Cipher = Cipher.getInstance("SM9", "GmSSL");
        sm9Cipher.init(Cipher.ENCRYPT_MODE, publicKey,sm9EncMasterKeyGenParameterSpec);
        byte[] ciphertext = sm9Cipher.doFinal(text.getBytes());
        System.out.println("Ciphertext: " + byteToHex(ciphertext));
        // decryption
        SM9PrivateKey privateKey= (SM9PrivateKey) keyPairGen.genKeyPair().getPrivate();
        // export private key
        privateKey.exportEncryptedPrivateKeyInfoPem("123456", "SM9Private.enc.mpk");
        SM9MasterKey masterKey = (SM9MasterKey)privateKey.getSecretKey();
        SM9UserKey userKey= masterKey.extractKey(sm9EncMasterKeyGenParameterSpec.getId());
        sm9Cipher.init(Cipher.DECRYPT_MODE, userKey.getPrivateKey());
        byte[] plaintext = sm9Cipher.doFinal(ciphertext);
        System.out.println("plaintext: " + new String(plaintext));
    }

    @Test
    public void SM9_sign_test() throws Exception{
        String text="Hello, GmSSL";
        SM9SignMasterKeyGenParameterSpec sm9SignMasterKeyGenParameterSpec = new SM9SignMasterKeyGenParameterSpec("alice");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("SM9", "GmSSL");
        keyPairGen.initialize(sm9SignMasterKeyGenParameterSpec);
        keyPairGen.generateKeyPair();

        Signature signature = Signature.getInstance("SM9", "GmSSL");
        //  Signature
        SM9PrivateKey privateKey= (SM9PrivateKey) keyPairGen.genKeyPair().getPrivate();
        // export private key
        privateKey.exportEncryptedPrivateKeyInfoPem("123456", "SM9Private.sign.mpk");
        SM9MasterKey masterKey = (SM9MasterKey)privateKey.getSecretKey();
        SM9UserKey userKey= masterKey.extractKey(sm9SignMasterKeyGenParameterSpec.getId());
        signature.initSign(userKey.getPrivateKey());
        byte[] signatureText = text.getBytes();
        signature.update(signatureText);
        byte[] signatureByte = signature.sign();
        System.out.println("Signature:"+byteToHex(signatureByte));
        // Verify
        signature.setParameter(sm9SignMasterKeyGenParameterSpec);
        PublicKey publicKey=  keyPairGen.genKeyPair().getPublic();
        // export public key
        SM9PublicKey SM9PublicKey = (SM9PublicKey)publicKey;
        SM9PublicKey.exportPublicKeyPem("SM9Public.sign.mpk");
        signature.initVerify(publicKey);
        signature.update(signatureText);
        boolean signatureResult = signature.verify(signatureByte);
        System.out.println("SignatureResult:"+signatureResult);
    }

    @Test
    public void ZUC_test() throws Exception{
        String text="Hello,GmSSL!";
        SecureRandom secureRandom = SecureRandom.getInstance("Random", "GmSSL");
        Cipher cipher = Cipher.getInstance("ZUC","GmSSL");
        SecretKey key = new ZucKey(secureRandom.generateSeed(ZucKey.KEY_SIZE));
        IvParameterSpec ivParameterSpec = new IvParameterSpec(secureRandom.generateSeed(ZucCipher.IV_SIZE));
        // encryption
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] ciphertext = new byte[100];
        int cipherlen = cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, 0);
        cipherlen += cipher.update(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        cipherlen += cipher.doFinal(text.getBytes(), 0, text.getBytes().length, ciphertext, cipherlen);
        byte[] ciphertext1 = Arrays.copyOfRange(ciphertext,0,cipherlen);
        System.out.println("Ciphertext: " + byteToHex(ciphertext1));
        // decryption
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        cipher.update(ciphertext1);
        byte[] plaintext1 = cipher.doFinal();
        System.out.println("plaintext: " + new String(plaintext1));
    }

    /**
     * convert byte array to hex string
     * @param btArr
     * @return String
     */
    private String byteToHex(byte[] btArr) {
        BigInteger bigInteger = new BigInteger(1, btArr);
        return bigInteger.toString(16);
    }

    /**
     * convert hex string to byte array
     * @param hexString
     * @return byte[]
     */
    private byte[] hexToByte(String hexString) {
        byte[] byteArray = new BigInteger(hexString, 16)
                .toByteArray();
        if (byteArray[0] == 0) {
            byte[] output = new byte[byteArray.length - 1];
            System.arraycopy(
                    byteArray, 1, output,
                    0, output.length);
            return output;
        }
        return byteArray;
    }
}
