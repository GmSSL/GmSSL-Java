package org.gmssl;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Sm2 unit test
 */
public class Sm2Test {

    Sm2Key sm2_key=null;

    @Before
    public void beforeTest(){
        sm2_key = new Sm2Key();
        sm2_key.generateKey();
    }

    @Test
    public void computeZTest(){
        byte[] z = sm2_key.computeZ(Sm2Key.DEFAULT_ID);
        StringBuilder buff=new StringBuilder(z.length*2);
        for(byte b:z){
            buff.append(String.format("%02x",b & 0xff));
        }
        //System.out.println("z:"+buff.toString());
        Assert.assertNotNull("数据为空异常",buff.toString());
    }

    @Test
    public void verifyTest(){
        Random rng = new Random();
        byte[] dgst = rng.randBytes(Sm3.DIGEST_SIZE);
        byte[] sig = sm2_key.sign(dgst);
        boolean verify_ret = sm2_key.verify(dgst, sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("数据不为真异常",verify_ret);
    }

    @Test
    public void encryptAndDecryptTest(){
        String testStr="gmssl";
        byte[] ciphertext = sm2_key.encrypt(testStr.getBytes());
        byte[] plaintext = sm2_key.decrypt(ciphertext);
        String originalStr= new String(plaintext);
        //System.out.printf("Plaintext : "+originalStr);
        Assert.assertEquals("原值与加解密后期望值不相等异常",testStr,originalStr);
    }

    @Test
    public void verifySignatureTest(){
        String testStr="gmssl";
        Sm2Signature sign = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, true);
        sign.update(testStr.getBytes());
        byte[] sig = sign.sign();

        Sm2Signature verify = new Sm2Signature(sm2_key, Sm2Key.DEFAULT_ID, false);
        verify.update(testStr.getBytes());
        boolean verify_ret = verify.verify(sig);
        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("数据不为真异常",verify_ret);
    }

}
