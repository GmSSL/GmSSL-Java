package org.gmssl;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class Sm4CbcTest {

    Sm4Cbc sm4Cbc=null;
    Random rng = new Random();
    byte[] key = rng.randBytes(Sm4Cbc.KEY_SIZE);
    byte[] iv = rng.randBytes(Sm4Cbc.IV_SIZE);

    @Before
    public void beforeTest(){
        sm4Cbc = new Sm4Cbc();
    }

    @Test
    public void encryptTest(){
        String testStr="abc";
        byte[] ciphertext = new byte[Sm4Cbc.BLOCK_SIZE * 2];
        sm4Cbc.init(key, iv, true);
        int cipherlen = sm4Cbc.update(testStr.getBytes(), 0, 3, ciphertext, 0);
        cipherlen += sm4Cbc.doFinal(ciphertext, cipherlen);
        //System.out.println(cipherlen);
        StringBuilder buff=new StringBuilder(cipherlen*2);
        for(int i=0;i<cipherlen;i++){
            buff.append(String.format("%02x",ciphertext[i] & 0xff));
        }
        //System.out.println("cipher:"+buff.toString());
        Assert.assertNotNull("数据为空异常",buff.toString());
    }

    @Test
    public void decryptTest(){


    }

}
