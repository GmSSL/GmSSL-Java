package org.gmssl;

import org.junit.Assert;
import org.junit.Test;

public class Sm3HmacTest {

    @Test
    public void macTest(){
        String testStr="gmssl";
        Random rng = new Random();
        byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

        Sm3Hmac sm3hmac = new Sm3Hmac(key);
        sm3hmac.update(testStr.getBytes(), 0, 3);
        byte[] mac = sm3hmac.generateMac();

        StringBuilder buff=new StringBuilder(mac.length*2);
        for(byte b:mac){
            buff.append(String.format("%02x",b & 0xff));
        }
        //System.out.println(buff.toString());
        Assert.assertNotNull("数据为空异常",buff.toString());
    }

}
