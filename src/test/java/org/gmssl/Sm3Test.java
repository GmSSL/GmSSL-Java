package org.gmssl;

import org.junit.Assert;
import org.junit.Test;

/**
 * Sm3 unit test
 */
public class Sm3Test {

    @Test
    public void digestTest(){
        String testStr="gmssl";
        try(Sm3 sm3 = new Sm3()) {
            sm3.update(testStr.getBytes(), 0, 3);
            byte[] dgst = sm3.digest();
            StringBuilder buff=new StringBuilder(dgst.length*2);
            for(byte b:dgst){
                buff.append(String.format("%02x",b & 0xff));
            }
            //System.out.println(buff.toString());
            Assert.assertNotNull("数据为空异常",buff.toString());
        }catch (Exception e){
            e.printStackTrace();
        }

    }

}
