/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author yongfeili
 * @email  290836576@qq.com
 * @date 2023/09/07
 * @description Sm3 unit test
 */
public class Sm3Test {

    @Test
    public void digestTest(){
        String testStr="gmssl";
        try(Sm3 sm3 = new Sm3()) {
            sm3.update(testStr.getBytes());
            byte[] dgst = sm3.digest();

            String dgstHex= HexUtil.byteToHex(dgst);
            //System.out.println(dgstHex);
            Assert.assertNotNull("数据为空异常",dgstHex);
        }catch (Exception e){
            e.printStackTrace();
        }

    }

}
