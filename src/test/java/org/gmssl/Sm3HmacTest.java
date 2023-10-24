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
 * @description Sm3Hmac unit test
 */
public class Sm3HmacTest {

    @Test
    public void macTest(){
        String testStr="gmssl";
        Random rng = new Random();
        byte[] key = rng.randBytes(Sm3Hmac.MAC_SIZE);

        Sm3Hmac sm3hmac = new Sm3Hmac(key);
        sm3hmac.update(testStr.getBytes(), 0, 3);
        byte[] mac = sm3hmac.generateMac();

        String maxHex= HexUtil.byteToHex(mac);
        //System.out.println(maxHex);
        Assert.assertNotNull("data is empty exception!",maxHex);
    }

}
