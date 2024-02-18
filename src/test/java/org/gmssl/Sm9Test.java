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
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.*;
import java.util.Map;

/**
 * @author yongfei.li
 * @email 290836576@qq.com
 * @date 2023/10/20
 * @description sm9 unit test
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Sm9Test {

    @Test
    public void signTest() {
        String singContentStr = "gmssl";
        byte[] singContent = singContentStr.getBytes();

        Sm9SignMasterKey sign_master_key = new Sm9SignMasterKey();
        sign_master_key.generateMasterKey();
        Sm9SignKey sign_key = sign_master_key.extractKey("testKey");
        Sm9Signature sign = new Sm9Signature(true);
        sign.update(singContent);
        byte[] sig = sign.sign(sign_key);
        sign_master_key.exportPublicMasterKeyPem("sm9sign.mpk");

        String hexSig = HexUtil.byteToHex(sig);
        //System.out.println(hexSig);
        writeFile("sm9SignData.txt",hexSig);
        Assert.assertNotNull("data is empty exception!",hexSig);
    }

    @Test
    public void verifyTest(){
        String  hexSig=readFile("sm9SignData.txt");
        byte[] sig=HexUtil.hexToByte(hexSig);
        String singContentStr = "gmssl";
        byte[] singContent = singContentStr.getBytes();

        Sm9SignMasterKey sign_master_pub_key = new Sm9SignMasterKey();
        sign_master_pub_key.importPublicMasterKeyPem("sm9sign.mpk");
        Sm9Signature verify = new Sm9Signature(false);
        verify.update(singContent);
        boolean verify_ret = verify.verify(sig, sign_master_pub_key, "testKey");

        //System.out.println("Verify result = " + verify_ret);
        Assert.assertTrue("Verification of the signature failed!",verify_ret);

    }

    /**
     * The encryption test method will generate a file, which will be used by the decryption test method ,
     * the encryption test method needs to be run before the decryption test method.
     */
    @Test
    public void _encryptTest(){
        String plaintextStr = "gmssl";
        byte[] plaintext = plaintextStr.getBytes();

        Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
        enc_master_key.generateMasterKey();
        enc_master_key.exportEncryptedMasterKeyInfoPem("password","sm9enc.mpk");

        Sm9EncMasterKey enc_master_pub_key = new Sm9EncMasterKey();
        enc_master_pub_key.importEncryptedMasterKeyInfoPem("password","sm9enc.mpk");
        byte[] ciphertext = enc_master_pub_key.encrypt(plaintext, "testKey");

        String ciphertextHex=HexUtil.byteToHex(ciphertext);
        //System.out.println(ciphertextHex);
        writeFile("sm9EncryptData.txt",ciphertextHex);
        Assert.assertNotNull("data is empty exception!",ciphertextHex);
    }

    @Test
    public void decryptTest(){
        String ciphertextHex=readFile("sm9EncryptData.txt");
        byte[] ciphertext=HexUtil.hexToByte(ciphertextHex);

        Sm9EncMasterKey enc_master_key = new Sm9EncMasterKey();
        enc_master_key.importEncryptedMasterKeyInfoPem("password","sm9enc.mpk");
        Sm9EncKey enc_key = enc_master_key.extractKey("testKey");
        byte[] plaintext = enc_key.decrypt(ciphertext);

        String plaintextStr = new String(plaintext);
        //System.out.print(plaintextStr);
        Assert.assertEquals("The original value is not equal to the expected value after decryption!","gmssl",plaintextStr);
    }

    /**
     * Write string data to a temporary file.
     * @param fileName
     * @param data
     */
    private void writeFile(String fileName,String data){
        File tempFile = new File("./"+ fileName);
        try {
            if(tempFile.exists()){
                tempFile.delete();
            }else {
                tempFile.createNewFile();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter("./" + fileName))) {
            writer.write(data);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Read string data from a temporary file.
     * @param fileName
     * @return String data
     */
    private String readFile(String fileName){
        FileReader fileReader = null;
        StringBuilder data= new StringBuilder();
        try {
            fileReader = new FileReader(new File( "./"+fileName));
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                data.append(line);
            }
            bufferedReader.close();
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
        return data.toString();
    }

}
