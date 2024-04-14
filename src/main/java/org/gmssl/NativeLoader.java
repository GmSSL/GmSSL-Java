/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Properties;

/**
 * @author yongfei.li
 * @email  290836576@qq.com
 * @date 2023/09/07
 * @description Native lib load util
 */
public class NativeLoader {

    /* custom jni library prefix path relative to project resources */
    private static final String RESOURCELIB_PREFIXPATH = "lib";

    static final String GMSSLJNILIB_NAME="libgmssljni";

    private static final Properties PROPERTIES = new Properties();

    static {
        try (InputStream input = NativeLoader.class.getClassLoader().getResourceAsStream("config.properties")) {
            if (input == null) {
                throw new GmSSLException("can't find config file: config.properties");
            }
            PROPERTIES.load(input);
        } catch (IOException e) {
            e.printStackTrace();
            throw new GmSSLException("can't load config file: config.properties");
        }
    }

    /**
     * load jni lib from resources path,the parameter does not contain the path and suffix.
     * @param libaray libarayName
     *
     */
    public synchronized static void load (String libaray){
        String resourceLibPath = RESOURCELIB_PREFIXPATH + "/" + libaray + "." + libExtension();
        try (InputStream inputStream = NativeLoader.class.getClassLoader().getResourceAsStream(resourceLibPath)) {
            if (null == inputStream) {
                throw new GmSSLException("lib file not found in JAR: " + resourceLibPath);
            }
            Path tempFile = Files.createTempFile(libaray, "."+libExtension());
            tempFile.toFile().deleteOnExit();
            Files.copy(inputStream, tempFile, StandardCopyOption.REPLACE_EXISTING);
            checkReferencedLib();
            System.load(tempFile.toAbsolutePath().toString());
        } catch (Exception e) {
            throw new GmSSLException("Unable to load lib from JAR");
        }
    }

    /**
     * Get the operating system type.
     * @return operating system name
     */
    static String osType(){
        String os="unknown";
        String osName = System.getProperty("os.name").toLowerCase();
        if(osName.startsWith("windows")){
            os="win";
        }
        if(osName.startsWith("linux")){
            if ("dalvik".equalsIgnoreCase(System.getProperty("java.vm.name"))) {
                os = "android";
                System.setProperty("jna.nounpack", "true");
            } else {
                os="linux";
            }
        }
        if(osName.startsWith("mac os x") || osName.startsWith("darwin")){
            os="osx";
        }
        return os;
    }

    /**
     * Get the library extension name based on the operating system type.
     * @return extension name
     */
    static String libExtension(){
        String osType=osType();
        String libExtension=null;
        if("win".equals(osType)){
            libExtension="dll";
        }
        if("osx".equals(osType)){
            libExtension="dylib";
        }
        if("linux".equals(osType)){
            libExtension="so";
        }
        return libExtension;
    }


    /**
     * In macOS systems, the execution of library calls relies on loading gmssl.3.dylib from the installed gmssl library,
     * in order to correct the @rpath path issue. Alternatively, you can manually execute the command
     * "install_name_tool -change @rpath/libgmssl.3.dylib /usr/local/lib/libgmssl.3.dylib xxx/lib/libgmssljni.dylib" to fix the library reference path issue.
     * This has already been loaded and manual execution is unnecessary.
     *
     */
   private static void checkReferencedLib(){
       if("osx".equals(osType())){
           String macReferencedLib=PROPERTIES.getProperty("macReferencedLib");
           if(null!=macReferencedLib){
               System.load(macReferencedLib);
           }
       }
   }

}
