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
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * @author yongfei.li
 * @email  290836576@qq.com
 * @date 2023/09/07
 * @description Native lib load util
 */
public class NativeLoader {

    private static final CopyOnWriteArraySet<String> LOADED_LIBARAY_SET=new CopyOnWriteArraySet<>();

    /* custom jni library prefix path relative to project resources */
    private static final String RESOURCELIB_PREFIXPATH = "lib";

    /**
     * load jin lib:
     * load personal jni library,the path must be a full path relative to the operating system,the lib file extension must be given too.
     * load custom jni library,the default path is resources/lib of this project,load the corresponding class library according to the operating system.
     * load the corresponding system jni library according to the operating system.
     * @param libaray ... lib path  eg:/home/lib/libxxx.so,/gmssl/libxxx,libxxx
     *
     */
    public synchronized static void load (String... libaray){
        if(null == libaray || libaray.length<1){
            throw new GmSSLException("Library is empty exception!");
        }
        for(String lib:libaray){
            if(LOADED_LIBARAY_SET.contains(lib)){
                continue;
            }
            //load personal jni library,the path must be a full path relative to the operating system,the lib file extension must be given too.
            File personalLibFile = new File(lib).getAbsoluteFile();
            if(personalLibFile.exists() && personalLibFile.isFile()){
                loadLibFile(personalLibFile,lib);
            }else{
                //load custom jni library,the default path is resources/lib of this project,load the corresponding class library according to the operating system.
                String resourceLibPath=RESOURCELIB_PREFIXPATH+"/" + platform()+"/"+lib+"."+libExtension();
                URL resourceUrl = NativeLoader.class.getClassLoader().getResource(resourceLibPath);
                if(null !=resourceUrl){
                    File tmpLibFile= createTmpLibFile(resourceLibPath);
                    loadLibFile(tmpLibFile,lib);
                    tmpLibFile.deleteOnExit();
                }else{
                    //load the corresponding system jni library according to the operating system.
                    String[] sysLibPathS = System.getProperty("java.library.path").split(File.pathSeparator);
                    for(String sysLibPath:sysLibPathS){
                        File sysLibFile = new File(sysLibPath, lib+"."+libExtension()).getAbsoluteFile();
                        loadLibFile(sysLibFile,lib);
                        break;
                    }
                }
            }

        }
    }

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

    static String archType(){
        String arch="unknown";
        String archName = System.getProperty("os.arch").toLowerCase();
        if ("i386".equals(archName) || "i686".equals(archName)){
            arch="x86";
        }
        if ("x86_64".equals(archName) || "amd64".equals(archName)){
            arch="x86_64";
        }
        if ("arm".equals(archName)) {
            arch = "arm";
        }
        return arch;
    }

    static String libExtension(){
        String osType=osType();
        String libExtension=null;
        if("win".equals(osType)){
            libExtension="dll";
        }
        if("osx".equals(osType)){
            libExtension="jnilib";
        }
        if("linux".equals(osType)){
            libExtension="so";
        }
        return libExtension;
    }

    private static String platform(){
        String os=osType();
        String arch=archType();
        return os+"-"+arch;
    }

    private static void loadLibFile(File file,String libName){
        if (file.exists() && file.isFile()) {
            System.load(file.getAbsolutePath());
            LOADED_LIBARAY_SET.add(libName);
        }else{
            throw new GmSSLException("lib file is not found!");
        }
    }

    private static File createTmpLibFile(String resourceLibPath){
        InputStream in = NativeLoader.class.getClassLoader().getResourceAsStream(resourceLibPath);
        String tmpDirName = System.getProperty("java.io.tmpdir");
        File tmpDir = new File(tmpDirName);
        if (!tmpDir.exists()) {
            tmpDir.mkdir();
        }
        File file = null;
        try {
            file=File.createTempFile(resourceLibPath, null, tmpDir);
            assert in != null;
            ReadableByteChannel srcChannel = Channels.newChannel(in);
            FileChannel targetChannel = new FileOutputStream(file).getChannel();
            targetChannel.transferFrom(srcChannel, 0, Long.MAX_VALUE);
        } catch (FileNotFoundException e) {
            throw new GmSSLException("FileNotFoundException");
        } catch (IOException e) {
            throw new GmSSLException("IOException");
        }
        return file;
    }


}
