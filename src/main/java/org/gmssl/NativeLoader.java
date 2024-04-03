/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
package org.gmssl;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

import java.io.*;
import java.net.URL;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * @author yongfei.li
 * @email  290836576@qq.com
 * @date 2023/09/07
 * @description Native lib load util
 */
public class NativeLoader {

    private static final Set<String> LOADED_LIBARAY_SET=new CopyOnWriteArraySet<>();

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
            //load personal jni library,the path must be a full path relative to the operating system,the lib file extension must be given too. eg:/home/lib/libxxx.so
            File personalLibFile = new File(lib).getAbsoluteFile();
            if(personalLibFile.exists() && personalLibFile.isFile()){
                loadLibFile(personalLibFile,lib);
            }else{
                //load custom jni library,the default path is resources/lib of this project,load the corresponding class library according to the operating system.
                String resourceLibPath=RESOURCELIB_PREFIXPATH;
                resourceLibPath+="/"+lib+"."+libExtension();
                URL resourceUrl = NativeLoader.class.getClassLoader().getResource(resourceLibPath);
                if(null !=resourceUrl){
                    loadLibFile(new File(resourceUrl.getFile()),lib);
                }else{
                    //load the corresponding system jni library according to the operating system. eg:libxxx
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
     * Load the library based on the address of the lib file.
     * @param file
     * @param libName
     */
    private static void loadLibFile(File file,String libName){
        if (file.exists() && file.isFile()) {
            checkReferencedLib(file.getName());
            System.load(file.getAbsolutePath());
            LOADED_LIBARAY_SET.add(libName);
        }else{
            throw new GmSSLException("lib file is not found!");
        }
    }

    /**
     * In macOS systems, the execution of library calls relies on loading gmssl.3.dylib from the installed gmssl library,
     * in order to correct the @rpath path issue. Alternatively, you can manually execute the command
     * "install_name_tool -change @rpath/libgmssl.3.dylib /usr/local/lib/libgmssl.3.dylib xxx/lib/libgmssljni.dylib" to fix the library reference path issue.
     * This has already been loaded and manual execution is unnecessary.
     * @param libName
     */
   private static void checkReferencedLib(String libName){
        String macLibName=getPomProperty("libName")+".dylib";
       if(libName.endsWith(macLibName)){
           String macReferencedLib=getPomProperty("macReferencedLib");
           if(null!=macReferencedLib && !LOADED_LIBARAY_SET.contains(macReferencedLib)){
               System.load(macReferencedLib);
               LOADED_LIBARAY_SET.add(macReferencedLib);
           }
       }
   }

    /**
     * Get the value of the property attribute in the pom.xml file
     * @param property
     * @return property value
     */
   public static String getPomProperty(String property){
       String propertyValue;
       try {
           Model model = new MavenXpp3Reader().read(new FileReader("pom.xml"));
           propertyValue= model.getProperties().getProperty(property);
       } catch (IOException | XmlPullParserException e) {
           throw new GmSSLException("An exception occurred while reading the pom file!");
       }
       return propertyValue;
   }

}
