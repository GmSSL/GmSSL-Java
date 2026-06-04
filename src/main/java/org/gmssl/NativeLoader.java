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
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.Map;
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

    static final String GMSSLJNILIB_NAME = "libgmssljni";

    private static final Map<String, Path> loadedLibraries = new HashMap<>();

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
     *
     * @param library libraryName
     */
    public static void load(String library) {
        if (loadedLibraries.containsKey(library)) {
            return;
        }
        Path tempFile = null;
        String resourceLibPath = RESOURCELIB_PREFIXPATH + "/" + library + "." + libExtension();
        try (InputStream inputStream = NativeLoader.class.getClassLoader().getResourceAsStream(resourceLibPath)) {
            if (inputStream == null) {
                throw new GmSSLException("lib file not found in classpath: " + resourceLibPath);
            }
            tempFile = Files.createTempFile(library, "." + libExtension());
            tempFile.toFile().deleteOnExit();
            Files.copy(inputStream, tempFile, StandardCopyOption.REPLACE_EXISTING);
            checkReferencedLib();
            System.load(tempFile.toAbsolutePath().toString());
            loadedLibraries.put(library, tempFile);
        }catch (IOException e){
            throw new GmSSLException("lib file not found:"+ e.getMessage());
        }catch (UnsatisfiedLinkError e){
            throw new GmSSLException("Failed to load native library:"+ e.getMessage());
        } catch (Exception e) {
            throw new GmSSLException("Unable to load lib!");
        }
    }

    /**
     * Get the operating system type.
     *
     * @return operating system name
     */
    static String osType() {
        String os = "unknown";
        String vmName = System.getProperty("java.vm.name");
        if ("dalvik".equalsIgnoreCase(vmName) || "art".equalsIgnoreCase(vmName)) {
            os = "android";
        }
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.startsWith("windows")) {
            os = "win";
        } else if (osName.startsWith("linux")) {
            os = "linux";
        } else if (osName.startsWith("mac os x") || osName.startsWith("darwin")) {
            os = "osx";
        } else {
            System.err.println("Unsupported OS: " + osName);
        }
        return os;
    }

    /**
     * Get the library extension name based on the operating system type.
     *
     * @return extension name
     */
    static String libExtension() {
        String osType = osType();
        String libExtension = null;
        switch (osType) {
            case "win":
                libExtension = "dll";
                break;
            case "osx":
                libExtension = "dylib";
                break;
            case "linux":
            case "android":
                libExtension = "so";
                break;
            default:
                throw new IllegalArgumentException("Unsupported OS type!");
        }
        return libExtension;
    }


    /**
     * In macOS systems, the execution of library calls relies on loading gmssl.3.dylib from the installed gmssl library,
     * in order to correct the @rpath path issue. Alternatively, you can manually execute the command
     * "install_name_tool -change @rpath/libgmssl.3.dylib /usr/local/lib/libgmssl.3.dylib xxx/lib/libgmssljni.dylib" to fix the library reference path issue.
     * This has already been loaded and manual execution is unnecessary.
     */
    private static void checkReferencedLib() {
        String gmsslRoot = System.getProperty("gmssl.root");
        if (gmsslRoot == null || gmsslRoot.isEmpty()) {
            gmsslRoot = System.getenv("GMSSL_ROOT");
        }
        if (gmsslRoot == null || gmsslRoot.isEmpty()) {
            return;
        }

        String os = osType();
        if ("osx".equals(os)) {
            // Pre-load libgmssl.3.dylib so that @rpath resolution works
            String macReferencedLib = PROPERTIES.getProperty("macReferencedLib");
            if (macReferencedLib == null || macReferencedLib.isEmpty()) {
                Path libPath = Paths.get(gmsslRoot, "lib", "libgmssl.3.dylib");
                macReferencedLib = libPath.toString();
            }
            File libFile = new File(macReferencedLib);
            if (libFile.exists()) {
                System.load(macReferencedLib);
            }
        } else if ("win".equals(os)) {
            // Pre-load gmssl.dll so that the JNI DLL can resolve its dependency
            Path libPath = Paths.get(gmsslRoot, "bin", "gmssl.dll");
            File libFile = libPath.toFile();
            if (libFile.exists()) {
                System.load(libPath.toString());
            }
        }
    }

}
