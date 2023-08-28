cmake_minimum_required(VERSION 3.11)
project(gmssljni)

add_library(gmssljni-native SHARED gmssljni.c)
target_include_directories(gmssljni-native PUBLIC ${CMAKE_SOURCE_DIR}/src/include)
target_link_libraries(gmssljni-native -L/usr/local/lib)
target_link_libraries(gmssljni-native gmssl)
set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME gmssljni)


find_package(Java REQUIRED)
include(UseJava)
include_directories(jni)
include_directories(/usr/local/include)

# javac src/main/java/org/gmssl/GmSSLJNI.java -d .
# jar cf GmSSLJNI.jar GmSSLJNI.class
add_jar(GmSSLJNI
	VERSION 2.1.0-dev
	ENTRY_POINT org.gmssl.GmSSLJNI
	GENERATE_NATIVE_HEADERS
	OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
	SOURCES src/main/java/org/gmssl/GmSSLJNI.java
		src/main/java/org/gmssl/GmSSLJNIException.java
		src/main/java/org/gmssl/Sm3.java
		src/main/java/org/gmssl/Sm3Hmac.java
		src/main/java/org/gmssl/Sm4.java
		src/main/java/org/gmssl/Sm4Cbc.java
		src/main/java/org/gmssl/Sm4Ctr.java
		src/main/java/org/gmssl/Sm4Gcm.java
		src/main/java/org/gmssl/Sm2Key.java
		src/main/java/org/gmssl/Sm2Signature.java
		src/main/java/org/gmssl/Sm9EncKey.java
		src/main/java/org/gmssl/Sm9EncMasterKey.java
		src/main/java/org/gmssl/Sm9SignKey.java
		src/main/java/org/gmssl/Sm9SignMasterKey.java
		src/main/java/org/gmssl/Sm9Signature.java
		src/main/java/org/gmssl/Certificate.java
	)

enable_testing()

set(certfile
"-----BEGIN CERTIFICATE-----\n"
"MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG\n"
"EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw\n"
"MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO\n"
"UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE\n"
"MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT\n"
"V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti\n"
"W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ\n"
"MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b\n"
"53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI\n"
"pDoiVhsLwg==\n"
"-----END CERTIFICATE-----\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/ROOTCA.pem ${certfile})

# java -cp GmSSLJNI.jar org.gmssl.GmSSLJNI
add_test(NAME main COMMAND java -cp GmSSLJNI.jar -Djava.library.path=./ org.gmssl.GmSSLJNI)

