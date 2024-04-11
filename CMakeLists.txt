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

# Set the Maven command to be executed
set(MAVEN_COMMAND "mvn clean package test")
# Execute Maven command
execute_process(
    COMMAND ${MAVEN_COMMAND}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE MAVEN_RESULT
)
# Check if the Maven command was successfully executed
if(NOT MAVEN_RESULT EQUAL "0")
    message(FATAL_ERROR "Maven execute failed: ${MAVEN_OUTPUT}")
endif()

# Copy the generated jar package to the build directory
set(jarName "GmSSLJNI-2.1.0-dev.jar")
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/target/${jarName}
    DESTINATION ${CMAKE_CURRENT_BINARY_DIR}
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

add_test(NAME main COMMAND java -cp ${jarName} org.gmssl.GmSSLJNI)


