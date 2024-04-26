cmake_minimum_required(VERSION 3.11)
project(gmssljni)

find_program(GMSSL_EXECUTABLE NAMES gmssl)
if(GMSSL_EXECUTABLE)
    get_filename_component(GMSSL_BIN_DIR "${GMSSL_EXECUTABLE}" DIRECTORY)
    get_filename_component(GMSSL_PARENT_DIR "${GMSSL_BIN_DIR}" DIRECTORY)
else()
    message(FATAL_ERROR "gmssl not found!")
endif()

if(WIN32)
    message(STATUS "->Now is windows")
    link_directories(${GMSSL_PARENT_DIR}/lib)
    add_library(gmssljni-native SHARED gmssljni.c)
    target_include_directories(gmssljni-native PUBLIC ${GMSSL_PARENT_DIR}/include)
    #target_include_directories(gmssljni-native PUBLIC ${CMAKE_SOURCE_DIR}/jni)
    find_package(JNI REQUIRED)
    include_directories(${JNI_INCLUDE_DIRS})
    target_link_libraries(gmssljni-native gmssl)
    set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME lib$ENV{libName})
elseif(APPLE)
    message(STATUS "->Now is Apple systems.")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$ENV{libSubFolder})
    add_library(gmssljni-native SHARED gmssljni.c)
    target_link_libraries(gmssljni-native -L"${GMSSL_PARENT_DIR}/lib")
    find_package(JNI REQUIRED)
    include_directories(${JNI_INCLUDE_DIRS})
    include_directories(${GMSSL_PARENT_DIR}/include)
    target_link_libraries(gmssljni-native gmssl)
    set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME $ENV{libName})
elseif(UNIX)
    message(STATUS "->Now is UNIX-like OS's.")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/$ENV{libSubFolder})
    add_library(gmssljni-native SHARED gmssljni.c)
    target_link_libraries(gmssljni-native -L"${GMSSL_PARENT_DIR}/lib")
    find_package(JNI REQUIRED)
    include_directories(${JNI_INCLUDE_DIRS})
    include_directories(${GMSSL_PARENT_DIR}/include)
    target_link_libraries(gmssljni-native gmssl)
    set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME $ENV{libName})
else()
    message(FATAL_ERROR "->Now is other systems.")
endif()

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