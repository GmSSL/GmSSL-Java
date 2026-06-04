cmake_minimum_required(VERSION 3.11)
project(gmssljni C)

if(DEFINED GMSSL_ROOT AND (GMSSL_ROOT STREQUAL "" OR GMSSL_ROOT MATCHES "^\\$\\{.*\\}$"))
    unset(GMSSL_ROOT)
endif()
if(NOT DEFINED GMSSL_ROOT AND DEFINED ENV{GMSSL_ROOT} AND NOT "$ENV{GMSSL_ROOT}" STREQUAL "")
    set(GMSSL_ROOT "$ENV{GMSSL_ROOT}")
endif()

if(GMSSL_ROOT)
    unset(GMSSL_EXECUTABLE CACHE)
    find_program(GMSSL_EXECUTABLE NAMES gmssl HINTS "${GMSSL_ROOT}/bin" NO_DEFAULT_PATH)
else()
    find_program(GMSSL_EXECUTABLE NAMES gmssl)
endif()
if(GMSSL_EXECUTABLE)
    get_filename_component(GMSSL_BIN_DIR "${GMSSL_EXECUTABLE}" DIRECTORY)
    get_filename_component(GMSSL_PARENT_DIR "${GMSSL_BIN_DIR}" DIRECTORY)
else()
    message(FATAL_ERROR "gmssl not found! Install GmSSL or pass -DGMSSL_ROOT=/path/to/gmssl")
endif()

set(GMSSL_INCLUDE_DIR "${GMSSL_PARENT_DIR}/include")
set(GMSSL_LIBRARY_DIR "${GMSSL_PARENT_DIR}/lib")

if(NOT EXISTS "${GMSSL_INCLUDE_DIR}/gmssl/aead.h")
    message(FATAL_ERROR "GmSSL headers at ${GMSSL_INCLUDE_DIR} are incompatible: gmssl/aead.h is missing. Use guanzhi/GmSSL release v3.1.1 or a compatible release.")
endif()

unset(GMSSL_LIBRARY CACHE)
find_library(GMSSL_LIBRARY NAMES gmssl libgmssl HINTS "${GMSSL_LIBRARY_DIR}" NO_DEFAULT_PATH)
if(NOT GMSSL_LIBRARY)
    message(FATAL_ERROR "GmSSL library not found under ${GMSSL_LIBRARY_DIR}")
endif()

if(NOT DEFINED ENV{libSubFolder} OR "$ENV{libSubFolder}" STREQUAL "")
    set(LIB_SUB_FOLDER "${CMAKE_BUILD_TYPE}")
else()
    set(LIB_SUB_FOLDER "$ENV{libSubFolder}")
endif()
if(NOT LIB_SUB_FOLDER)
    set(LIB_SUB_FOLDER "Debug")
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${LIB_SUB_FOLDER}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${LIB_SUB_FOLDER}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${LIB_SUB_FOLDER}")
foreach(CONFIG_TYPE Debug Release RelWithDebInfo MinSizeRel)
    string(TOUPPER "${CONFIG_TYPE}" CONFIG_TYPE_UPPER)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${CMAKE_BINARY_DIR}/${CONFIG_TYPE}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${CMAKE_BINARY_DIR}/${CONFIG_TYPE}")
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_TYPE_UPPER} "${CMAKE_BINARY_DIR}/${CONFIG_TYPE}")
endforeach()

find_package(JNI REQUIRED)

add_library(gmssljni-native SHARED gmssljni.c)
target_include_directories(gmssljni-native PRIVATE ${JNI_INCLUDE_DIRS} "${GMSSL_INCLUDE_DIR}")
target_link_libraries(gmssljni-native PRIVATE "${GMSSL_LIBRARY}")

if(WIN32)
    set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME lib$ENV{libName})
else()
    set_target_properties(gmssljni-native PROPERTIES OUTPUT_NAME $ENV{libName})
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
