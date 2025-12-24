cmake_minimum_required(VERSION 3.15)
project(PrivDialog LANGUAGES CXX)

if (NOT WIN32)
  message(FATAL_ERROR "PrivDialog is Windows-only (requires Win32 APIs).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(PrivDialogDll SHARED src/privdiag_dll.cpp)
target_include_directories(PrivDialogDll PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(PrivDialogDll PRIVATE UNICODE _UNICODE)
target_link_libraries(PrivDialogDll PRIVATE user32 advapi32)

add_executable(PrivDialogExe WIN32 src/privdiag_exe.cpp)
target_include_directories(PrivDialogExe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(PrivDialogExe PRIVATE UNICODE _UNICODE)
target_link_libraries(PrivDialogExe PRIVATE user32 advapi32)

install(TARGETS PrivDialogDll PrivDialogExe
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
