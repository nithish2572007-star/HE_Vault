cmake_minimum_required(VERSION 3.12)
project(HE_Vault)

# Require C++17 for Microsoft SEAL
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies
find_package(SEAL 4.1 REQUIRED)
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(he_vault main.cpp)

# Link libraries
target_link_libraries(he_vault SEAL::seal OpenSSL::SSL OpenSSL::Crypto)
