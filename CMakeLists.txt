cmake_minimum_required(VERSION 3.21)
project(lactxv2)

set(CMAKE_CXX_STANDARD 14)

# find openssl install with the libraries filesystem and system
find_package(OpenSSL REQUIRED)


# check if OPENSSL was found
if(OpenSSL_FOUND)
    message ("LOG: OpenSSL found")
else()
    message (FATAL_ERROR "Cannot find OpenSSL")
endif()

# find sqlite3 install with the libraries filesystem and system
find_package(SQLite3 REQUIRED)

# check if SQLITE3 was found
if(SQLite3_FOUND)
    message ("LOG: SQLite3 found")
else()
    message (FATAL_ERROR "Cannot find SQLite3")
endif()


############################################################
# Create a library
############################################################

set(LATTICE_SOURCES
        src/lattice256/params.h
        src/util.h)

add_library(lattice256_fips202 SHARED src/lattice256/fips202.c ${LATTICE_SOURCES})
add_library(lattice256::fips202 ALIAS lattice256_fips202)
target_include_directories(lattice256_fips202 PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)

add_library(lattice256_shake SHARED src/lattice256/shake.c ${LATTICE_SOURCES})
add_library(lattice256::shake ALIAS lattice256_shake)
target_include_directories(lattice256_shake PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)
target_link_libraries(lattice256_shake PRIVATE lattice256::fips202)

add_library(lattice256_ntt SHARED src/lattice256/ntt.c ${LATTICE_SOURCES})
add_library(lattice256::ntt ALIAS lattice256_ntt)
target_include_directories(lattice256_ntt PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)

add_library(lattice256_poly SHARED src/lattice256/poly.c ${LATTICE_SOURCES})
add_library(lattice256::poly ALIAS lattice256_poly)
target_include_directories(lattice256_poly PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)
target_link_libraries(lattice256_poly PRIVATE lattice256::ntt)

add_library(lattice256_random SHARED src/lattice256/random.c ${LATTICE_SOURCES})
add_library(lattice256::random ALIAS lattice256_random)
target_include_directories(lattice256_random PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)
target_link_libraries(lattice256_random PRIVATE lattice256::poly)

add_library(lattice256 SHARED src/lattice256/polyvec.c  src/lattice256/uniform.c ${LATTICE_SOURCES})
add_library(lattice256::lib ALIAS lattice256)
target_include_directories(lattice256 PUBLIC ${PROJECT_SOURCE_DIR}/src/lattice256)
target_link_libraries(lattice256 PUBLIC lattice256::ntt)
target_link_libraries(lattice256 PUBLIC lattice256::fips202)
target_link_libraries(lattice256 PUBLIC lattice256::shake)
target_link_libraries(lattice256 PUBLIC lattice256::ntt)
target_link_libraries(lattice256 PUBLIC lattice256::poly)
target_link_libraries(lattice256 PUBLIC lattice256::random)

add_library(lactxv2_pack SHARED src/lactx_pack.c ${LATTICE_SOURCES})
add_library(lactxv2::pack ALIAS lactxv2_pack)
target_include_directories(lactxv2_pack PUBLIC ${PROJECT_SOURCE_DIR}/src/)
target_link_libraries(lactxv2_pack PRIVATE lattice256::poly)
target_link_libraries(lactxv2_pack PRIVATE m)

#Generate the shared library from the library sources
add_library(lactxv2_lib SHARED
        src/lactx_store.c
        src/lactx_header.c
        src/lactx_coin.c
        src/lactx_db.c)
add_library(lactxv2::library ALIAS lactxv2_lib)
target_include_directories(lactxv2_lib PUBLIC ${PROJECT_SOURCE_DIR}/include)

# link against the boost libraries
target_link_libraries(lactxv2_lib PRIVATE OpenSSL::SSL)
target_link_libraries(lactxv2_lib PRIVATE SQLite::SQLite3)
target_link_libraries(lactxv2_lib PRIVATE m)
target_link_libraries(lactxv2_lib PUBLIC lattice256::lib)
target_link_libraries(lactxv2_lib PUBLIC lactxv2::pack)

############################################################
# Create the tests
############################################################

# Add an executable with the above sources
add_executable(tests src/tests.c)

# link the new target with the target
target_link_libraries(tests PRIVATE lactxv2::library)
target_link_libraries(tests PRIVATE OpenSSL::SSL)
target_link_libraries(tests PRIVATE SQLite::SQLite3)
target_link_libraries(tests PRIVATE m)

############################################################
# Create the bench
############################################################

# Add an executable with the above sources
add_executable(bench src/bench/bench.c src/util.h src/lactx_pack.h)

# link the new target with the target
target_link_libraries(bench PRIVATE lactxv2::library)
target_link_libraries(bench PRIVATE OpenSSL::SSL)
target_link_libraries(bench PRIVATE SQLite::SQLite3)

############################################################
# Create the example
############################################################

# Add an executable with the above sources
add_executable(example example/simple_store.c)

# link the new target with the target
target_link_libraries(example PRIVATE lactxv2::library)
target_link_libraries(example PRIVATE OpenSSL::SSL)
target_link_libraries(example PRIVATE SQLite::SQLite3)
