set(CRYPTO_SOURCES
	crc32.cpp
	crypto.cpp
	hash_context.cpp
)

add_library(retdec-fileformat-crypto STATIC ${CRYPTO_SOURCES})
target_link_libraries(retdec-fileformat-crypto retdec-utils openssl-crypto)
target_include_directories(retdec-fileformat-crypto PUBLIC ${PROJECT_SOURCE_DIR}/include/)
