
set(CRYPTO_SOURCES
	crc32.cpp
	crypto.cpp
	hash_context.cpp
)

if(NOT TARGET fileformat-crypto)

	add_library(fileformat-crypto STATIC ${CRYPTO_SOURCES})
	target_link_libraries(fileformat-crypto tl-cpputils openssl-crypto)
	target_include_directories(fileformat-crypto PUBLIC ${PROJECT_SOURCE_DIR}/include/)

endif()
