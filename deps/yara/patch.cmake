
function(patch_vcxproj file)

    file(READ "${file}" content)
    set(new_content "${content}")

    string(REPLACE
        "jansson.lib"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "libcrypto.lib"
        ""
        new_content
        "${new_content}"
    )
	# We also use this to enable macho module.
    string(REPLACE
        "CUCKOO_MODULE"
        "MACHO_MODULE"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "HASH_MODULE"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "HAVE_LIBCRYPTO"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "PROFILING_ENABLED"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.Jansson.x64.1.1.0\\include"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.Jansson.x86.1.1.0\\include"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.Jansson.x64.1.1.0\\lib"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.Jansson.x86.1.1.0\\lib"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.OpenSSL.x64.1.1.0\\include"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.OpenSSL.x86.1.1.0\\include"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.OpenSSL.x64.1.1.0\\lib"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "..\\packages\\YARA.OpenSSL.x86.1.1.0\\lib"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
		"<ClCompile Include=\"..\\..\\..\\libyara\\modules\\cuckoo\\cuckoo.c\" />"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<ClCompile Include=\"..\\..\\..\\libyara\\modules\\dex\\dex.c\" />"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<ClCompile Include=\"..\\..\\..\\libyara\\modules\\hash\\hash.c\" />"
        ""
        new_content
        "${new_content}"
    )

	if(RETDEC_MSVC_STATIC_RUNTIME)
		string(REPLACE
			"MultiThreadedDLL"
			"MultiThreaded"
			new_content
			"${new_content}"
		)
	endif()

    if("${new_content}" STREQUAL "${content}")
        message(STATUS "-- Patching: ${file} skipped")
    else()
        message(STATUS "-- Patching: ${file} patched")
        file(WRITE "${file}" "${new_content}")
    endif()
endfunction()

patch_vcxproj("${yara_path}/windows/vs2015/libyara/libyara.vcxproj")
patch_vcxproj("${yara_path}/windows/vs2015/libyara/libyara.vcxproj")

# https://github.com/VirusTotal/yara/pull/1289
function(patch_dotnet file)
    file(READ "${file}" content)
    set(new_content "${content}")

    string(REPLACE
        "// Return a 0 size as an error.\n    result.size = 0;\n"
        "// Return a 0 size as an error.\n    result.size = 0;\n    return result;\n"
        new_content
        "${new_content}"
    )

    if("${new_content}" STREQUAL "${content}")
        message(STATUS "-- Patching: ${file} skipped")
    else()
        message(STATUS "-- Patching: ${file} patched")
        file(WRITE "${file}" "${new_content}")
    endif()
endfunction()
patch_dotnet("${yara_path}/libyara/modules/dotnet/dotnet.c")

# https://github.com/VirusTotal/yara/pull/1540
function(patch_configure_ac file)
    file(READ "${file}" content)
    set(new_content "${content}")

    string(REPLACE
        "PKG_CHECK_MODULES(PROTOBUF_C, libprotobuf-c >= 1.0.0)"
        "PKG_CHECK_MODULES([PROTOBUF_C], [libprotobuf-c >= 1.0.0])"
        new_content
        "${new_content}"
    )

    string(REPLACE
        "AC_CHECK_LIB(protobuf-c, protobuf_c_message_unpack,,"
        "AC_CHECK_LIB([protobuf-c], protobuf_c_message_unpack,,"
        new_content
        "${new_content}"
    )

    if("${new_content}" STREQUAL "${content}")
        message(STATUS "-- Patching: ${file} skipped")
    else()
        message(STATUS "-- Patching: ${file} patched")
        file(WRITE "${file}" "${new_content}")
    endif()
endfunction()
patch_configure_ac("${yara_path}/configure.ac")
