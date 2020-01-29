
function(patch_vcxproj file)

    file(READ "${file}" content)
    set(new_content "${content}")

    string(REPLACE
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;CUCKOO_MODULE;HASH_MODULE;DOTNET_MODULE;HAVE_LIBCRYPTO;USE_WINDOWS_PROC;YR_BUILDING_STATIC_LIB;PROFILING_ENABLED</PreprocessorDefinitions>"
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;MACHO_MODULE;USE_WINDOWS_PROC</PreprocessorDefinitions>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<AdditionalDependencies>jansson.lib;libcrypto.lib;%(AdditionalDependencies)</AdditionalDependencies>"
        "<AdditionalDependencies>%(AdditionalDependencies)</AdditionalDependencies>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;CUCKOO_MODULE;HASH_MODULE;DOTNET_MODULE;HAVE_LIBCRYPTO;USE_WINDOWS_PROC;YR_BUILDING_STATIC_LIBC;PROFILING_ENABLED</PreprocessorDefinitions>"
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;MACHO_MODULE;USE_WINDOWS_PROC</PreprocessorDefinitions>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<AdditionalDependencies>crypt32.lib;ws2_32.lib;advapi32.lib;jansson.lib;libcrypto.lib;%(AdditionalDependencies)</AdditionalDependencies>"
        "<AdditionalDependencies>crypt32.lib;ws2_32.lib;advapi32.lib;%(AdditionalDependencies)</AdditionalDependencies>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;CUCKOO_MODULE;HASH_MODULE;DOTNET_MODULE;HAVE_LIBCRYPTO;USE_WINDOWS_PROC;YR_BUILDING_STATIC_LIB</PreprocessorDefinitions>"
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;MACHO_MODULE;USE_WINDOWS_PROC</PreprocessorDefinitions>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;CUCKOO_MODULE;HASH_MODULE;DOTNET_MODULE;HAVE_LIBCRYPTO;USE_WINDOWS_PROC;YR_BUILDING_STATIC_LIB;NDEBUG=1</PreprocessorDefinitions>"
        "<PreprocessorDefinitions>_CRT_SECURE_NO_WARNINGS;MACHO_MODULE;USE_WINDOWS_PROC;NDEBUG=1</PreprocessorDefinitions>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<AdditionalIncludeDirectories>..\\..\\..\\libyara;..\\..\\..\\libyara\\include;..\\..\\..;..\\packages\\YARA.Jansson.x64.1.1.0\\include;..\\packages\\YARA.OpenSSL.x64.1.1.0\\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>"
        "<AdditionalIncludeDirectories>..\\..\\..\\libyara;..\\..\\..\\libyara\\include;..\\..\\..;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<AdditionalLibraryDirectories>..\\packages\\YARA.OpenSSL.x64.1.1.0\\lib;..\\packages\\YARA.Jansson.x64.1.1.0\\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>"
        "<AdditionalLibraryDirectories>%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>"
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<ClCompile Include=\"..\\..\\..\\libyara\\modules\\cuckoo.c\" />"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<ClCompile Include=\"..\\..\\..\\libyara\\modules\\dex.c\" />"
        ""
        new_content
        "${new_content}"
    )
    string(REPLACE
        "<ClCompile Include=\"..\\..\\..\\libyara\\modules\\hash.c\" />"
        ""
        new_content
        "${new_content}"
    )

    if("${new_content}" STREQUAL "${content}")
        message("-- Patching: ${file} skipped")
    else()
        message("-- Patching: ${file} patched")
        file(WRITE "${file}" "${new_content}")
    endif()
endfunction()

patch_vcxproj("${yara_path}/windows/vs2015/libyara/libyara.vcxproj")
patch_vcxproj("${yara_path}/windows/vs2015/libyara/libyara.vcxproj")
