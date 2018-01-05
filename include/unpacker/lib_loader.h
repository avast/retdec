/**
 * @file include/unpacker/lib_loader.h
 * @brief Wrapper for multiplatform loading of dynamic libraries.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKER_LIB_LOADER_H
#define UNPACKER_LIB_LOADER_H

#include <string>

#include "tl-cpputils/os.h"

#ifdef OS_WINDOWS
	#include <windows.h>
#else
	#include <dlfcn.h>
#endif

namespace unpackertool {

#ifdef OS_WINDOWS
	using LibHandle = HMODULE;
	using FuncHandle = FARPROC;

	static inline LibHandle LOAD_LIBRARY(const std::string& path)
	{
		return LoadLibraryA(path.c_str());
	}

	static inline FuncHandle GET_FUNCTION(LibHandle& lib, const std::string& name)
	{
		return GetProcAddress(lib, name.c_str());
	}

	static inline void UNLOAD_LIBRARY(LibHandle& handle)
	{
		FreeLibrary(handle);
	}

	static inline std::string GET_LAST_ERROR()
	{
		// @todo: Implement on windows
		return std::string();
	}
#else
	using LibHandle = void*;
	using FuncHandle = void*;

	static inline LibHandle LOAD_LIBRARY(const std::string& path)
	{
		return dlopen(path.c_str(), RTLD_NOW);
	}

	static inline FuncHandle GET_FUNCTION(LibHandle& lib, const std::string& name)
	{
		return dlsym(lib, name.c_str());
	}

	static inline void UNLOAD_LIBRARY(LibHandle& handle)
	{
		dlclose(handle);
	}

	static inline std::string GET_LAST_ERROR()
	{
		const char* errorMsg = dlerror();
		if (errorMsg == nullptr)
			return std::string();

		return std::string(errorMsg);
	}
#endif

/**
 * @brief Abstract loader of dynamic libraries.
 *
 * Performs the multiplatform loading of dynamic libraries. It is required to have
 * LOAD_LIBRARY, GET_FUNCTION and UNLOAD_LIBRARY functions implemented on the targeted platform.
 * Also LibHandle and FuncHandle types need to be defined.
 */
class LibLoader
{
public:
	/**
	 * Loads the specified dynamic library.
	 *
	 * @param path Name of the dynamic library.
	 *
	 * @return The handle to the loaded library.
	 */
	static LibHandle loadLibrary(const std::string& path)
	{
		return LOAD_LIBRARY(path);
	}

	/**
	 * Loads the specified function from the dynamic library.
	 *
	 * @tparam FuncType Type of the function loaded.
	 *
	 * @param handle Handle of the loaded library returned by @ref loadLibrary.
	 * @param name The name of the function to load.
	 *
	 * @return The pointer to the loaded function.
	 */
	template <typename FuncType> static FuncType loadFunction(LibHandle& handle, const std::string& name)
	{
		return reinterpret_cast<FuncType>(reinterpret_cast<std::uint64_t>(GET_FUNCTION(handle, name.c_str())));
	}

	/**
	 * Unloads the specified dynamic library from memory.
	 *
	 * @param handle Handle to the loaded library.
	 */
	static void unloadLibrary(LibHandle handle)
	{
		UNLOAD_LIBRARY(handle);
	}

	/**
	 * Returns the last error in case of error during the library loading.
	 *
	 * @return Error string.
	 */
	static std::string getLastError()
	{
		return GET_LAST_ERROR();
	}
};

} // namespace unpackertool

#endif
