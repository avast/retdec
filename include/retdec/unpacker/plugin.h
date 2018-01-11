/**
 * @file include/retdec/unpacker/plugin.h
 * @brief Plugin class declaration which is representation of interface to the plugin library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UNPACKER_PLUGIN_H
#define RETDEC_UNPACKER_PLUGIN_H

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include "retdec/unpacker/unpacker_exception.h"

#define plugin(T) retdec::unpackertool::Plugin::instance<T>()

namespace retdec {
namespace unpackertool {

/**
 * Exit code of the plugin from Plugin::unpack method.
 */
enum PluginExitCode
{
	PLUGIN_EXIT_UNPACKED = 0, ///< Unpacking successful.
	PLUGIN_EXIT_UNSUPPORTED, ///< Unpacking recognized valid data, but it doesn't support unpacking of them
	PLUGIN_EXIT_FAILED ///< Unpacking failed because of malformed data
};

/**
 * @brief The abstract base of unpacking plugin.
 *
 * Represents the unpacking plugin capable of unpacking the specified version of packer. It is an abstract class that
 * is implemented in every single plugin. Plugins are located in unpackertool/plugins/ where every plugin has its
 * own folder. These steps need to be followed to create a new plugin:
 *
 * 1. Create new folder for your plugin in unpackertool/plugins/ and add 'add_subdirectory(YOUR_PLUGIN)' into unpackertool/plugins/CMakeLists.txt.
 * 2. Create CMakeLists.txt in your new folder based on the template in unpackertool/plugins/example/.
 * 3. Subclass Plugin class while
 *      - Providing all data in constructor to info attribute (see @ref Plugin::Info).
 *      - Providing implementation of Plugin::prepare method.
 *      - Providing implementation of Plugin::unpack method.
 *      - Providing implementation of Plugin::cleanup method.
 * 4. Put @c Plugin<YOUR_PLUGIN_CLASS>::instance() into @c PluginMgr::plugins in unpackertool/plugin_mgr.cpp.
 */
class Plugin
{
public:
	/**
	 * @brief The structure representing the plugin metadata.
	 *
	 * This structure represents the plugin managed by @ref PluginMgr.
	 * Contains the metadata about the plugin.
	 */
	struct Info
	{
		Info() : name(""), pluginVersion(""), packerVersion(""), author("") {}

		/**
		 * Check whether all fields are initialized
		 *
		 * @return True if all fields are initialized, otherwise false.
		 */
		bool isUninitialized() const
		{
			return (name == "") || (pluginVersion == "") || (packerVersion == "") || (author == "");
		}

		std::string name; ///< Name of the plugin and also the packer.
		std::string pluginVersion; ///< Plugin version.
		std::string packerVersion; ///< Regular expression of packer version it supports.
		std::string author; ///< Author of the plugin.
	};

	/**
	 * Arguments passed to plugin when it is stared. It contains data that are passed through
	 * command-line or parsed from the config file when unpacker is started by the user.
	 */
	struct Arguments
	{
		std::string inputFile; ///< Path to the input file (packed file).
		std::string outputFile; ///< Path to the output file (unpacked file).
		bool brute; ///< Brute mode of the unpacking was chosen.
	};

	virtual ~Plugin() {} ///< Destructor.

	/**
	 * Returns the static info of the plugin.
	 *
	 * @return @ref Plugin::Info structure containing static plugin info.
	 */
	const Plugin::Info* getInfo() const
	{
		return &info;
	}

	/**
	 * Returns the startup arguments of the plugin.
	 *
	 * @return @ref Plugin::Arguments structure containing startup arguments of the plugin.
	 */
	const Plugin::Arguments* getStartupArguments() const
	{
		return &startupArgs;
	}

	/**
	 * Runs the plugin and all its phases. Also sets the startup arguments of the plugin.
	 *
	 * @param args The plugin arguments. See @ref Plugin::Info.
	 *
	 * @return Exit code of the plugin.
	 */
	PluginExitCode run(const Plugin::Arguments& args)
	{
		// Check whether we have cached exit code
		if (_cachedExitCode != PLUGIN_EXIT_UNPACKED)
		{
			log("Exiting with cached exit code ", _cachedExitCode);
			return _cachedExitCode;
		}

		_cachedExitCode = PLUGIN_EXIT_UNPACKED;
		startupArgs = args;

		try
		{
			prepare();
			unpack();
		}
		catch (const retdec::unpacker::FatalException& ex)
		{
			error(ex.getMessage());
			_cachedExitCode = PLUGIN_EXIT_FAILED;
		}
		catch (const retdec::unpacker::UnsupportedInputException& ex)
		{
			error(ex.getMessage());
			_cachedExitCode = PLUGIN_EXIT_UNSUPPORTED;
		}

		cleanup();
		return _cachedExitCode;
	}

	/**
	 * Pure virtual method that performs preparation of unpacking.
	 */
	virtual void prepare() = 0;

	/**
	 * Pure virtual method that performs the unpacking in the specific plugins.
	 */
	virtual void unpack() = 0;

	/**
	 * Pure virtual method that performs freeing of all owned resources.
	 */
	virtual void cleanup() = 0;

	/**
	 * Prints the message on the standard output prepending the message with '[PLUGIN-NAME]'.
	 * End of line is automatically inserted at the end of the message.
	 *
	 * @tparam Args Types of data to print.
	 *
	 * @param args Data to print.
	 */
	template <typename... Args> void log(const Args&... args)
	{
		Plugin::logImpl(std::cout, "[", getInfo()->name, "] ", args...);
	}

	/**
	 * Prints the error message on the standard error output prepending the message with '[ERROR] [PLUGIN-NAME]'.
	 * End of line is automatically inserted at the end of the message.
	 *
	 * @tparam Args Types of data to print.
	 *
	 * @param args Data to print.
	 */
	template <typename... Args> void error(const Args&... args)
	{
		Plugin::logImpl(std::cerr, "[ERROR] [", getInfo()->name, "] ", args...);
	}

	/**
	 * Returns the instance of specific type of plugin. This should be the only way
	 * how plugin instances are obtained.
	 *
	 * @return Plugin instance.
	 */
	template <typename T>
	static T* instance()
	{
		static std::unique_ptr<T> pluginInstance = std::make_unique<T>();
		return pluginInstance.get();
	}

protected:
	Plugin() : _cachedExitCode(PLUGIN_EXIT_UNPACKED) {}
	Plugin(const Plugin&);
	Plugin& operator =(const Plugin&);

	Plugin::Info info; ///< The static info of the plugin.
	Plugin::Arguments startupArgs; ///< Startup arguments of the plugin.

private:
	PluginExitCode _cachedExitCode; ///< Cached exit code of the plugin for the unpacked file.

	template <typename T, typename... Args> static void logImpl(std::ostream& out, const T& data, const Args&... args)
	{
		out << data;
		logImpl(out, args...);
	}

	static void logImpl(std::ostream& out)
	{
		out << std::endl;
	}
};

} // namespace unpackertool
} // namespace retdec

#endif
