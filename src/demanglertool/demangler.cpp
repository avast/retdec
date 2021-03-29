/**
 * @file src/demanglertool/demangler.cpp
 * @brief Demangler tool.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <string>
#include <iostream>

#include "retdec/demangler/demangler.h"

#include "retdec/utils/io/log.h"
#include "retdec/utils/version.h"

using namespace std::string_literals;
using namespace retdec::utils;
using namespace retdec::utils::io;

using ItaniumDemangler = retdec::demangler::ItaniumDemangler;
using MicrosoftDemangler = retdec::demangler::MicrosoftDemangler;
using BorlandDemangler = retdec::demangler::BorlandDemangler;

/**
 * @brief String constant containing help.
 */
const std::string helpmsg =
	"Usage:\n"
	"\tretdec-demangler [-h, --help]   | Show this help.\n"
	"\tretdec-demangler --version      | Show RetDec version.\n"
	"\tretdec-demangler <mangledname>  | Attempt to demangle <mangledname> using all available demanglers and print result if succeded.\n";

/**
 * @brief Main function of the Demangler tool.
 */
int main(int argc, char *argv[])
{
	auto dem_gcc = std::make_unique<ItaniumDemangler>();
	auto dem_ms = std::make_unique<MicrosoftDemangler>();
	auto dem_borland = std::make_unique<BorlandDemangler>();

	std::string demangledGcc;
	std::string demangledMs;
	std::string demangledBorland;

	if (argc <= 1 || "-h"s == argv[1] || "--help"s == argv[1]) {
		Log::info() << helpmsg;
		return 0;
	}

	if ("--version"s == argv[1])
	{
		Log::info() << version::getVersionStringLong() << std::endl;
		return 0;
	}

	//process all mangled arguments
	for (unsigned int i = 1; i < static_cast<unsigned int>(argc); i++) {
		//demangle using all available demanglers
		demangledGcc = dem_gcc->demangleToString(argv[i]);
		demangledMs = dem_ms->demangleToString(argv[i]);
		demangledBorland = dem_borland->demangleToString(argv[i]);

		if (!demangledGcc.empty()) {
			Log::info() << "gcc: " << demangledGcc << std::endl;
		}
		if (!demangledMs.empty()) {
			Log::info() << "ms: " << demangledMs << std::endl;
		}
		if (!demangledBorland.empty()) {
			Log::info() << "borland: " << demangledBorland << std::endl;
		}
	}

	return 0;
}
