/**
 * @file src/demanglertool/demangler.cpp
 * @brief Demangler tool.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cstring>
#include <iostream>

#include "retdec/demangler/demangler.h"

using namespace std;

/**
 * @brief String constant containing help.
 */
const string helpmsg =
	"Demangler tool.\n"
	"\n"
	"Usage:\n"
	"\t'demangler -h | Show this help.\n"
	"\t'demangler mangledname | Attempt to demangle a name using all available demanglers and print result if succeded.\n";

/**
 * @brief Main function of the Demangler tool.
 * @param argc Argument count.
 * @param argv Arguments.
 */
int main(int argc, char *argv[]) {
	retdec::demangler::CDemangler dem_gcc("gcc");
	retdec::demangler::CDemangler dem_ms("ms");
	retdec::demangler::CDemangler dem_borland("borland");

	string demangledGcc;
	string demangledMs;
	string demangledBorland;

	//no argument -- print help
	if (argc <= 1) {
		cout << helpmsg;
		return 0;
	}

	//first argunment contains help request
	else {
		//print help
		if (strcmp(argv[1],"-h") == 0 || strcmp(argv[1],"--help") == 0) {
			cout << helpmsg;
			return 0;
		}
	}

	//check for initialization errors
	if (!dem_gcc.isOk()) {
		cerr << dem_gcc.printError() << endl;
		return 1;
	}

	if (!dem_ms.isOk()) {
		cerr << dem_ms.printError() << endl;
		return 1;
	}

	if (!dem_borland.isOk()) {
		cerr << dem_borland.printError() << endl;
		return 1;
	}

	//process all mangled arguments
	for (unsigned int i = 1; i < static_cast<unsigned int>(argc); i++) {
		//demangle using all available demanglers
		demangledGcc = dem_gcc.demangleToString(argv[i]);
		demangledMs = dem_ms.demangleToString(argv[i]);
		demangledBorland = dem_borland.demangleToString(argv[i]);

		//check for success or fail and reset errors
		if (!dem_gcc.isOk()) {
			cerr << "gcc: " << dem_gcc.printError() << endl;
			dem_gcc.resetError();
		}
		else {
			cout << "gcc: " << demangledGcc << endl;
		}

		if (!dem_ms.isOk()) {
			cerr << "ms: " << dem_ms.printError() << endl;
			dem_ms.resetError();
		}
		else {
			cout << "ms: " << demangledMs << endl;
		}

		if (!dem_borland.isOk()) {
			cerr << "borland: " << dem_borland.printError() << endl;
			dem_borland.resetError();
		}
		else {
			cout << "borland: " << demangledBorland << endl;
		}

		demangledGcc = "";
		demangledMs = "";
		demangledBorland = "";

	} //for

	return 0;
}
