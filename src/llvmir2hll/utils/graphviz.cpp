/**
* @file src/llvmir2hll/utils/graphviz.cpp
* @brief Implementation of the @c graphviz utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cctype>

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/graphviz.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using namespace std::string_literals;

using retdec::utils::addSlashes;
using retdec::utils::toHex;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Default constructor.
*/
UtilsGraphviz::UtilsGraphviz() {}

/**
* @brief Destructor.
*/
UtilsGraphviz::~UtilsGraphviz() {}

/**
* @brief Creates a label from the given @a str so it can be used in labels in
*        the @c dot format.
*/
std::string UtilsGraphviz::createLabel(const std::string &str) {
	// Backslash all the needed characters.
	// TODO Is the following list of characters to be backslashed complete?
	//      Check the dot's specification.
	return addSlashes(str, "\"'\\\0<>{}|"s);
}

/**
* @brief Converts the given string so it can be used as a node's name.
*/
std::string UtilsGraphviz::createNodeName(const std::string &str) {
	std::string nodeName;

	for (auto c : str) {
		// Keep characters from [_a-zA-Z0-9].
		if (std::isalpha(c) || c == '_') {
			nodeName += c;
		}
		// Replace '.', '-', and spaces with '_'.
		else if (c == '.' || c == '-' || std::isspace(c)) {
			nodeName += '_';
		}
		// Every other character is converted into its hexadecimal
		// representation.
		else {
			nodeName += toHex(c);
		}
	}

	return nodeName;
}

} // namespace llvmir2hll
} // namespace retdec
