/**
* @file include/retdec/llvmir2hll/utils/graphviz.h
* @brief @c graphviz utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_UTILS_GRAPHVIZ_H
#define RETDEC_LLVMIR2HLL_UTILS_GRAPHVIZ_H

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief @c graphviz utilities.
*
* For more information on @c graphviz, see http://www.graphviz.org/.
*
* This class implements the "static helper" (or "library") design pattern (it
* has just static functions and no public instances can be created).
*/
class UtilsGraphviz {
public:
	static std::string createLabel(const std::string &str);
	static std::string createNodeName(const std::string &str);

private:
	UtilsGraphviz();
	~UtilsGraphviz();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
