/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/empty_array_to_string_optimizer.h
* @brief Optimizes global empty arrays to empty strings.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_EMPTY_ARRAY_TO_STRING_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_EMPTY_ARRAY_TO_STRING_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Module;

/**
* @brief Optimizes global empty arrays to empty strings.
*
* This optimizer transforms global empty arrays in arrays to empty
* strings. For example, the following global variable definition
* @code
* ERRMSG = [[], "test2", "test3"]
* @endcode
* is converted to
* @code
* ERRMSG = ["", "test2", "test3"]
* @endcode
*
* It simply searches for global arrays which hold strings and (possibly
* several) empty arrays. If this is the case, it converts all the found empty
* arrays into empty strings.
*
* The reason for the existence of this optimization is that during the
* generation of backend IR, it is not known whether we should generate @c [] or
* @c "". This is the place where this optimization comes handy.
*
* TODO: Consider also local arrays? The situation is not the same as with
* global arrays. For example, the following piece of code
* @code
* int main(int argc, const char **argv) {
*     const char *ARR[] = {
*         "",
*         "b",
*         "c",
*     };
*
*     printf("%s\n", ARR[argc]);
*     return 0;
* }
* @endcode
* is currently converted to
* @code
* def main(argc, **argv):
*     # entry
*     ARR = array(3)
*     ARR[0] = []
*     ARR[1] = "b"
*     ARR[2] = "c"
*     puts(ARR[argc])
* return 0
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class EmptyArrayToStringOptimizer final: public Optimizer {
public:
	EmptyArrayToStringOptimizer(ShPtr<Module> module);

	virtual ~EmptyArrayToStringOptimizer() override;

	virtual std::string getId() const override { return "EmptyArrayToString"; }

private:
	virtual void doOptimization() override;

	bool isArrayOfStrings(ShPtr<ConstArray> array);
	bool isEmptyArray(ShPtr<Expression> expr);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
