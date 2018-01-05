/**
* @file include/retdec/llvmir2hll/ir/value.h
* @brief A base class of all objects a module can contain.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_VALUE_H
#define RETDEC_LLVMIR2HLL_IR_VALUE_H

#include <iosfwd>
#include <string>

#include <llvm/Support/raw_ostream.h>

#include "retdec/llvmir2hll/support/metadatable.h"
#include "retdec/llvmir2hll/support/observer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/subject.h"
#include "retdec/llvmir2hll/support/visitable.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class of all objects a module can contain.
*
* Instances of this class have reference object semantics.
*/
class Value: public Visitable, public Metadatable<std::string>,
		public SharableFromThis<Value>, public Observer<Value>,
		public Subject<Value>, private retdec::utils::NonCopyable {
public:
	virtual ~Value() = 0;

	virtual ShPtr<Value> getSelf() override;

	/**
	* @brief Returns a clone of the value.
	*
	* A clone is (in most cases) an exact copy of the value. This member
	* function provides the copy mechanism for reference objects.
	*
	* The following parts of values are not cloned:
	*  - predecessors and successors of statements
	*
	* The following subclasses of Value are not cloned, i.e. they are
	* returned without any copying:
	*  - Function
	*  - Variable
	*
	* Statements in compound statements (i.e. statements where @c isCompound()
	* returns @c true) are cloned without their successors; therefore, e.g.,
	* just the first statement of every if's clause is cloned.
	*/
	virtual ShPtr<Value> clone() = 0;

	/**
	* @brief Returns @c true if this value is equal to @a otherValue, @c false
	*        otherwise.
	*
	* This member function brings the support of value object semantics into
	* reference objects, namely equality based not only on identity.
	*
	* This function doesn't consider observers, metadata, etc.
	*/
	virtual bool isEqualTo(ShPtr<Value> otherValue) const = 0;

	std::string getTextRepr();

protected:
	Value();
};

/// @name Emission To Streams
/// @{

// These functions have to be declared in the same namespace that defines Value
// and its subclasses; C++ lookup rules rely on that.
llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const ShPtr<Value> &value);
// The following function is used to print values in tests (Google Tests
// framework). It must have this signature; ShPtr<Value> does not work.
std::ostream &operator<<(std::ostream &os, Value *value);

/// @}

} // namespace llvmir2hll
} // namespace retdec

#endif
