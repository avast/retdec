/**
* @file include/retdec/llvmir2hll/support/visitable.h
* @brief Interface for classes whose instances are visitable by a Visitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_VISITABLE_H
#define RETDEC_LLVMIR2HLL_SUPPORT_VISITABLE_H

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief Interface for classes whose instances are visitable by a Visitor.
*
* Implements the Visitor design pattern.
*/
class Visitable {
public:
	/**
	* @brief Visitor pattern implementation.
	*
	* Subclasses should implement this method as:
	* @code
	* v->visit(ucast<T>(shared_from_this()));
	* @endcode
	*
	* where @c T is the name of the subclass, and shared_from_this() and @c
	* ucast<> are from Decompiler/Support/SmartPtr.h.
	*/
	virtual void accept(Visitor *v) = 0;

protected:
	// Public constructor is not needed in an interface, so prevent the
	// compiler from generating a public one.
	Visitable() = default;

	// Protected non-virtual destructor disables polymorphic destruction, which
	// is the appropriate behavior in this case.
	~Visitable() = default;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
