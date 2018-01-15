/**
* @file include/retdec/ctypes/visitable.h
* @brief Interface for classes whose instances are visitable by a visitor.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_VISITABLE_H
#define RETDEC_CTYPES_VISITABLE_H

namespace retdec {
namespace ctypes {

class Visitor;

/**
* @brief Interface for classes whose instances are visitable by a visitor.
*
* Implements the visitor design pattern.
*/
class Visitable
{
	public:
		/**
		* @brief Visitor pattern implementation.
		*
		* Subclasses should implement this method as:
		* @code
		* v->visit(std::static_pointer_cast<T>(std::shared_from_this()));
		* @endcode
		*
		* where @c T is the name of the subclass.
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

} // namespace ctypes
} // namespace retdec

#endif
