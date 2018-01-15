/**
* @file include/retdec/llvmir2hll/support/singleton.h
* @brief Implementation of the Singleton design pattern.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_SINGLETON_H
#define RETDEC_LLVMIR2HLL_SUPPORT_SINGLETON_H

namespace retdec {
namespace llvmir2hll {

/**
* @brief Implementation of the Singleton design pattern.
*
* This template is especially suited to be used to make object factories
* singletons. For example, the following code snippet shows how to define a
* singleton factory:
* @code
* using FactoryWriter = Singleton<
*    Factory<
*        // Type of the basic product.
*        Writer,
*        // Type of the object's identifier.
*        std::string
*    >
* >;
* @endcode
*
* @tparam T Class with only a single instance. It needs to have a public
*           constructor.
*/
template<class T>
class Singleton {
public:
	/**
	* @brief Returns the instance of the object being held.
	*
	* This function always returns a reference to the same object. The object
	* is created upon the first call of this function.
	*/
	static T &getInstance() {
		// This variant of returning a static variable has a big advantage - we
		// don't have to care about the destruction of the object being held
		// (if it was using dynamic allocation or it was declared static as a
		// private variable, we would need to take care of it). Sometimes it's
		// called "Meyer's singleton", according to the author.
		static T instance;
		return instance;
	}

public:
	// Disable both constructors, destructor, and assignment operator.
	// They are declared public to make diagnostics messages more precise.
	Singleton() = delete;
	Singleton(const Singleton &) = delete;
	~Singleton() = delete;
	Singleton &operator=(const Singleton &) = delete;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
