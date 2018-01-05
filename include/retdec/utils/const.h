/**
* @file include/retdec/utils/const.h
* @brief A helper function to prevent code duplication between const and
*        non-const member functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The implementation is based on http://stackoverflow.com/a/16780327/2580955.
*/

#ifndef RETDEC_UTILS_CONST_H
#define RETDEC_UTILS_CONST_H

namespace retdec {
namespace utils {

// Internal helpers to remove constness.
// (std::remove_cv cannot be used here because we are removing the constness
// from the pointed/referenced type.)

template<typename T>
struct NonConst { using type = T; };

template<typename T>
struct NonConst<const T> { using type = T; }; // by value

template<typename T>
struct NonConst<const T&> { using type = T&; }; // by reference

template<typename T>
struct NonConst<const T*> { using type = T*; }; // by pointer

template<typename T>
struct NonConst<const T&&> { using type = T&&; }; // by rvalue-reference

/*
* @brief A helper function to prevent code duplication between const and
*        non-const member functions.
*
* Usage example:
* @code
* class Array {
* public:
*     // const version
*     const int *getElement(std::size_t i) const {
*         // Here comes the implementation.
*         // ...
*     }
*
*     // non-const version
*     int *getElement(std::size_t i) {
*         return likeConstVersion(this, &Array::getElement, i);
*     }
*
*    // ...
* };
* @endcode
*/
template<typename ConstReturn, class Object, typename... MemFunArgs,
	typename... RealArgs>
auto likeConstVersion(
	const Object *object,
	ConstReturn (Object::*memFun)(MemFunArgs...) const,
	RealArgs... args)
{
	return const_cast<typename NonConst<ConstReturn>::type>(
		(object->*memFun)(args...)
	);
}

} // namespace utils
} // namespace retdec

#endif
