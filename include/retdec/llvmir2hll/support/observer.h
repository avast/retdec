/**
* @file include/retdec/llvmir2hll/support/observer.h
* @brief Implementation of a generic typed observer (observer part).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_OBSERVER_H
#define RETDEC_LLVMIR2HLL_SUPPORT_OBSERVER_H

#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Implementation of a generic typed observer using shared pointers
*        (observer part).
*
* @tparam SubjectType Type of a subject.
* @tparam ArgType     Type of an optional argument.
*
* Implements the Observer design pattern.
*
* Usage:
*
* @code
* class PlanetController: public Observer<Planet> {
* public:
*     PlanetController() {}
*     ~PlanetController() {}
*     virtual void update(ShPtr<SubjectType> subject, ShPtr<ArgType> arg =
*             nullptr) override {
*         std::cout << subject->getName() << " has changed.\n";
*     }
* };
* @endcode
*
* @see Subject
*/
template<typename SubjectType, typename ArgType = SubjectType>
class Observer {
public:
	/**
	* @brief Creates a new observer.
	*/
	Observer() {}

	/**
	* @brief Destructs the observer.
	*/
	virtual ~Observer() {}

	/**
	* @brief Subject has changed its state.
	*
	* @param[in] subject Observable object.
	* @param[in] arg Optional argument.
	*
	* This method is a reaction to @a subject state change.
	*
	* By default, it does nothing.
	*/
	virtual void update(ShPtr<SubjectType> subject,
		ShPtr<ArgType> arg = nullptr) {}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
