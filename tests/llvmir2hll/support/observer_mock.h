/**
* @file tests/llvmir2hll/support/observer_mock.h
* @brief A mock for the Observer class.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef BACKEND_BIR_SUPPORT_TESTS_OBSERVER_MOCK_H
#define BACKEND_BIR_SUPPORT_TESTS_OBSERVER_MOCK_H

#include <gmock/gmock.h>

#include "retdec/llvmir2hll/support/observer.h"

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief A mock for the Observer class.
*/
template<typename SubjectType, typename ArgType = SubjectType>
class ObserverMock: public Observer<SubjectType, ArgType> {
public:
	MOCK_METHOD2_T(update, void (ShPtr<SubjectType>, ShPtr<ArgType>));
};

/**
* @brief Instantiates an ObserverMock with the given name and type.
*
* More specifically, this macro instantiates two classes:
*  (1) @c observerNameMock, which is of type
*      @code
*      ::testing::MockType<ObserverMock<SubjectType>> *
*      @endcode
*  (2) @c observerName, which is of type
*      @code
*      ShPtr<Observer<SubjectType>>
*      @endcode
*      and delegates to the mock from (1).
*/
#define INSTANTIATE_OBSERVER_MOCK(observerName, MockType, SubjectType) \
	::testing::MockType<ObserverMock<SubjectType>> *observerName##Mock = \
		new ::testing::MockType<ObserverMock<SubjectType>>(); \
	ShPtr<Observer<SubjectType>> observerName(observerName##Mock);

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec

#endif
