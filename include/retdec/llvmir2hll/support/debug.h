/**
* @file include/retdec/llvmir2hll/support/debug.h
* @brief Debugging support.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_DEBUG_H
#define RETDEC_LLVMIR2HLL_SUPPORT_DEBUG_H

#include <cstdlib> // for abort()

#include <llvm/Support/raw_ostream.h> // for llvm::errs()

/// @name Assertions and Preconditions
/// @{

#ifndef NDEBUG

// Death tests work only when assertions are enabled.
#define DEATH_TESTS_ENABLED 1

/**
* @brief Implementation of aborting the program with an error message @a MSG.
*        For internal use only.
*/
#define ABORT_IMPL(MSG) \
	(llvm::errs() << __FILE__ ":" << __LINE__ << ": " << __func__ << \
		": " << MSG << ".\n", std::abort())

/**
* @brief Implementation of assertion macros in the module. For internal use
*        only.
*/
#define ASSERT_MSG_IMPL(TEST, MSG) \
	((TEST) ? static_cast<void>(0) : ABORT_IMPL(MSG))

/**
* @brief Aborts the program if the assertion @a TEST is @c false, and prints a
*        text version of @a TEST.
*
* Equivalent of assert() from the C standard library.
*/
#define ASSERT(TEST) \
	ASSERT_MSG_IMPL(TEST, "Assertion failed: `" << #TEST << "`")

/**
* @brief Aborts the program if the assertion @a TEST is @c false, and prints a
*        text version of @a TEST and a custom error message @a MSG.
*
* After the text version of @a TEST, it prints the custom message @a MSG, which
* can be anything that can be emitted. You can even sequence several objects
* into the message using the @c << operator. For example,
* @code
* ASSERT_MSG(i > 10, "i = " << i);
* @endcode
*/
#define ASSERT_MSG(TEST, MSG) \
	ASSERT_MSG_IMPL(TEST, "Assertion failed: `" << #TEST \
		<< "` (" << MSG << ")")

/**
* @brief Aborts the program if the precondition @a TEST is @c false, and prints
*        a text version of @a TEST and a custom error message @a MSG.
*
* See ASSERT_MSG for more information on the parameter @a MSG.
*
* Example:
* @code
* PRECONDITION(!module || enableCaching,
*     "when module is non-null, caching has to be enabled");
* @endcode
*/
#define PRECONDITION(TEST, MSG) \
	ASSERT_MSG_IMPL(TEST, "Precondition failed: `" << #TEST \
		<< "` (" << MSG << ")")

/**
* @brief Aborts the program if the precondition @a TEST evaluates to a null
*        pointer, and prints a text version of @a TEST and an error message.
*
* Example:
* @code
* PRECONDITION_NON_NULL(aliasAnalysis);
* @endcode
*/
#define PRECONDITION_NON_NULL(TEST) \
	PRECONDITION(TEST, "expected a non-null pointer")

/**
* @brief Aborts the program with a failed precondition and prints a custom
*        error message @a MSG.
*
* Example:
* @code
* PRECONDITION_FAILED("statement " << stmt << doesn't exist");
* @endcode
*/
#define PRECONDITION_FAILED(MSG) \
	ABORT_IMPL("Precondition failed: " << MSG)

/**
* @brief Aborts the program if the postcondition @a TEST is @c false, and
*        prints a text version of @a TEST and a custom error message @a MSG.
*
* See ASSERT_MSG for more information on the parameter @a MSG.
*/
#define POSTCONDITION(TEST, MSG) \
	ASSERT_MSG_IMPL(TEST, "Postcondition failed: `" << #TEST \
		<< "` (" << MSG << ")")

/**
* @brief Aborts the program if the POSTCONDITION @a TEST evaluates to a null
*        pointer, and prints a text version of @a TEST and an error message.
*/
#define POSTCONDITION_NON_NULL(TEST) \
	POSTCONDITION(TEST, "expected a non-null pointer")

/**
* @brief Aborts the program with a failed postcondition and prints a custom
*        error message @a MSG.
*
* Example:
* @code
* POSTCONDITION_FAILED("statement " << stmt << doesn't exist");
* @endcode
*/
#define POSTCONDITION_FAILED(MSG) \
	ABORT_IMPL("Postcondition failed: " << MSG)

/**
* @brief Aborts the program if the invariant @a TEST is @c false, and
*        prints a text version of @a TEST and a custom error message @a MSG.
*
* See ASSERT_MSG for more information on the parameter @a MSG.
*/
#define INVARIANT(TEST, MSG) \
	ASSERT_MSG_IMPL(TEST, "Invariant failed: `" << #TEST \
		<< "` (" << MSG << ")")

/**
* @brief Aborts the program if the INVARIANT @a TEST evaluates to a null
*        pointer, and prints a text version of @a TEST and an error message.
*/
#define INVARIANT_NON_NULL(TEST) \
	INVARIANT(TEST, "expected a non-null pointer")

/**
* @brief Aborts the program with a failed invariant and prints a custom error
*        message @a MSG.
*
* Example:
* @code
* INVARIANT_FAILED("statement " << stmt << doesn't exist");
* @endcode
*/
#define INVARIANT_FAILED(MSG) \
	ABORT_IMPL("Invariant failed: " << MSG)

// In the google test framework, there already is a FAIL macro, so when we use
// this framework, use the FAIL macro from there.
#ifndef FAIL
/**
* @brief Aborts the program with the given message @a MSG.
*
* See ASSERT_MSG for more information on the parameter @a MSG.
*/
#define FAIL(MSG) \
	ABORT_IMPL("Fail (" << MSG << ")")
#endif

#else // #defined NDEBUG

// Death tests work only when assertions are enabled.
#define DEATH_TESTS_ENABLED 0

#define ABORT_IMPL(MSG) static_cast<void>(0)
#define ASSERT(TEST) static_cast<void>(0)
#define ASSERT_MSG(TEST, MSG) static_cast<void>(0)
#define ASSERT_MSG_IMPL(TEST, MSG) static_cast<void>(0)
#define PRECONDITION(TEST, MSG) static_cast<void>(0)
#define PRECONDITION_NON_NULL(TEST) static_cast<void>(0)
#define PRECONDITION_FAILED(MSG) static_cast<void>(0)
#define POSTCONDITION(TEST, MSG) static_cast<void>(0)
#define POSTCONDITION_NON_NULL(TEST) static_cast<void>(0)
#define POSTCONDITOON_FAILED(MSG) static_cast<void>(0)
#define INVARIANT(TEST, MSG) static_cast<void>(0)
#define INVARIANT_NON_NULL(TEST) static_cast<void>(0)
#define INVARIANT_FAILED(MSG) static_cast<void>(0)
// In the google test framework, there already is a FAIL macro, so when we use
// this framework, use the FAIL macro from there.
#ifndef FAIL
	#define FAIL(MSG) static_cast<void>(0)
#endif

#endif // #ifndef NDEBUG

/// @}

namespace retdec {
namespace llvmir2hll {

/**
* @brief Returns @a object.
*
* @tparam T Type of @a object.
*/
template<typename T>
T &id(T &object) {
	return object;
}

/// @name Dumps
/// @{

/**
* @brief Dumps the contents of the given container to standard error using the
*        given dumping function.
*
* @param[in] container Container whose contents has to be dumped.
* @param[in] dumpFunc Function that is called on every element. It has to
*                     return a dumpable value (e.g. a string).
* @param[in] delim Delimiter used to separate individual items.
* @param[in] end String to end the output with.
*
* @tparam Container Type of the container.
* @tparam DumpFunc Type of the dumping function.
*/
template<class Container, class DumpFunc>
void dump(const Container &container, DumpFunc dumpFunc, const std::string &delim = ", ",
		const std::string &end = "\n") {
	bool somethingEmitted = false;
	for (const auto &item : container) {
		if (somethingEmitted) {
			llvm::errs() << delim;
		}
		llvm::errs() << dumpFunc(item);
		somethingEmitted = true;
	}
	llvm::errs() << end;
}

/**
* @brief Dumps the contents of the given container to standard error.
*
* @param[in] container Container whose contents has to be dumped.
* @param[in] delim Delimiter used to separate individual items.
* @param[in] end String to end the output with.
*
* @tparam Container Type of the container.
*/
template<class Container>
void dump(const Container &container, const std::string &delim = ", ",
		const std::string &end = "\n") {
	dump(container, id<const typename Container::value_type>, delim, end);
}

/**
* @brief A dumping function which, given an object pointer, calls getName()
*        on it via @c ->.
*
* @tparam T Underlying type of @a object. Must have a <tt>std::string
*           getName()</tt> member function.
*/
template<class T>
std::string dumpFuncGetName(T object) {
	return object->getName();
}

/**
* @brief A dumping function which, given an object pointer, calls getTextRepr()
*        on it via @c ->.
*
* @tparam T Underlying type of @a object. Must have a <tt>std::string
*           getTextRepr()</tt> member function.
*/
template<class T>
std::string dumpFuncGetTextRepr(T object) {
	return object->getTextRepr();
}

/// @}

} // namespace llvmir2hll
} // namespace retdec

#endif
