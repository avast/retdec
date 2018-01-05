/**
* @file include/retdec/utils/scope_exit.h
* @brief Macro for performing actions when the current block exits.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*
* The code is based on the following presentation:
* CppCon 2015: Andrei Alexandrescu: "Declarative Control Flow"
* (https://www.youtube.com/watch?v=WjTrfoiB0MQ).
*/

#ifndef RETDEC_UTILS_SCOPE_EXIT_H
#define RETDEC_UTILS_SCOPE_EXIT_H

// The _IMPL macro is needed to force the expansion of s1 and s2.
#define SCOPE_EXIT_CONCATENATE_IMPL(s1, s2) s1##s2
#define SCOPE_EXIT_CONCATENATE(s1, s2) SCOPE_EXIT_CONCATENATE_IMPL(s1, s2)

#define SCOPE_EXIT_ANONYMOUS_VARIABLE \
	SCOPE_EXIT_CONCATENATE(SCOPE_EXIT_ANONYMOUS_VARIABLE_, __LINE__)

/**
* @brief Macro for performing actions when the current block exits.
*
* Usage:
* @code
* SCOPE_EXIT {
*     stmt1;
*     stmt2;
*     ...
* };
* @endcode
* <b>Important:</b> Do not forget the trailing semicolon!
*
* The above statements are executed when the current block exits, either
* normally or via an exception. All variables from outer blocks are
* automatically captured by reference.
*
* This macro is useful for performing automatic cleanup actions, mainly when
* there is no RAII support.
*/
#define SCOPE_EXIT \
	const auto SCOPE_EXIT_ANONYMOUS_VARIABLE = \
		retdec::utils::ScopeExitGuardHelper() + [&]()

namespace retdec {
namespace utils {

// Calls the given function in its destructor.
template<typename Function>
class ScopeExitGuard {
public:
	ScopeExitGuard(Function &&f):
		f(std::forward<Function>(f)) {}
	~ScopeExitGuard() { f(); }

private:
	Function f;
};

// A helper type that allows the main macro to have a nice syntax.
struct ScopeExitGuardHelper {};

template<typename Function>
auto operator+(ScopeExitGuardHelper /* unused */, Function &&f) {
	return ScopeExitGuard<Function>(std::forward<Function>(f));
}

} // namespace utils
} // namespace retdec

#endif
