/**
* @file include/retdec/llvmir2hll/graphs/cg/cg.h
* @brief A representation of a call graph (CG).
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CG_CG_H

#include <map>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class Function;
class Module;

/**
* @brief A representation of a call graph (CG).
*
* See http://en.wikipedia.org/wiki/Call_graph.
*
* Use CGBuilder to create instances of this class. Whenever the underlying
* module is changed in a way that would affect the validity of the generated
* CG, the CG has to be re-built.
*
* Instances of this class have reference object semantics.
*
* This class is not meant to be subclassed.
*/
class CG final: private retdec::utils::NonCopyable {
	friend class CGBuilder;

public:
	/**
	* @brief Information about called functions from a caller.
	*/
	class CalledFuncs {
	public:
		explicit CalledFuncs(ShPtr<Function> caller,
			bool callsOnlyDefinedFuncs = true,
			bool callsByPointer = false);

	public:
		/// Function that calls functions in @c callees. If it is a
		/// declaration, @c callees are empty.
		ShPtr<Function> caller;

		/// Functions that are called from @c caller (it may or may not contain
		/// indirectly called functions, see getCalledFuncs()).
		FuncSet callees;

		/// @c true if all called functions are defined, @c false otherwise
		/// (just declared functions are not considered defined).
		/// If @c caller is a declaration, this data member is set to @c true.
		bool callsOnlyDefinedFuncs;

		/// @c true if there are is a call by a pointer to a function, @c false
		/// otherwise.
		/// If @c caller is a declaration, this data member is set to @c false.
		bool callsByPointer;
	};

	/// Mapping of a caller into callees.
	using CallerCalleeMap = std::map<ShPtr<Function>, ShPtr<CalledFuncs>>;

	/// Callers iterator.
	using caller_iterator = CallerCalleeMap::const_iterator;

public:
	~CG();

	ShPtr<Module> getCorrespondingModule() const;
	ShPtr<CalledFuncs> getCalledFuncs(ShPtr<Function> func,
		bool includeIndirectCalls = false) const;

	/// @name Callers Accessors
	/// @{
	caller_iterator caller_begin() const;
	caller_iterator caller_end() const;
	/// @}

private:
	CG(ShPtr<Module> module);

	ShPtr<CalledFuncs> computeIndirectCalls(ShPtr<CalledFuncs> calledFuncs) const;

private:
	/// Module for which this call graph has been created.
	ShPtr<Module> module;

	/// Mapping of a caller into callees.
	CallerCalleeMap callerCalleeMap;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
