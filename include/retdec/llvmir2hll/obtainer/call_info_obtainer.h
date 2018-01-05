/**
* @file include/retdec/llvmir2hll/obtainer/call_info_obtainer.h
* @brief A base class of all obtainers of information about functions and
*        function calls.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINER_H
#define RETDEC_LLVMIR2HLL_OBTAINER_CALL_INFO_OBTAINER_H

#include <stack>
#include <string>

#include "retdec/llvmir2hll/graphs/cg/cg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class CFGBuilder;
class CallExpr;
class Function;
class Module;
class ValueAnalysis;

/**
* @brief Base class for all classes storing information about a function call.
*
* Instances of this class have reference object semantics.
*/
class CallInfo: private retdec::utils::NonCopyable {
	friend class CallInfoObtainer;

public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~CallInfo() = 0;

	ShPtr<CallExpr> getCall() const;

	/**
	* @brief Returns @c true if @a var is never read in the call, @c false
	*        otherwise.
	*/
	virtual bool isNeverRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if @a var may be read in the call, @c false
	*        otherwise.
	*/
	virtual bool mayBeRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if @a var is always read in the call, @c false
	*        otherwise.
	*
	* "Always read" means that every time the function is called, @a var
	* is read.
	*/
	virtual bool isAlwaysRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if there is no assign into @a var in the call, @c
	*        false otherwise.
	*/
	virtual bool isNeverModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var may be changed in the call,
	*        @c false otherwise.
	*/
	virtual bool mayBeModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var is always changed in
	*        the call, @c false otherwise.
	*
	* "Always changed" means that every time the function is called, @a var
	* has a new assigned value. The new value may, however, be the same as the
	* old value.
	*/
	virtual bool isAlwaysModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var is never changed in the
	*        call, @c false otherwise.
	*
	* "Never changed" means that a new value may be assigned to @a var in the
	* call, but when the called function returns, the value of @a var is always
	* its original value.
	*/
	virtual bool valueIsNeverChanged(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the given variable is modified prior to being
	*        read in the call, @c false otherwise.
	*
	* When this function returns @c true, it doesn't mean that the variable is
	* actually read or modified in the call. It only means that if the variable
	* is read in the call, then it has been assigned a value before this read.
	*/
	virtual bool isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const = 0;

protected:
	explicit CallInfo(ShPtr<CallExpr> call);

protected:
	/// Function call for which this piece of information is computed.
	ShPtr<CallExpr> call;
};

/**
* @brief Base class for all classes storing information about a function.
*
* Instances of this class have reference object semantics.
*/
class FuncInfo: private retdec::utils::NonCopyable {
	friend class CallInfoObtainer;

public:
	// It needs to be public so it can be called in ShPtr's destructor.
	virtual ~FuncInfo() = 0;

	ShPtr<Function> getFunc() const;

	/**
	* @brief Returns @c true if @a var is never read in the function, @c false
	*        otherwise.
	*/
	virtual bool isNeverRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if @a var may be read in the function, @c false
	*        otherwise.
	*/
	virtual bool mayBeRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if @a var is always read in the function, @c false
	*        otherwise.
	*
	* "Always read" means that every time the function is called, @a var is
	* read.
	*/
	virtual bool isAlwaysRead(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if there is no assign into @a var in the function,
	*        @c false otherwise.
	*/
	virtual bool isNeverModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var may be changed in the
	*        function, @c false otherwise.
	*/
	virtual bool mayBeModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var is always changed in
	*        the function, @c false otherwise.
	*
	* "Always changed" means that every time the function is called, @a var has
	* a new assigned value. The new value may, however, be the same as the old
	* value.
	*/
	virtual bool isAlwaysModified(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the value of @a var is never changed in the
	*        call, @c false otherwise.
	*
	* "Never changed" means that a new value may be assigned to @a var in the
	* call, but when the called function returns, the value of @a var is always
	* its original value.
	*/
	virtual bool valueIsNeverChanged(ShPtr<Variable> var) const = 0;

	/**
	* @brief Returns @c true if the given variable is modified prior to being
	*        read in the function, @c false otherwise.
	*
	* When this function returns @c true, it doesn't mean that the variable is
	* actually read or modified in the function. It only means that if the
	* variable is read in the function, then it has been assigned a value
	* before this read.
	*/
	virtual bool isAlwaysModifiedBeforeRead(ShPtr<Variable> var) const = 0;

protected:
	explicit FuncInfo(ShPtr<Function> func);

protected:
	/// Function for which this piece of information is computed.
	ShPtr<Function> func;
};

/**
* @brief A base class of all obtainers of information about functions and
*        function calls.
*
* Every function call information obtainer should subclass this class and
* override getCallInfo() and getFuncInfo(). Furthermore, also CallInfo should
* be subclassed and this subclass should have the concrete obtainer as a friend
* so it can set its values (remember that in C++, friendship is not inherited).
* If the obtainer overrides init(), then it has to call
* CallInfoObtainer::init().
*
* Every time an instance of this class (or its subclass) is created or the
* underlying module is changed in a way that affects the call graph, the init()
* member function has to be called.
*
* Instances of this class have reference object semantics.
*/
class CallInfoObtainer: public SharableFromThis<CallInfoObtainer>,
	private retdec::utils::NonCopyable {
public:
	virtual ~CallInfoObtainer() = 0;

	ShPtr<CG> getCG() const;
	ShPtr<CFG> getCFGForFunc(ShPtr<Function> func) const;

	virtual void init(ShPtr<CG> cg, ShPtr<ValueAnalysis> va);
	virtual bool isInitialized() const;

	/**
	* @brief Returns the ID of the obtainer.
	*/
	virtual std::string getId() const = 0;

	/**
	* @brief Computes and returns information about the given function call
	*        which occurs in @a caller.
	*
	* @par Preconditions
	*  - the call obtainer has been initialized using init()
	*  - the given call and caller exist in the module
	*/
	virtual ShPtr<CallInfo> getCallInfo(ShPtr<CallExpr> call,
		ShPtr<Function> caller) = 0;

	/**
	* @brief Computes and returns information about the given function.
	*
	* @par Preconditions
	*  - the call obtainer has been initialized using init()
	*  - the given function exists in the module
	*/
	virtual ShPtr<FuncInfo> getFuncInfo(ShPtr<Function> func) = 0;

protected:
	/// Set of sets of functions.
	using FuncSetSet = std::set<FuncSet>;

	/**
	* @brief Represents an order in which FuncInfos should be computed.
	*
	* To compute (create) an instance of this class, use
	* getFuncInfoCompOrder().
	*
	* Example: Consider the following call graph:
	* @code
	*       1     5
	*      / \    ^
	*     v   v   |
	* 6-->2-->3-->4
	* @endcode
	*
	* Then, getFuncInfoCompOrder() returns an instance of this class with the
	* following data:
	* @code
	* order = <5,4,3,6>
	* sccs = {{1,2,3}}
	* @endcode
	*
	* It means that the concrete obtainer should first compute the FuncInfo for
	* 5, then for 4, then for the strongly connected component (SCC, see
	* http://en.wikipedia.org/wiki/Strongly_connected_component) which contain
	* 3, and then for 6. Note that in @c order, instead of 3, there may be 2 or
	* 1 (since all of them form an SCC, it doesn't matter which of them appears
	* in @c order).
	*
	* A single function is not considered to be an SCC unless it contains a
	* call to itself.
	*
	* Functions which haven't been defined (only declared) are also included
	* into the order.
	*/
	class FuncInfoCompOrder {
	public:
		void debugPrint() const;

	public:
		/// An order in which FuncInfos should be computed.
		FuncVector order;

		/// SCCs in the call graph.
		FuncSetSet sccs;
	};

	/// Mapping of a function into its CFG.
	using FuncCFGMap = std::map<ShPtr<Function>, ShPtr<CFG>>;

protected:
	CallInfoObtainer();

	ShPtr<FuncInfoCompOrder> getFuncInfoCompOrder(ShPtr<CG> cg);

protected:
	/// The current module.
	ShPtr<Module> module;

	/// Call graph of the current module.
	ShPtr<CG> cg;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Mapping of a function into its CFG.
	FuncCFGMap funcCFGMap;

	/// The used builder of CFGs.
	ShPtr<CFGBuilder> cfgBuilder;

private:
	/**
	* @brief A computation of strongly connected components (SCCs) from a call
	*        graph.
	*
	* See http://en.wikipedia.org/wiki/Strongly_connected_component for a
	* description of an SCC.
	*
	* The used algorithm is the Tarjan's strongly connected components
	* algorithm, see
	* http://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
	*
	* Instances of this class have reference object semantics.
	*/
	class SCCComputer: private retdec::utils::NonCopyable {
	public:
		~SCCComputer();

		static FuncSetSet computeSCCs(ShPtr<CG> cg);

	private:
		/// Stack of CalledFuncs.
		using CalledFuncStack = std::stack<ShPtr<CG::CalledFuncs>>;

		/**
		* @brief Information about a CalledFunc from the SCC algorithm.
		*/
		struct CalledFuncInfo {
			CalledFuncInfo(): onStack(false), index(-1), lowlink(0) {}

			bool onStack;
			int index;
			int lowlink;
		};

		/// Mapping of a CalledFunc into its information.
		using CalledFuncInfoMap = std::map<ShPtr<CG::CalledFuncs>, CalledFuncInfo>;

	private:
		SCCComputer(ShPtr<CG> cg);
		void visit(ShPtr<CG::CalledFuncs> calledFunc,
			CalledFuncInfo &calledFuncInfo);
		FuncSetSet findSCCs();

	private:
		/// Call graph of the current module.
		ShPtr<CG> cg;

		/// The 'index' variable from the SCC algorithm.
		int index;

		/// The set of computed SCCs.
		FuncSetSet sccs;

		/// The currently computed SCC.
		FuncSet currentSCC;

		/// The 'stack' variable from the SCC algorithm.
		CalledFuncStack stack;

		/// Information about every CalledFunc.
		CalledFuncInfoMap calledFuncInfoMap;
	};

	/**
	* @brief An SCC with a represent.
	*/
	struct SCCWithRepresent {
		SCCWithRepresent(FuncSet scc, ShPtr<Function> represent):
			scc(scc), represent(represent) {}

		FuncSet scc;
		ShPtr<Function> represent;
	};

private:
	FuncSetSet computeSCCs();
	bool callsJustComputedFuncs(ShPtr<Function> func,
		const FuncSet &computedFuncs) const;
	SCCWithRepresent findNextSCC(const FuncSetSet &sccs,
		const FuncSet &computedFuncs, const FuncSet &remainingFuncs) const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
