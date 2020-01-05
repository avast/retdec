/**
* @file include/retdec/llvmir2hll/var_renamer/var_renamer.h
* @brief A base class for all variable renamers.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMER_H
#define RETDEC_LLVMIR2HLL_VAR_RENAMER_VAR_RENAMER_H

#include <map>
#include <string>

#include "retdec/llvmir2hll/support/visitors/ordered_all_visitor.h"
#include "retdec/llvmir2hll/var_name_gen/var_name_gen.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class for all variable renamers.
*
* This class should be used as a base class for all variable renamers.
*
* To implement a new renamer:
*  - create a new class that subclasses this class (you can copy and edit an
*    existing renamer)
*  - override the needed virtual methods (if you want to simply just rename
*    variables differently, it suffices to override renameGlobalVar(),
*    renameFuncParam(), and renameFuncLocalVar())
*  - create a static create() function and register the renamer at
*    VarRenamerFactory (see the implementation of existing subclasses)
*
* The following renames are done by default:
*  (1) If a function has assigned a real name, it is used.
*
*  (2) If a variable has assigned a name from debug information, it is used.
*
*  (3) Other variables are assigned a name by using the passed variable name
*      generator.
*
* Notes:
*  - use assignName() to assign a new to a variable (it not only checks that
*    that the assigned name would not result in a name clash but also update data
*    members, such as @c renamedVars)
*  - apart from giving them real names, function names should not be changed
*
* Instances of this class have reference object semantics.
*/
class VarRenamer: protected OrderedAllVisitor {
public:
	/**
	* @brief Returns the ID of the renamer.
	*/
	virtual std::string getId() const = 0;

	void renameVars(Module* module);

protected:
	VarRenamer(VarNameGen* varNameGen, bool useDebugNames = true);

	void assignName(Variable* var, const std::string &name,
		Function* func = nullptr);
	void assignNameFromDebugInfoIfAvail(Variable* var,
		Function* func = nullptr);
	bool isGlobalVar(Variable* var) const;
	bool isFunc(Variable* var) const;
	bool hasBeenRenamed(Variable* var) const;
	bool nameExists(const std::string &name,
		Function* func = nullptr) const;
	Function* getFuncByName(const std::string &name) const;

	virtual void doVarsRenaming();

	/// @name Renaming Using Debug Names
	/// @{
	virtual void renameUsingDebugNames();
	/// @}

	/// @name Renaming of Global Variables
	/// @{
	virtual void renameGlobalVars();
	virtual void renameGlobalVar(Variable* var);
	/// @}

	/// @name Renaming of Variables in Functions
	/// @{
	virtual void renameVarsInFuncs();
	virtual void renameVarsInFunc(Function* func);
	virtual void renameFuncParam(Variable* var,
		Function* func);
	virtual void renameFuncLocalVar(Variable* var,
		Function* func);
	/// @}

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(Variable* var) override;
	/// @}

protected:
	/// Mapping of a function into a set of strings.
	using FuncStringSetMap = std::map<Function*, StringSet>;

	/// Mapping of a function's name into the function.
	using FuncByNameMap = std::map<std::string, Function*>;

protected:
	/// Used generator of variable names.
	VarNameGen* varNameGen = nullptr;

	/// Should we use variable names from debugging information?
	bool useDebugNames;

	/// Module in which the variables are being renamed.
	Module* module = nullptr;

	/// Global variables in @c module. This is here to speedup the renaming. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;

	/// Mapping of function names into functions.
	/// This is here to speedup the renaming (@c module->getFuncByName() is too
	/// slow, I have profiled it).
	FuncByNameMap funcsByName;

	/// Variables which have already been renamed.
	VarSet renamedVars;

	/// Assigned names of global variables.
	StringSet globalVarsNames;

	/// Assigned names to local variables of all functions in the module,
	/// including function parameters.
	///
	/// To get the set of names assigned to the current function @c func,
	/// use @c localVarsNames[func].
	FuncStringSetMap localVarsNames;

	/// The currently visited function.
	Function* currFunc = nullptr;

private:
	void storeFuncsByName();
	std::string ensureNameUniqueness(Variable* var,
		const std::string &name, Function* func = nullptr);
	std::string generateUniqueName(Variable* var,
		const std::string &name, Function* func = nullptr);
	void assignRealNamesToFuncs();
	void assignNameToFunc(Function* func, const std::string &newName);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
