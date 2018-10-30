/**
* @file include/retdec/bin2llvmir/providers/names.h
* @brief Database of objects' names in binary.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_NAMES_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_NAMES_H

#include <map>
#include <set>

#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/utils/address.h"

namespace retdec {
namespace bin2llvmir {

namespace names {

const std::string entryPointName               = "entry_point";
const std::string generatedImportPrefix        = "imported_function_ord_";
const std::string generatedFunctionPrefix      = "function_";
const std::string generatedFunctionPrefixIDA   = "ida_";
const std::string generatedFunctionPrefixUnk   = "unknown_";
const std::string generatedTempVarPrefix       = "v";
const std::string generatedBasicBlockPrefix    = "dec_label_pc_";
const std::string generatedUndefFunctionPrefix = "__decompiler_undefined_function_";
const std::string generatedVtablePrefix        = "vtable_";
const std::string asm2llvmGv                   = "_asm_program_counter";
const std::string pseudoCallFunction           = "__pseudo_call";
const std::string pseudoReturnFunction         = "__pseudo_return";
const std::string pseudoBranchFunction         = "__pseudo_branch";
const std::string pseudoCondBranchFunction     = "__pseudo_cond_branch";
const std::string pseudoX87dataLoadFunction    = "__frontend_reg_load.fpr";
const std::string pseudoX87tagLoadFunction     = "__frontend_reg_load.fpu_tag";
const std::string pseudoX87dataStoreFunction   = "__frontend_reg_store.fpr";
const std::string pseudoX87tagStoreFunction    = "__frontend_reg_store.fpu_tag";

std::string generateFunctionName(utils::Address a, bool ida = false);
std::string generateFunctionNameUnknown(utils::Address a, bool ida = false);
std::string generateBasicBlockName(utils::Address a);
std::string generateTempVariableName(utils::Address a, unsigned cntr);
std::string generateFunctionNameUndef(unsigned cntr);
std::string generateVtableName(utils::Address a);

} // namespace names

/**
 * Representation of one name.
 */
class Name
{
	public:
		/**
		 * Name type and its priority.
		 * Lower number -> higher priority.
		 */
		enum class eType
		{
			// This is not set automatically in this module -> for manual use
			// only - when some bin2llvmir part wants to really make sure
			// a certain name is used.
			HIGHEST_PRIORITY = 0,
			// Stuff from config.
			CONFIG_FUNCTION,
			CONFIG_GLOBAL,
			CONFIG_SEGMENT,
			//
			DEBUG_FUNCTION,
			DEBUG_GLOBAL,
			// Stuff from file image.
			IMPORT,
			EXPORT,
			SYMBOL_FUNCTION,
			SYMBOL_OBJECT,
			SYMBOL_FILE,
			SYMBOL_OTHER,
			STATIC_CODE,
			ENTRY_POINT,
			SECTION,
			IMPORT_GENERATED,
			// This is not set automatically in this module -> for manual use
			// only - when some bin2llvmir part wants to use some name if
			// nothing better is available.
			LOWEST_PRIORITY,
			// Invalid - somethingwent wrong, do not use this entry.
			INVALID,
		};

	public:
		Name();
		Name(Config* c, const std::string& name, eType type, Lti* lti = nullptr);

		operator std::string() const;
		explicit operator bool() const;
		bool operator<(const Name& o) const;

		const std::string& getName() const;
		eType getType() const;

	private:
		void fixPic32Mangling();

	private:
		std::string _name;
		eType _type = eType::INVALID;
		bool _inLti = false;
};

/**
 * Representation of all the names for one object.
 */
class Names
{
	public:
		using iterator = typename std::set<Name>::iterator;

	public:
		bool addName(
				Config* c,
				const std::string& name,
				Name::eType type,
				Lti* lti = nullptr);

		const Name& getPreferredName();

		iterator begin();
		iterator end();
		std::size_t size() const;
		bool empty() const;

	private:
		std::set<Name> _names;
		static Name _emptyName;
};

/**
 * Names container.
 */
class NameContainer
{
	public:
		NameContainer(
				llvm::Module* m,
				Config* c,
				DebugFormat* d,
				FileImage* i,
				demangler::CDemangler* dm,
				Lti* lti = nullptr);

		bool addNameForAddress(
				retdec::utils::Address a,
				const std::string& name,
				Name::eType type,
				Lti* lti = nullptr);

		const Names& getNamesForAddress(retdec::utils::Address a);
		const Name& getPreferredNameForAddress(retdec::utils::Address a);

	private:
		void initFromConfig();
		void initFromDebug();
		void initFromImage();

		std::string getNameFromImportLibAndOrd(
				const std::string& libName,
				int ord);
		bool loadImportOrds(const std::string& libName);

	private:
		/// <ordinal number, function name>
		using ImportOrdMap = std::map<int, std::string>;

	private:
		llvm::Module* _module = nullptr;
		Config* _config = nullptr;
		DebugFormat* _debug = nullptr;
		FileImage* _image = nullptr;
		demangler::CDemangler* _demangler = nullptr;
		Lti* _lti = nullptr;

		std::map<retdec::utils::Address, Names> _data;
		/// <library name without suffix ".dll", map with ordinals>
		std::map<std::string, ImportOrdMap> _dllOrds;
};

/**
 * Names provider.
 */
class NamesProvider
{
	public:
		static NameContainer* addNames(
				llvm::Module* m,
				Config* c,
				DebugFormat* d,
				FileImage* i,
				demangler::CDemangler* dm,
				Lti* lti);
		static NameContainer* getNames(llvm::Module* m);
		static bool getNames(llvm::Module* m, NameContainer*& names);
		static void clear();

	private:
		static std::map<llvm::Module*, NameContainer> _module2names;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
