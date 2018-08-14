/**
* @file src/bin2llvmir/providers/names.cpp
* @brief Database of objects' names in binary.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;

namespace retdec {
namespace bin2llvmir {

//
//==============================================================================
// names::
//==============================================================================
//

namespace names {

std::string generateFunctionName(utils::Address a, bool ida)
{
	return ida
			? generatedFunctionPrefixIDA + a.toHexString()
			: generatedFunctionPrefix + a.toHexString();
}

std::string generateFunctionNameUnknown(utils::Address a, bool)
{
	return generatedFunctionPrefixUnk + a.toHexString();
}

std::string generateBasicBlockName(utils::Address a)
{
	return generatedBasicBlockPrefix + a.toHexString();
}

std::string generateTempVariableName(utils::Address a, unsigned cntr)
{
	return generatedTempVarPrefix + std::to_string(cntr) + "_" + a.toHexString();
}

std::string generateFunctionNameUndef(unsigned cntr)
{
	return generatedUndefFunctionPrefix + std::to_string(cntr);
}

std::string generateVtableName(utils::Address a)
{
	return generatedVtablePrefix + a.toHexString();
}

} // namespace names

//
//==============================================================================
// Name
//==============================================================================
//

Name::Name()
{

}

Name::Name(Config* c, const std::string& name, eType type, Lti* lti) :
		_name(normalizeNamePrefix(name)),
		_type(type)
{
	if (c->getConfig().architecture.isPic32())
	{
		fixPic32Mangling();
	}

	_inLti = lti->getLtiFunction(_name) != nullptr;
}

Name::operator std::string() const
{
	return getName();
}

Name::operator bool() const
{
	return _type != eType::INVALID;
}

bool Name::operator<(const Name& o) const
{
	if (_type == o._type)
	{
		// Can this even happen? Maybe it should not.
		//
		if (_name.empty())
		{
			return false;
		}
		else if (o._name.empty())
		{
			return true;
		}
		else if (_inLti)
		{
			return true;
		}
		else if (o._inLti)
		{
			return false;
		}
		// E.g. real case symbol table:
		// 0x407748 @ .text
		// 0x407748 @ _printf
		//
		else if (_name.front() == '.')
		{
			return false;
		}
		else if (o._name.front() == '.')
		{
			return true;
		}
		// Default.
		//
		else
		{
			return _name < o._name;
		}
	}
	else
	{
		return _type < o._type;
	}
}

const std::string& Name::getName() const
{
	return _name;
}

Name::eType Name::getType() const
{
	return _type;
}

void Name::fixPic32Mangling()
{
	if (_name.empty()) return;

	if (_name.find("_d") == 0)
	{
		_name = _name.substr(2);
	}
	else if (_name[0] == '_')
	{
		_name = _name.substr(1);
	}

	if (_name.empty()) return;

	if (_name.find("_cd") != std::string::npos)
	{
		_name = _name.substr(0, _name.find("_cd"));
	}
	else if (_name.find("_gG") != std::string::npos)
	{
		_name = _name.substr(0, _name.find("_gG"));
	}
	else if (_name.find("_eE") != std::string::npos)
	{
		_name = _name.substr(0, _name.find("_eE"));
	}
	else if (_name.find("_fF") != std::string::npos)
	{
		_name = _name.substr(0, _name.find("_fF"));
	}
	else if (retdec::utils::endsWith(_name, "_s"))
	{
		_name.pop_back();
		_name.pop_back();
	}
}

//
//==============================================================================
// Names
//==============================================================================
//

Name Names::_emptyName;

/**
 * Name is not added if \p name is empty.
 * \return \c True if name added, \c false otherwise.
 */
bool Names::addName(
		Config* c,
		const std::string& name,
		Name::eType type,
		Lti* lti)
{
	if (name.empty())
	{
		return false;
	}

	_names.emplace(c, name, type, lti);

	return true;
}

const Name& Names::getPreferredName()
{
	return _names.empty() ? _emptyName : *_names.begin();
}

Names::iterator Names::begin()
{
	return _names.begin();
}

Names::iterator Names::end()
{
	return _names.end();
}

std::size_t Names::size() const
{
	return _names.size();
}

bool Names::empty() const
{
	return _names.empty();
}

//
//==============================================================================
// NameContainer
//==============================================================================
//

NameContainer::NameContainer(
		llvm::Module* m,
		Config* c,
		DebugFormat* d,
		FileImage* i,
		demangler::CDemangler* dm,
		Lti* lti)
		:
		_module(m),
		_config(c),
		_debug(d),
		_image(i),
		_demangler(dm),
		_lti(lti)
{
	initFromConfig();
	initFromDebug();
	initFromImage();
}

/**
 * Name is not added if \p a is undefined or \p name is empty.
 * \return \c True if name added, \c false otherwise.
 */
bool NameContainer::addNameForAddress(
		retdec::utils::Address a,
		const std::string& name,
		Name::eType type,
		Lti* lti)
{
	if (a.isUndefined() || name.empty())
	{
		return false;
	}

	auto& ns = _data[a];
	return ns.addName(_config, name, type, lti ? lti : _lti);
}

const Names& NameContainer::getNamesForAddress(retdec::utils::Address a)
{
	return _data[a];
}

const Name& NameContainer::getPreferredNameForAddress(retdec::utils::Address a)
{
	return _data[a].getPreferredName();
}

void NameContainer::initFromConfig()
{
	addNameForAddress(
			_config->getConfig().getEntryPoint(),
			names::entryPointName,
			Name::eType::ENTRY_POINT);

	for (auto& p : _config->getConfig().functions)
	{
		addNameForAddress(
				p.second.getStart(),
				p.second.getName(),
				Name::eType::CONFIG_FUNCTION);
	}

	for (auto& p : _config->getConfig().globals)
	{
		addNameForAddress(
				p.second.getStorage().getAddress(),
				p.second.getName(),
				Name::eType::CONFIG_GLOBAL);
	}

	for (auto& s : _config->getConfig().segments)
	{
		addNameForAddress(
				s.getStart(),
				s.getName(),
				Name::eType::CONFIG_SEGMENT);
	}
}

void NameContainer::initFromDebug()
{
	if (_debug == nullptr)
	{
		return;
	}

	for (const auto& p : _debug->functions)
	{
		addNameForAddress(
				p.first,
				p.second.getName(),
				Name::eType::DEBUG_FUNCTION);
	}

	for (const auto& p : _debug->globals)
	{
		Address addr;
		if (p.second.getStorage().isMemory(addr))
		{
			addNameForAddress(
					addr,
					p.second.getName(),
					Name::eType::DEBUG_GLOBAL);
		}
	}
}

void NameContainer::initFromImage()
{
	if (auto* impTbl = _image->getFileFormat()->getImportTable())
	for (const auto &imp : *impTbl)
	{
		Address addr = imp->getAddress();
		std::string name = imp->getName();
		unsigned long long ord = 0;
		bool ordOk = false;

		if (name.empty())
		{
			auto libN = impTbl->getLibrary(imp->getLibraryIndex());
			std::transform(libN.begin(), libN.end(), libN.begin(), ::tolower);
			retdec::utils::removeSuffix(libN, ".dll");

			ordOk = imp->getOrdinalNumber(ord);
			if (ordOk)
			{
				name = getNameFromImportLibAndOrd(libN, ord);
			}
		}

		if (name.empty() && ordOk)
		{
			name = names::generatedImportPrefix + std::to_string(ord);

			addNameForAddress(
					addr,
					name,
					Name::eType::IMPORT_GENERATED);
		}
		else
		{
			addNameForAddress(
					addr,
					name,
					Name::eType::IMPORT);
		}
	}

	if (auto *exTbl = _image->getFileFormat()->getExportTable())
	for (const auto &exp : *exTbl)
	{
		addNameForAddress(
				exp.getAddress(),
				exp.getName(),
				Name::eType::EXPORT);
	}

	for (const auto* t : _image->getFileFormat()->getSymbolTables())
	for (const auto& s : *t)
	{
		unsigned long long a = 0;
		if (s->getRealAddress(a))
		{
			Name::eType t = Name::eType::SYMBOL_OTHER;
			switch (s->getUsageType())
			{
				case retdec::fileformat::Symbol::UsageType::FUNCTION:
					t = Name::eType::SYMBOL_FUNCTION;
					break;
				case retdec::fileformat::Symbol::UsageType::OBJECT:
					t = Name::eType::SYMBOL_OBJECT;
					break;
				case retdec::fileformat::Symbol::UsageType::FILE:
					t = Name::eType::SYMBOL_FILE;
					break;
				default:
					t = Name::eType::SYMBOL_OTHER;
					break;
			}

			if (_config->getConfig().architecture.isArmOrThumb() && a % 2)
			{
				a -= 1;
			}

			addNameForAddress(a, s->getName(), t);
		}
	}

	if (_image->getFileFormat())
	{
		unsigned long long ep = 0;
		if (_image->getFileFormat()->getEpAddress(ep))
		{
			if (_config->getConfig().architecture.isArmOrThumb() && ep % 2)
			{
				ep -= 1;
			}

			addNameForAddress(
					ep,
					names::entryPointName,
					Name::eType::ENTRY_POINT);
		}
	}

	// TODO: if we add this here, we get few more names, but these names may
	// be used for functions. Which we do not want - we prefer names like
	// function_<addr> to section names for functions.
	// If we add this here, functions need some kind of cutoff not to use
	// names below certain source.
	//
//	for (auto& seg : _image->getSegments())
//	{
//		addNameForAddress(
//				seg->getAddress(),
//				seg->getName(),
//				Name::eType::ENTRY_POINT);
//	}
}

std::string NameContainer::getNameFromImportLibAndOrd(
		const std::string& libName,
		int ord)
{
	auto it = _dllOrds.find(libName);
	if (it == _dllOrds.end())
	{
		if (!loadImportOrds(libName))
		{
			return std::string();
		}
		else
		{
			it = _dllOrds.find(libName);
		}
	}

	const ImportOrdMap& ords = it->second;
	auto ordIt = ords.find(ord);
	if (ordIt != ords.end())
	{
		return ordIt->second;
	}

	return std::string();
}

bool NameContainer::loadImportOrds(const std::string& libName)
{
	auto dir = _config->getConfig().parameters.getOrdinalNumbersDirectory();
	auto filePath = dir + "/" + libName + ".ord";

	std::ifstream inputFile;
	inputFile.open(filePath);
	if (!inputFile)
	{
		return false;
	}

	std::string line;
	ImportOrdMap ordMap;
	while (!getline(inputFile, line).eof())
	{
		std::stringstream ordDecl(line);

		int ord = -1;
		std::string funcName;
		ordDecl >> ord >> funcName;
		if (ord >= 0)
		{
			ordMap[ord] = funcName;
		}
	}
	inputFile.close();
	_dllOrds.emplace(libName, ordMap);

	return true;
}

//
//==============================================================================
// NameContainer
//==============================================================================
//

std::map<llvm::Module*, NameContainer> NamesProvider::_module2names;

NameContainer* NamesProvider::addNames(
		llvm::Module* m,
		Config* c,
		DebugFormat* d,
		FileImage* i,
		demangler::CDemangler* dm,
		Lti* lti)
{
	// Debug info may not be present -> \p d can be nullptr.
	if (m == nullptr
			|| c == nullptr
			|| i == nullptr
			|| dm == nullptr)
	{
		return nullptr;
	}

	auto p = _module2names.emplace(m, NameContainer(m, c, d, i, dm, lti));
	return &p.first->second;
}

NameContainer* NamesProvider::getNames(llvm::Module* m)
{
	auto f = _module2names.find(m);
	return f != _module2names.end() ? &f->second : nullptr;
}

bool NamesProvider::getNames(llvm::Module* m, NameContainer*& names)
{
	names = getNames(m);
	return names != nullptr;
}

void NamesProvider::clear()
{
	_module2names.clear();
}

} // namespace bin2llvmir
} // namespace retdec
