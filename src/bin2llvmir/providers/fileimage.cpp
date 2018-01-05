/**
 * @file src/bin2llvmir/providers/fileimage.cpp
 * @brief File image provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/global_var.h"
#include "retdec/bin2llvmir/utils/type.h"
#include "retdec/loader/image_factory.h"
#include "retdec/loader/loader/raw_data/raw_data_image.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  FileImage
//=============================================================================
//

FileImage::FileImage(
		llvm::Module* m,
		const std::string& path,
		Config* config)
		:
		FileImage(
				m,
				retdec::loader::createImage(path, &config->getConfig()),
				config)
{

}

FileImage::FileImage(
		llvm::Module* m,
		const std::shared_ptr<retdec::fileformat::FileFormat>& ff,
		Config* config)
		:
		FileImage(
				m,
				retdec::loader::createImage(ff),
				config)
{

}

FileImage::FileImage(
		llvm::Module* m,
		std::unique_ptr<retdec::loader::Image> img,
		Config* config)
		:
		_module(m),
		_image(std::move(img))
{
	if (_image == nullptr)
	{
		_image.reset();
		// && !path.empty() ???
		throw std::runtime_error("Failed to load input file");
		return;
	}

	_image->getFileFormat()->initFromConfig(config->getConfig());
	if (auto* imgRaw = dynamic_cast<retdec::loader::RawDataImage*>(
			_image.get()))
	{
		imgRaw->reload();
	}

	if (_image->getSegments().empty()
			|| _image->getByteLength() == 0
			|| _image->getBytesPerWord() == 0
			|| _image->getWordLength() == 0)
	{
		throw std::runtime_error("Missing basic info about input file"
				" -> there can be no decompilation");
	}
}

bool FileImage::isOk() const
{
	return _image != nullptr;
}

retdec::loader::Image* FileImage::getImage()
{
	return _image.get();
}

retdec::fileformat::FileFormat* FileImage::getFileFormat()
{
	return _image->getFileFormat();
}

ConstantInt* FileImage::getConstantInt(
		IntegerType* t,
		retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	std::uint64_t v = 0;
	auto s = getTypeByteSizeInBinary(_module, t);
	return _image->getXByte(addr, s, v) ? ConstantInt::get(t, v) : nullptr;
}

llvm::ConstantInt* FileImage::getConstantDefault(retdec::utils::Address addr)
{
	return getConstantInt(getDefaultType(_module), addr);
}

llvm::Constant* FileImage::getConstantHalf(retdec::utils::Address addr)
{
	return getConstantFloat(addr);
}

llvm::Constant* FileImage::getConstantFloat(retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	float v = 0.0;
	auto* t = Type::getFloatTy(_module->getContext());
	return _image->getFloat(addr, v) ? ConstantFP::get(t, v) : nullptr;
}

llvm::Constant* FileImage::getConstantDouble(retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	double v = 0.0;
	auto* t = Type::getDoubleTy(_module->getContext());
	return _image->getDouble(addr, v) ? ConstantFP::get(t, v) : nullptr;
}

llvm::Constant* FileImage::getConstantLongDouble(retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	long double v = 0.0;
	auto* t = Type::getX86_FP80Ty(_module->getContext());
	auto b = _image->get10Byte(addr, v);
	std::stringstream ss;
	ss << v;
	return b ? ConstantFP::get(t, StringRef(ss.str().c_str())) : nullptr;
}

llvm::Constant* FileImage::getConstantCharPointer(retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	std::string str;
	if (_image->getNTBS(addr, str))
	{
		auto sc = ConstantDataArray::getString(
				_module->getContext(),
				str);

		// We need a global variable of type [N x i8*] so we can convert
		// it to i8* constant.
		// This is a helper global variable just to make a conversion,
		// we do not store info about it in config or anywhere else.
		//
		auto* gv = new GlobalVariable(
				*_module,
				sc->getType(),
				true, // constant
				GlobalValue::ExternalLinkage,
				sc);

		return convertConstantToType(
				gv,
				getCharPointerType(_module->getContext()));
	}
	else
	{
		return nullptr;
	}
}

llvm::Constant* FileImage::getConstantCharArrayNice(
		retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	std::string str;
	if (_image->getNTBS(addr, str) && retdec::utils::isNiceString(str, 1.0))
	{
		return ConstantDataArray::getString(_module->getContext(), str);
	}
	else
	{
		return nullptr;
	}
}

/**
 * TODO: we should get existing or create a new global variable
 * on referenced address (if valid). Then we could probably return this
 * global var as constant
 */
llvm::Constant* FileImage::getConstantPointer(
		llvm::PointerType* type,
		retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}

	std::uint64_t v = 0;
	if (_image->getWord(addr, v))
	{
		auto* dt = getDefaultType(_module);
		auto* ci = ConstantInt::get(dt, v);
		return ConstantExpr::getIntToPtr(ci, type);;
	}
	else
	{
		return nullptr;
	}
}

llvm::Constant* FileImage::getConstantStruct(
		llvm::StructType* type,
		retdec::utils::Address addr)
{
	size_t offset = 0;
	std::vector<Constant*> vc;
	for (auto* e : type->elements())
	{
		auto* ec = getConstant(
				e,
				addr + offset);

		if (ec == nullptr)
			return nullptr;

		offset += getTypeByteSizeInBinary(_module, e);
		vc.push_back(ec);
	}

	return ConstantStruct::get(type, vc);
}

llvm::Constant* FileImage::getConstantArray(
		llvm::ArrayType* type,
		retdec::utils::Address addr)
{
	std::vector<Constant*> vc;
	size_t offset = 0;
	auto elemNum = type->getNumElements();
	auto* elemType = type->getElementType();
	auto elemSize = getTypeByteSizeInBinary(_module, elemType);

	for (std::size_t i = 0; i < elemNum; ++i)
	{
		auto* ec = getConstant(
				elemType,
				addr + offset);

		if (ec == nullptr)
		{
			return nullptr;
		}

		offset += elemSize;
		vc.push_back(ec);
	}

	// Even though ConstantArray::get() is used, this can create an
	// ConstantDataArray instance if elements are of the simple type.
	//
	return ConstantArray::get(type, vc);
}

/**
 * Get constant of the given @a type. If @a objf and @a addr are specified,
 * constant is initialized with an actual value on the provided address in
 * object file. Otherwise @c nullptr is returned -- it can still be used to
 * construct global variable with undefined value.
 * @param type Type of the constant.
 * @param addr Address of the constant in the @a objf.
 * @param wideString Is type a wide string?
 * @return Constant of the given type and data, or @c nullptr.
 *
 * @note Right now, this can create only constants of simple or array types.
 *       If unhandled type (e.g. structure, function pointer) is provided,
 *       @c nullptr is returned.
 */
llvm::Constant* FileImage::getConstant(
		llvm::Type* type,
		retdec::utils::Address addr,
		bool wideString)
{
	Constant* c = nullptr;

	if (addr.isUndefined())
	{
		return nullptr;
	}

	if (wideString)
	{

		auto& ctx = _module->getContext();
		std::vector<std::uint64_t> wideStr;
		unsigned wcharSize = _image->getFileFormat()->isElf() ? 4 : 2;

		if (_image->getNTWS(addr, wcharSize, wideStr))
		{
			if (wcharSize == 2)
			{
				std::vector<uint16_t> array(wideStr.begin(), wideStr.end());
				c = ConstantDataArray::get(ctx, array);
			}
			else if (wcharSize == 4)
			{
				std::vector<unsigned int> array(wideStr.begin(), wideStr.end());
				c = ConstantDataArray::get(ctx, array);
			}

			c->setValueName(ValueName::Create("wide-string"));
			return c;
		}
		else
		{
			std::vector<unsigned int> array = {0};
			c = ConstantDataArray::get(ctx, array);
			c->setValueName(ValueName::Create("wide-string"));
			return c;
		}
	}
	else if (IntegerType* it = dyn_cast<IntegerType>(type))
	{
		c = getConstantInt(it, addr);
	}
	else if (type->isHalfTy())
	{
		c = getConstantHalf(addr);
	}
	else if (type->isFloatTy())
	{
		c = getConstantFloat(addr);
	}
	else if (type->isDoubleTy())
	{
		c = getConstantDouble(addr);
	}
	else if (type->isX86_FP80Ty())
	{
		c = getConstantLongDouble(addr);
	}
	else if (isCharPointerType(type))
	{
		c = getConstantCharPointer(addr);
	}
	else if (auto* ptr = dyn_cast_or_null<PointerType>(type))
	{
		c = getConstantPointer(ptr, addr);
	}
	else if (auto* st = dyn_cast<StructType>(type))
	{
		c = getConstantStruct(st, addr);
	}
	else if (auto* at = dyn_cast<ArrayType>(type))
	{
		c = getConstantArray(at, addr);
	}
	else if (type->isFP128Ty())
	{
		c = getConstantDouble(addr);
	}
	else
	{
		errs() << "unhandled type catched : "
				<< *type << " @ " << addr.toHexString() << "\n";
		assert(false && "unhandled type catched");
		return nullptr;
	}

	// Make extra sure the returned constant's type is the same as expected.
	return convertConstantToType(c, type);
}

/**
 * Get constant from the given address @a addr.
 * The type is unknown. If there is a constant of recognizable type on the
 * address, then constant of this type is created. Otherwise, default integer
 * constant is created. The recognizable types are:
 * - ASCII string.
 * - ASCII string encoded as wide string.
 * - Pointer to global variable.
 * - Array of pointers to global variables.
 * @param config Config associated with module.
 * @param dbgf Debug file.
 * @param addr Address of the constant in the @a objf.
 * @return Constant on the given address, or @c nullptr.
 */
llvm::Constant* FileImage::getConstant(
		Config* config,
		DebugFormat* dbgf,
		retdec::utils::Address addr)
{
	if (addr.isUndefined())
	{
		return nullptr;
	}
	auto& ctx = _module->getContext();
	auto origAddr = addr;

	Constant* c = nullptr;

	std::string str;
	std::vector<std::uint64_t> wideStr;
	unsigned wcharSize = getFileFormat()->isElf() ? 4 : 2;

	std::uint64_t val = 0;
	auto res = _image->getWord(addr, val);
	auto* seg = res ? _image->getSegmentFromAddress(val) : nullptr;
	//    if (res && config && config->getLlvmFunction(val) == nullptr && seg && seg->getSecSeg() && !seg->getSecSeg()->isCode())
	auto* srcSeg = _image->getSegmentFromAddress(addr);
	if (res && config && config->getLlvmFunction(val) == nullptr && seg && seg->getSecSeg() && !seg->getSecSeg()->isCode() && srcSeg && !srcSeg->getSecSeg()->isCode())
	{
		std::vector<Constant*> refGvs;
		while (1)
		{
			std::uint64_t val = 0;
			if (!_image->getWord(addr, val))
			{
				break;
			}
			if (val == origAddr)
			{
				break; // cycle
			}

			// TODO: it would be great to use this info here, but vtable analysis
			// can not handle it at the moment -> some features.cpp tests fail.
			//
			if (auto* cf = config->getConfigFunction(val))
			{
				if (!retdec::utils::contains(cf->getName(), "unknown_"))
				{
					break;
				}
			}

			auto* newGv = getGlobalVariable(_module, config, this, dbgf, val);
			if (newGv == nullptr)
			{
				break;
			}

			refGvs.push_back(newGv);
			addr += getDefaultTypeByteSize(_module);

			static auto& conf = config->getConfig();
			if (conf.globals.getObjectByAddress(addr))
			{
				break;
			}
		}

		if (refGvs.size() == 1)
		{
			c = refGvs.front();
		}
		else if (refGvs.size() > 1 && isStringArrayPointeType(refGvs.front()->getType()))
		{
			auto* at = ArrayType::get(
					PointerType::get(Type::getInt8Ty(ctx), 0),
					refGvs.size());

			std::vector<Constant*> av2;
			for (auto* c : refGvs)
				av2.push_back(convertConstantToType(
						c,
						PointerType::get(Type::getInt8Ty(ctx), 0)) );

			c = ConstantArray::get(at, ArrayRef<Constant*>(av2));
		}
	}
	// for-simple.c -a x86 -f elf -c gcc -C -O0, 8049b7c -- in 2 sections -- .data + .bss
	// the same for any array -- all data in single section
	else if (!seg && _image->getNTWSNice(addr, wcharSize, wideStr) && wideStr.size() >= 3)
	{
		if (wcharSize == 2)
		{
			std::vector<uint16_t> array(wideStr.begin(), wideStr.end());
			c = ConstantDataArray::get(ctx, ArrayRef<uint16_t>(array));
		}
		else if (wcharSize == 4)
		{
			std::vector<unsigned int> array(wideStr.begin(), wideStr.end());
			c = ConstantDataArray::get(ctx, ArrayRef<unsigned int>(array));
		}

		// Simple Value::setName() does not work on Constant.
		c->setValueName(ValueName::Create("wide-string"));
	}
	else if (!seg && _image->getNTBS(addr, str) && retdec::utils::isNiceString(str, 1.0) && str.size() >= 2)
	{
		c = ConstantDataArray::getString(ctx, str);
	}
	else
	{
		c = getConstantInt(getDefaultType(_module), addr);
	}

	return c;
}

/**
 * There is a function retdec::fileformat::getSymbolTables()
 * which gets the first symbol on a specified address.
 *
 * However, sometimes there are multiple symbols for one address.
 * E.g. ".text" and "_scanf". This function tries to decide which one is
 * preferred and return it.
 * If there is only one symbol, it is simply returned.
 * If there is no symbol, @c nullptr is returned.
 */
const retdec::fileformat::Symbol* FileImage::getPreferredSymbol(
		retdec::utils::Address addr)
{
	std::set<const retdec::fileformat::Symbol*> syms;

	for (const auto* t : _image->getFileFormat()->getSymbolTables())
	for (const auto& s : *t)
	{
		unsigned long long a = 0;
		if (!s->getRealAddress(a))
		{
			continue;
		}

		if (addr == a)
		{
			syms.insert(s.get());
		}
	}

	const retdec::fileformat::Symbol* ret = nullptr;

	for (auto* s : syms)
	{
		const auto& retName = ret->getName();
		const auto& sName = s->getName();
		if (ret == nullptr
				|| retName.empty()
				|| retName.front() == '.'
				|| sName.empty()
				|| sName.front() == '_')
		{
			ret = s;
		}
	}

	// TODO: direct config provider usage + ugly statis.
	//
	static bool lowered = false;
	auto* c = ConfigProvider::getConfig(_module);
	if (c && ret == nullptr && c->getConfig().architecture.isArmOrThumb())
	{
		if (!lowered)
		{
			lowered = true;
			ret = getPreferredSymbol(addr - 1);
			lowered = false;
			return ret;
		}
	}

	return ret;
}

//
//=============================================================================
//  FileImageProvider
//=============================================================================
//

std::map<llvm::Module*, FileImage> FileImageProvider::_module2image;

/**
 * Create and add to provider a file image created from file at @a path for
 * the given module @a m and architecture @a a.
 * @return Created and added file image or @c nullptr if something went wrong
 *         and it was not successfully created.
 */
FileImage* FileImageProvider::addFileImage(
		llvm::Module* m,
		const std::string& path,
		Config *config)
{
	return addFileImage(m, FileImage(m, path, config));
}

/**
 * Create and add to provider a file image @a ff for the given module @a m
 * and architecture @a a.
 * @return Created and added file image or @c nullptr if something went wrong
 *         and it was not successfully created.
 */
FileImage* FileImageProvider::addFileImage(
		llvm::Module* m,
		const std::shared_ptr<retdec::fileformat::FileFormat>& ff,
		Config* config)
{
	return addFileImage(m, FileImage(m, ff, config));
}

FileImage* FileImageProvider::addFileImage(
		llvm::Module* m,
		FileImage img)
{
	if (!img.isOk())
	{
		return nullptr;
	}

	auto p = _module2image.emplace(m, std::move(img));
	return &p.first->second;
}

/**
 * @return Get file image associated with the given module @a m or @c nullptr
 *         if there is no associated file image.
 */
FileImage* FileImageProvider::getFileImage(
		llvm::Module* m)
{
	auto f = _module2image.find(m);
	return f != _module2image.end() ? &f->second : nullptr;
}

/**
 * Get file image @a objf associated with the module @a m.
 * @param[in]  m    Module for which to get file image.
 * @param[out] objf Set to file image associated with @a m module, or
 *                  @c nullptr if there is no associated file image.
 * @return @c True if file image @a objf was set ok and can be used.
 *         @c False otherwise.
 */
bool FileImageProvider::getFileImage(
		llvm::Module* m,
		FileImage*& objf)
{
	objf = getFileImage(m);
	return objf != nullptr;
}

/**
 * Clear all stored data.
 */
void FileImageProvider::clear()
{
	_module2image.clear();
}

} // namespace bin2llvmir
} // namespace retdec
