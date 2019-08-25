/**
* @file src/llvmir2hll/hll/output_manager/plain_manager.cpp
* @brief Implementation of PlainOutputManager.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/output_managers/plain_manager.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace llvmir2hll {

PlainOutputManager::PlainOutputManager(llvm::raw_ostream& out) :
        _out(out)
{

}

PlainOutputManager::~PlainOutputManager()
{

}

void PlainOutputManager::space(const std::string& space)
{
    _out << space;
}

void PlainOutputManager::punctuation(char p)
{
    _out << p;
}

void PlainOutputManager::operatorX(
    const std::string& op,
    bool spaceBefore,
    bool spaceAfter)
{
    if (spaceBefore)
    {
        space();
    }
    _out << op;
    if (spaceAfter)
    {
        space();
    }
}

void PlainOutputManager::variableId(const std::string& id)
{
    _out << id;
}

void PlainOutputManager::memberId(const std::string& id)
{
    _out << id;
}

void PlainOutputManager::labelId(const std::string& id)
{
    _out << id;
}

void PlainOutputManager::functionId(const std::string& id)
{
    _out << id;
}

void PlainOutputManager::parameterId(const std::string& id)
{
    _out << id;
}

void PlainOutputManager::keyword(const std::string& k)

{
    _out << k;
}

void PlainOutputManager::dataType(const std::string& t)
{
    _out << t;
}

void PlainOutputManager::preprocessor(const std::string& p)
{
    _out << p;
}

void PlainOutputManager::include(const std::string& i)
{
    _out << "<" << i << ">";
}

void PlainOutputManager::constantBool(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::constantInt(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::constantFloat(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::constantString(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::constantSymbol(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::constantPointer(const std::string& c)
{
    _out << c;
}

void PlainOutputManager::comment(
    const std::string& c,
    const std::string& indent)
{
    std::stringstream ss;
    ss << indent << getCommentPrefix();
    if (!c.empty())
    {
        ss << " " << utils::replaceCharsWithStrings(c, '\n', " ");
    }
    _out << ss.str();
}

void PlainOutputManager::newLine(Address addr)
{
    _out << "\n";
}

void PlainOutputManager::commentModifier(const std::string& indent)
{
    _out << indent << getCommentPrefix() << " ";
}

} // namespace llvmir2hll
} // namespace retdec
