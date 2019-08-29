/**
* @file src/llvmir2hll/hll/output_manager.cpp
* @brief Implementation of OutputManager.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/output_manager.h"

namespace retdec {
namespace llvmir2hll {

OutputManager::~OutputManager()
{

}

void OutputManager::setCommentPrefix(const std::string& prefix)
{
    _commentPrefix = prefix;
}

const std::string& OutputManager::getCommentPrefix() const
{
    return _commentPrefix;
}

void OutputManager::setOutputLanguage(const std::string& lang)
{
    _outLanguage = lang;
}

const std::string& OutputManager::getOutputLanguage() const
{
    return _outLanguage;
}

void OutputManager::operatorX(
    const std::string& op,
    bool spaceBefore,
    bool spaceAfter,
    Address addr)
{
    if (spaceBefore)
    {
        space(" ", addr);
        // Reset so that it doesn't get used again in later tokens.
        addr = Address::Undefined;
    }
    operatorX(op, addr);
    if (spaceAfter)
    {
        space();
    }
}

void OutputManager::comment(
    const std::string& c,
    const std::string& indent,
    Address addr)
{
    if (!indent.empty())
    {
        space(indent, addr);
        // Reset so that it doesn't get used again in later tokens.
        addr = Address::Undefined;
    }
    comment(c, addr);
}

void OutputManager::commentLine(
    const std::string& c,
    const std::string& indent,
    Address addr)
{
    comment(c, indent, addr);
    newLine();
}

void OutputManager::includeLine(
    const std::string& header,
    const std::string& indent,
    const std::string& c,
    Address addr)
{
    if (!indent.empty())
    {
        space(indent, addr);
        // Reset so that it doesn't get used again in later tokens.
        addr = Address::Undefined;
    }
    preprocessor("#include", addr);
    space();
    include(header);
    if (!c.empty()) comment(c, " ");
    newLine();
}

void OutputManager::typedefLine(
    const std::string& indent,
    const std::string& t1,
    const std::string& t2,
    Address addr)
{
    if (!indent.empty())
    {
        space(indent, addr);
        // Reset so that it doesn't get used again in later tokens.
        addr = Address::Undefined;
    }
    keyword("typedef");
    space();
    dataType(t1);
    space();
    dataType(t2);
    punctuation(';');
    newLine();
}

} // namespace llvmir2hll
} // namespace retdec
