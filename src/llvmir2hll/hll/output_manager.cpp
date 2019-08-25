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

void OutputManager::commentLine(
    const std::string& c,
    const std::string& indent,
    Address addr)
{
    comment(c);
    newLine();
}

void OutputManager::includeLine(
    const std::string& header,
    const std::string& indent,
    const std::string& c)
{
    space(indent);
    preprocessor("#include");
    space();
    include(header);
    if (!c.empty()) comment(c, " ");
    newLine();
}

void OutputManager::typedefLine(
    const std::string& indent,
    const std::string& t1,
    const std::string& t2)
{
    space(indent);
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
