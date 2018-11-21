/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_demangler.h"
#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_parser.h"

namespace retdec {
namespace demangler {

/**
 * @brief Constructor for borland demangler.
 */
BorlandDemangler::BorlandDemangler() : Demangler("borland") {}

/**
 * @brief Demangles name mangled by borland mangling scheme into string.
 * @param mangled Name mangled by borland mangling scheme.
 * @return Demangled name.
 */
std::string BorlandDemangler::demangleToString(const std::string &mangled)
{
	borland::BorlandASTParser parser{mangled};
	auto ast = parser.ast();
	return ast ? ast->str() : std::string{};
}

namespace borland {

/**
 * @brief Constructor for AST parser. It parses name mangled by borland mangling scheme into AST.
 * @param mangled Name mangled by borland mangling scheme.
 */
BorlandASTParser::BorlandASTParser(const std::string &mangled) :
	_status(init),
	_mangled(mangled.c_str(), mangled.length()),
	_ast(nullptr)
{
	parse();
}

/**
 * @return Status of parser.
 */
BorlandASTParser::Status BorlandASTParser::status()
{
	return _status;
}

/**
 * @brief Main method of parser. Tries to create AST, sets status.
 */
void BorlandASTParser::parse()
{
	if (!_mangled.consumeFront('@')) {    // name
		_status = invalid_mangled_name;
		return;
	}

	auto name = parseFullName();
	if (!name) {
		_status = invalid_mangled_name;
		return;
	}

	if (_mangled.empty()) {
		_status = success;
		_ast = std::move(name);
		return;
	}

	auto call_conv = parseCallConv();
	if (!call_conv) {
		_status = invalid_mangled_name;
		return;
	}

//	auto params = parseParams();
	auto params = NameNode::create("");    //TODO

	_ast = FunctionNode::create(std::move(call_conv), std::move(name), std::move(params));
	_status = success;
}

/**
 * @brief Tries to consume first nested name in in source and returns it.
 */
StringView BorlandASTParser::getNestedName(StringView &source)
{
	auto nested = source.cutUntil('@');
	source.consumeFront('@');
	return nested;
}

/**
 * @brief Tries to parse whole name into AST.
 * @return Pointer to Node that represents name.
 */
std::unique_ptr<Node> BorlandASTParser::parseFullName()
{
	auto name = _mangled.substrUntil('$');
	if (name.empty()) {
		return nullptr;
	}
	_mangled.consumeFront(name);
	_mangled.consumeFront('$');

	auto nestedPart = getNestedName(name);
	if (nestedPart.empty()) {
		return NameNode::create(name);
	}
	std::unique_ptr<Node> nameNode = NameNode::create(nestedPart);

	StringView nextNested;
	while (!(nextNested = getNestedName(name)).empty()) {
		auto nextNestedNode = NameNode::create(nextNested);
		nameNode = NestedNameNode::create(std::move(nameNode), std::move(nextNestedNode));
	}

	// everything left must be absolute name
	auto absNameNode = NameNode::create(name);
	return NestedNameNode::create(std::move(nameNode), std::move(absNameNode));
}

/**
 * @brief Tries to parse calling convention into AST node.
 * @return Pointer to CallConv on success, else nullptr.
 */
std::unique_ptr<CallConv> BorlandASTParser::parseCallConv()
{
	using Convention = CallConv::Conventions;

	if (!_mangled.consumeFront('q')) {
		return nullptr;
	}

	auto conv = Convention::unknown;
	if (_mangled.consumeFront('q')) {
		switch (_mangled.popFront()) {
		case 'r':
			conv = Convention::fastcall;
			break;
		case 's':
			conv = Convention::stdcall;
			break;
		default:
			break;
		}
	} //else unknown, cant tell for certain

	return CallConv::create(conv);
}

/**
 * @return Shared pointer to AST.
 */
std::shared_ptr<Node> BorlandASTParser::ast()
{
	return _status == success ? _ast : nullptr;
}

} // borland
} // demangler
} // retdec
