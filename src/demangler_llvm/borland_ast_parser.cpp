/**
 * @file src/demangler_llvm/borland_demangler.cpp
 * @brief Implementation of borland demangler parsing into AST.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#include "llvm/Demangle/borland_ast.h"
#include "llvm/Demangle/borland_ast_parser.h"
#include "llvm/Demangle/borland_ast_types.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Constructor for AST parser. It parses name mangled by borland mangling scheme into AST.
 * @param mangled Name mangled by borland mangling scheme.
 */
BorlandASTParser::BorlandASTParser(Context &context, const std::string &mangled) :
	_status(in_progress),
	_mangled(mangled.c_str(), mangled.length()),
	_ast(nullptr),
	_context(context)
{
	parse();
}

/**
 * @return Shared pointer to AST.
 */
std::shared_ptr<Node> BorlandASTParser::ast()
{
	return _status == success ? _ast : nullptr;
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
 *
 * <mangled-name> ::= @ <mangled-function>
 */
void BorlandASTParser::parse()
{
	if (_mangled.consumeFront('@')) {
		parseFunction();
	}

	if (!_mangled.empty()) {
		_status = invalid_mangled_name;
	}
}

/*
 * @brief Tries to parse mangled name to function Node.
 *
 * <mangled-function> ::= <abslute-name> <type-info>
 */
void BorlandASTParser::parseFunction()
{
	auto absNameNode = parseAbsoluteName();
	if (_status == Status::invalid_mangled_name) {
		return;
	}

	/* function qualifiers */
	bool isVolatile{}, isConst{};
	std::tie(isVolatile, isConst) = parseQualifiers();

	// TODO operators

	/* function calling convention */
	FunctionNode::CallConv callConv = parseCallConv();
	if (_status == Status::invalid_mangled_name) {
		return;
	}

	/* parameters */
	auto paramsNode = parseFuncParams();
	if (_status == Status::invalid_mangled_name) {
		return;
	}

//	auto retType = parseRetType();

	_status = Status::success;
	_ast = FunctionNode::create(absNameNode, callConv, paramsNode, isVolatile, isConst);
}

std::pair<bool, bool> BorlandASTParser::parseQualifiers()
{
	bool is_volatile = _mangled.consumeFront('w');
	bool is_const = _mangled.consumeFront('x');

	return {is_volatile, is_const};
}

FunctionNode::CallConv BorlandASTParser::parseCallConv()
{
	if (_mangled.consumeFront("qqr")) {
		return FunctionNode::CallConv::fastcall;
	} else if (_mangled.consumeFront("qqs")) {
		return FunctionNode::CallConv::stdcall;
	} else if (_mangled.consumeFront("q")) {
		return FunctionNode::CallConv::unknown;    // most likely cdecl, pascal
	} else {
		_status = Status::invalid_mangled_name;
		return FunctionNode::CallConv::unknown;
	}
}

std::shared_ptr<NodeArray> BorlandASTParser::parseFuncParams()
{
	auto params = NodeArray::create();

	while (!_mangled.empty() && _status == Status::in_progress) {
		auto param = parseType();
		if (param) {
			params->addNode(param);
		} else {
			break;
		}
	}

	return params->empty() ? nullptr : params;
}

std::shared_ptr<Node> BorlandASTParser::parseType()
{
	/* qualifiers */
	bool isVolatile{}, isConst{};
	std::tie(isVolatile, isConst) = parseQualifiers();

	if (_mangled.consumeFront('p')) {
		return PointerTypeNode::create(_context, parseType(), isVolatile, isConst);
	}

	if (_mangled.consumeFront('r')) {
		// if is volatile or const -> invalid
		// parseType, if reference -> invalid
		// return referenceType::create(type)
	}

	if (_mangled.consumeFront('h')) {
		// rRef
	}

	if (_mangled.consumeFront('a')) {
		// array
		//consume size
		//consume $
		//parse array type
	}

//	unsigned len = parseNumber();
//	if (len) {
//		return parseNamedType();
//	}

	auto builtIn = parseBuildInType(isVolatile, isConst);
	if (builtIn) {
		return builtIn;
	}

	return nullptr;
}

std::shared_ptr<Node> BorlandASTParser::parseBuildInType(bool isVolatile, bool isConst)    // TODO isVolatile a const as params
{
	if (_mangled.consumeFront('o')) {
		return BuiltInTypeNode::create(_context, "bool", isVolatile, isConst);
	} else if (_mangled.consumeFront('b')) {
//		return TypeFactory::createWChar();
		return BuiltInTypeNode::create(_context, "wchar_t", isVolatile, isConst);
	} else if (_mangled.consumeFront('v')) {
//		return TypeFactory::createVoid();
		return BuiltInTypeNode::create(_context, "void", isVolatile, isConst);
	}

	/* char types */
	if (_mangled.consumeFront("zc")) {    //only explicitly signed type
		return CharTypeNode::create(_context, ThreeStateSignness::signed_char, isVolatile, isConst);
	} else if (_mangled.consumeFront("uc")) {
		return CharTypeNode::create(_context, ThreeStateSignness::unsigned_char, isVolatile, isConst);
	} else if (_mangled.consumeFront('c')) {
		return CharTypeNode::create(_context, ThreeStateSignness::no_prefix, isVolatile, isConst);
	}

	/* integral types */
	bool isUnsigned = false;
	if (_mangled.consumeFront('u')) {
		isUnsigned = true;
	}
	if (_mangled.consumeFront('s')) {
//		return TypeFactory::createShort(isUnsigned);
		return IntegralTypeNode::create(_context, "short", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('i')) {
//		return TypeFactory::createInt(isUnsigned);
		return IntegralTypeNode::create(_context, "int", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('l')) {
//		return TypeFactory::createLong(isUnsigned);
		return IntegralTypeNode::create(_context, "long", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('j')) {
//		return TypeFactory::createLongLong(isUnsigned);
		return IntegralTypeNode::create(_context, "long long", isUnsigned, isVolatile, isConst);
	}
	if (isUnsigned) {    // was 'u' then not integral type
		_status = Status::invalid_mangled_name;
		return nullptr;
	}

		/* float types */
	else if (_mangled.consumeFront('f')) {
//		return TypeFactory::createFloat();
		return FloatTypeNode::create(_context, "float", isVolatile, isConst);
	} else if (_mangled.consumeFront('d')) {
//		return TypeFactory::createDouble();
		return FloatTypeNode::create(_context, "double", isVolatile, isConst);
	} else if (_mangled.consumeFront('g')) {
//		return TypeFactory::createLongDouble();
		return FloatTypeNode::create(_context, "long double", isVolatile, isConst);
	}

	return nullptr;
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
 *
 * <abslute-name> ::= <namespace> <name> $
 * <namespace> ::=
 * <namespace> ::= <basic-name> @ <namespace>
 */
std::shared_ptr<Node> BorlandASTParser::parseAbsoluteName()
{
	auto name = _mangled.cutUntil('$');
	if (name.empty()) {
		_status = Status::invalid_mangled_name;
		return nullptr;
	}
	_mangled.consumeFront('$');

	auto nestedPart = getNestedName(name);
	if (nestedPart.empty()) {
		return NameNode::create(name);
	}
	std::shared_ptr<Node> nameNode = NameNode::create(nestedPart);

	StringView nextNested;
	while (!(nextNested = getNestedName(name)).empty()) {
		auto nextNestedNode = NameNode::create(nextNested);
		nameNode = NestedNameNode::create(nameNode, nextNestedNode);
	}

	// everything left must be absolute name
	auto absNameNode = NameNode::create(name);
	return NestedNameNode::create(nameNode, absNameNode);
}

} // borland
} // demangler
} // retdec
