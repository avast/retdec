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
	auto absNameNode = parseFuncName();
	if (_status == invalid_mangled_name || absNameNode == nullptr) {
		_status = invalid_mangled_name;
		return;
	}

	_mangled.consumeFront('$');

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

	std::shared_ptr<Node> retType = nullptr;
	if (_mangled.consumeFront('$')) {
		retType = parseType();    // TODO zaclen to do funkcie
	}

	_status = Status::success;
	_ast = FunctionNode::create(absNameNode, callConv, paramsNode, retType, isVolatile, isConst);
}

std::shared_ptr<Node> BorlandASTParser::parseFuncName()
{
	std::shared_ptr<Node> name = nullptr;

	const char *start = _mangled.begin();
	const char *end = _mangled.end();
	const char *c = _mangled.begin();
	while (c <= end) {
		if (*c == '$' || *c == '%' || *c == '@') {
			auto nameView = StringView(start, c);
			if (!nameView.empty()) {
				_mangled.consumeFront(nameView);        // propagate to mangled
				auto nameNode = NameNode::create(nameView);
				if (!name) {
					name = nameNode;
				} else {
					name = NestedNameNode::create(name, nameNode);
				}

				start = c + 1;
			}
			if (_mangled.front() == '@') {
				_mangled.consumeFront('@');
			} else {
				break;
			}
		}
		++c;
	}

	if (_mangled.front() == '%') {
		name = parseTemplate(name);
	}

	return name;
}

std::shared_ptr<Node> BorlandASTParser::parseName(const char *endMangled)
{
	std::shared_ptr<Node> name = nullptr;

	const char *start = _mangled.begin();
	const char *end = endMangled;
	const char *c = _mangled.begin();
	while (c < end) {
		if (*c == '%' || *c == '@') {
			auto nameView = StringView(start, c);
			if (!nameView.empty()) {
				_mangled.consumeFront(nameView);        // propagate to mangled
				auto nameNode = NameNode::create(nameView);
				if (!name) {
					name = nameNode;
				} else {
					name = NestedNameNode::create(name, nameNode);
				}

				start = c + 1;
			}
			if (_mangled.front() == '@') {
				_mangled.consumeFront('@');
			} else {
				break;
			}
		}
		++c;
	}

	if (c == end) { // parse remainder as name
		auto nameView = StringView(start, c);
		_mangled.consumeFront(nameView);        // propagate to mangled
		auto nameNode = NameNode::create(nameView);
		if (!name) {
			name = nameNode;
		} else {
			name = NestedNameNode::create(name, nameNode);
		}
	}

	if (!_mangled.empty() && _mangled.front() == '%' && c != end) {
		name = parseTemplate(name, end);
	}

	return name;
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
		if (_mangled.consumeFront('t')) {
			unsigned backref = parseNumberNoConsume();
			if (backref > 0 && backref <= params->size()) {
				parseNumber();
				params->addNode(params->get(backref-1));
				continue;
			}
		}
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
		auto pointedType = parseType();
		if (pointedType) {
			return PointerTypeNode::create(_context, pointedType, isVolatile, isConst);
		} else {
			_status = invalid_mangled_name;
			return nullptr;
		}
	}

	if (_mangled.consumeFront('r')) {
		if (isConst || isVolatile) {
			_status = invalid_mangled_name;
			return nullptr;
		}

		auto referencedType = parseType();
		if (!referencedType || referencedType->kind() == Node::Kind::KReferenceType) {    // TODO restricted reference
			_status = invalid_mangled_name;
			return nullptr;
		}

		return ReferenceTypeNode::create(_context, referencedType);
	}

	if (_mangled.consumeFront('h')) {
		auto referencedType = parseType();
		if (!referencedType || referencedType->kind() == Node::Kind::KReferenceType) {    // TODO more restrictions
			_status = invalid_mangled_name;
			return nullptr;
		}
		return RReferenceTypeNode::create(_context, referencedType);
	}

	if (_mangled.consumeFront('a')) {
		unsigned len = parseNumber();
		if (len == 0) {
			_status = invalid_mangled_name;
			return nullptr;
		}
		_mangled.consumeFront('$');
		auto arrType = parseType();
		return ArrayNode::create(_context, arrType, len, isVolatile, isConst);
//		return PointerTypeNode::create(_context, arrType, false, false);
	}

	unsigned len = parseNumber();
	if (_status == invalid_mangled_name) {
		return nullptr;
	}
	if (len > 0) {
		auto name = parseNamedType(len);
		return NamedTypeNode::create(_context, name, isVolatile, isConst);    //todo checky
//		return parseNamedType(len);
	}

	auto builtIn = parseBuildInType(isVolatile, isConst);
	if (builtIn) {
		return builtIn;
	}

	return nullptr;
}

std::shared_ptr<Node> BorlandASTParser::parseBuildInType(bool isVolatile,
														 bool isConst)    // TODO isVolatile a const as params
{
	if (_mangled.consumeFront('o')) {
		return BuiltInTypeNode::create(_context, "bool", isVolatile, isConst);
	} else if (_mangled.consumeFront('b')) {
		return BuiltInTypeNode::create(_context, "wchar_t", isVolatile, isConst);
	} else if (_mangled.consumeFront('v')) {
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
		return IntegralTypeNode::create(_context, "short", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('i')) {
		return IntegralTypeNode::create(_context, "int", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('l')) {
		return IntegralTypeNode::create(_context, "long", isUnsigned, isVolatile, isConst);
	} else if (_mangled.consumeFront('j')) {
		return IntegralTypeNode::create(_context, "long long", isUnsigned, isVolatile, isConst);
	}
	if (isUnsigned) {    // was 'u' then not integral type
		_status = Status::invalid_mangled_name;
		return nullptr;
	}

		/* float types */
	else if (_mangled.consumeFront('f')) {
		return FloatTypeNode::create(_context, "float", isVolatile, isConst);
	} else if (_mangled.consumeFront('d')) {
		return FloatTypeNode::create(_context, "double", isVolatile, isConst);
	} else if (_mangled.consumeFront('g')) {
		return FloatTypeNode::create(_context, "long double", isVolatile, isConst);
	}

	return nullptr;
}

unsigned BorlandASTParser::parseNumber()
{
	unsigned acc = 0;
	if (!_mangled.empty()) {
		char c = _mangled.front();
		if (c == '0') {
			_status = invalid_mangled_name;    // cant start with 0
			return 0;
		}

		while (!_mangled.empty() && _mangled.front() >= '0' && _mangled.front() <= '9') {
			c = _mangled.popFront();
			acc = 10*acc + static_cast<unsigned>(c-'0');
		}
	}

	return acc;
}

unsigned BorlandASTParser::parseNumberNoConsume() const {
	StringView mangledCopy = _mangled;
	unsigned acc = 0;
	if (!mangledCopy.empty()) {
		char c = mangledCopy.front();
		if (c == '0') {
			return 0;
		}

		while (!mangledCopy.empty() && mangledCopy.front() >= '0' && mangledCopy.front() <= '9') {
			c = mangledCopy.popFront();
			acc = 10*acc + static_cast<unsigned>(c-'0');
		}
	}

	return acc;
}

std::shared_ptr<Node> BorlandASTParser::parseNamedType(unsigned nameLen)
{
	const char *end_named = _mangled.begin() + nameLen;
	if (_mangled.end() < end_named) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	auto nameNode = parseName(end_named);
	if (nameNode == nullptr) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	return nameNode;    // TODO quals
//	return NamedTypeNode::create(_context, nameNode, )
}

std::shared_ptr<Node> BorlandASTParser::parseTemplate(std::shared_ptr<Node> templateNamespace)
{
	_mangled.consumeFront('%');

	auto templateName = _mangled.cutUntil('$');
	if (templateName.empty()) {
		_status = invalid_mangled_name;
		return nullptr;
	}
	std::shared_ptr<Node> templateNameNode = NameNode::create(templateName);

	if (templateNamespace) {
		templateNameNode = NestedNameNode::create(templateNamespace, templateNameNode);
	}

	_mangled.consumeFront('$');

	auto params = NodeArray::create();
	while (_mangled.front() != '%') {
		if (_mangled.consumeFront('t')) {
			unsigned backref = parseNumberNoConsume();
			if (backref > 0 && backref <= params->size()) {
				parseNumber();
				params->addNode(params->get(backref-1));
				continue;
			}
		}// TODO else nothing, check delphi for tests
		auto typeNode = parseType();
		if (typeNode && _status != invalid_mangled_name) {
			params->addNode(typeNode);
		}
	}

	_mangled.consumeFront('%');
	auto templateNode = TemplateNode::create(templateNameNode, params);
	return templateNode;
}

std::shared_ptr<Node> BorlandASTParser::parseTemplate(std::shared_ptr<Node> templateNamespace, const char *end)
{
	_mangled.consumeFront('%');
	auto templateName = _mangled.cutUntil('$');
	if (templateName.empty()) {
		_status = invalid_mangled_name;
		return nullptr;
	}

	std::shared_ptr<Node> templateNameNode = NameNode::create(templateName);

	if (templateNamespace) {
		templateNameNode = NestedNameNode::create(templateNamespace, templateNameNode);
	}

	_mangled.consumeFront('$');
	auto params = NodeArray::create();
	while (_mangled.front() != '%') {	// TODO tato podmienka je zle, musi sa ist po kedy nebude jedno pred koncom, posledny znak musi byt %
		if (_mangled.consumeFront('t')) {
			unsigned backref = parseNumberNoConsume();
			if (backref > 0 && backref <= params->size()) {
				parseNumber();
				params->addNode(params->get(backref-1));
				continue;
			}
		}// TODO else nothing, check delphi for tests
		auto typeNode = parseType();
		if (!typeNode || _status == invalid_mangled_name) {
			break;
		}
		params->addNode(typeNode);
	}

	_mangled.consumeFront('%');
	if (_mangled.begin() != end) {
		_status = invalid_mangled_name;
		return nullptr;
	}
	auto templateNode = TemplateNode::create(templateNameNode, params);
	return templateNode;
	// TODO problem ked je viac parametrov v template
}

} // borland
} // demangler
} // retdec
