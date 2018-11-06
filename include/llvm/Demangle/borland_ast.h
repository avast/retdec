/**
 * @file include/llvm/Demangle/borland_ast.h
 * @brief Representation of syntactic tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_H
#define RETDEC_BORLAND_AST_H

#include <memory>
#include <string>

#include "llvm/Demangle/StringView.h"

namespace retdec {
namespace demangler {
namespace borland {

class Node;
class NameNode;
class NestedNameNode;

/**
 * @brief Parser from name mangled by borland mangling scheme into AST.
 */
class BorlandASTParser
{
	public:
		enum Status: uint8_t
		{
			success = 0,
			init,
			memory_alloc_failure,
			invalid_mangled_name,
			unknown_error,
		};

	public:
		explicit BorlandASTParser(const std::string &mangled);

		std::shared_ptr<Node> ast();

		Status status();

	private:
		void parse();
		std::unique_ptr<Node> parseFullName();
		static StringView getNestedName(StringView &source);

	private:
		Status _status;
		StringView _mangled;
		std::shared_ptr<Node> _ast;
};

/**
 * @brief Base class for all nodes in AST.
 */
class Node
{
	public:
		enum Kind: unsigned
		{
			KName,
			KNestedName,
			KType,
			KNodeArray,
			KFunction,
		};

	public:
		Node(Kind kind, bool has_right_side);

		virtual ~Node() = default;

		void print(std::ostream &s);

		std::string str();

		Kind kind();

	protected:
		virtual void printLeft(std::ostream &s) = 0;

	protected:
		Kind _kind;
};

/**
 * @brief Node for representation of names.
 */
class NameNode: public Node
{
	public:
		static std::unique_ptr<NameNode> create(const StringView &name);

	private:
		explicit NameNode(const StringView &name);

		void printLeft(std::ostream &s) override;

	private:
		StringView _name;
};

/**
 * @brief Node for representation of nested names.
 */
class NestedNameNode: public Node
{
	public:
		static std::unique_ptr<NestedNameNode> create(std::unique_ptr<Node> super, std::unique_ptr<Node> name);

	private:
		NestedNameNode(std::unique_ptr<Node> super, std::unique_ptr<Node> name);

		void printLeft(std::ostream &s) override;

	private:
		std::unique_ptr<Node> _super;
		std::unique_ptr<Node> _name;
};

}
}
}

#endif //RETDEC_BORLAND_AST_H
