/**
 * @file include/retdec/dwarfparser/dwarf_base.h
 * @brief Declaration of base classes used in dwarfparser.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_DWARFPARSER_DWARF_BASE_H
#define RETDEC_DWARFPARSER_DWARF_BASE_H

#include <list>
#include <map>
#include <string>
#include <vector>

#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

namespace retdec {
namespace dwarfparser {

// Extern forward declarations.
class DwarfFile;
class DwarfCU;

// Locale forward declarations.
template <class T>
class DwarfBaseContainer;
class DwarfBaseElement;

/**
 * @class DwarfBaseContainer.
 * @brief Base container class for all container objects used by dwarfparser.
 */
template <class T>
class DwarfBaseContainer
{
	//
	// Type aliases
	//
	public:
		using iterator = typename std::vector<T*>::iterator;
		using const_iterator = typename std::vector<T*>::const_iterator;

	//
	// Non-virtual functions.
	//
	public:
		DwarfBaseContainer(DwarfFile *file, DwarfBaseElement *elem = nullptr)  :
			m_res(0),
			m_error(nullptr),
			m_parentFile(file),
			m_parentElem(elem)
		{

		}

		std::size_t size() const                { return m_data.size();  }
		void push_back(T *n)                    { m_data.push_back(n);   }
		bool empty() const                      { return m_data.empty(); }
		iterator begin()                        { return m_data.begin(); }
		const_iterator begin() const            { return m_data.begin(); }
		iterator end()                          { return m_data.end();   }
		const_iterator end() const              { return m_data.end();   }

		DwarfBaseElement *getParentElem() const { return m_parentElem;   }
		DwarfFile *getParentFile() const        { return m_parentFile;   }

		// TODO: get element by DIE?
		DwarfBaseElement *getElemByOffset(Dwarf_Off o);

	//
	// Virtual functions.
	//
	public:
		virtual ~DwarfBaseContainer()
		{
			for (iterator it=begin(); it!=end(); ++it)
				delete (*it);
			m_data.clear();
		}

		virtual void dump() const
		{
			for (const_iterator cit=begin(); cit!=end(); ++cit)
				(*cit)->dump();
		}

	//
	// Pure virtual functions.
	//
	public:
		virtual T* loadAndGetDie(Dwarf_Die die, unsigned lvl) = 0;

	//
	// Data.
	//
	protected:
		std::vector<T*> m_data;         ///< Object container.

		int m_res;                      ///< Global return value.
		Dwarf_Error m_error;            ///< Global error code.

		DwarfFile *m_parentFile;        ///< Pointer to DWARF file representation.
		DwarfBaseElement *m_parentElem; ///< Pointer to parent element, if nullptr then parent is DWARF file.

	public:
		/**
		 * DIE offset to element mapping.
		 * One element may have multiple offsets -- multiple mappings.
		 * ==> *DO NOT* iterate through this container, use 'm_data'.
		 */
		std::map<Dwarf_Off, T*> off2data;
};

/**
 * @class DwarfBaseElement
 * @brief Base element class for all objects used by dwarfparser.
 */
class DwarfBaseElement
{
	public:
		/**
		 * @brief Types element
		 */
		enum type_t
		{
			CU,
			FUNCTION,
			LINE,
			TYPE,
			VAR
		};

		DwarfBaseElement(type_t type, DwarfBaseContainer<DwarfBaseElement> *prnt, Dwarf_Off d);
		virtual ~DwarfBaseElement() {}
		virtual void dump() const = 0;

	public:
		virtual const std::string& getName() const                {return name;}

		type_t getType() const                                    {return m_type;}
		DwarfBaseContainer<DwarfBaseElement> *getPrntCont() const {return m_parent;}
		DwarfFile *getParentFile() const                          {return getPrntCont()->getParentFile();}
		DwarfCU *getCuParent() const                              {return m_cuParent;}

		Dwarf_Debug &getLibdwarfDebug() const;
		void addOffset(Dwarf_Off o);
		std::string getDwarfdump2OffsetString() const;

	public:
		std::string name;

	protected:
		type_t m_type;
		DwarfBaseContainer<DwarfBaseElement> *m_parent; ///< Pointer to parent container that contains this element.
		DwarfCU *m_cuParent;                            ///< Pointer to parent CU element that contains this element.
};

/**
 * @brief Get container's element with provided offset.
 * @param o Offset.
 * @return Element with offset.
 */
template <class T>
DwarfBaseElement* DwarfBaseContainer<T>::getElemByOffset(Dwarf_Off o)
{
	auto it = off2data.find(o);
	if (it != off2data.end())
		return it->second;
	else
		return nullptr;
}

} // namespace dwarfparser
} // namespace retdec

#endif
