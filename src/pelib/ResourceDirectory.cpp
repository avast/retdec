/*
* ResourceDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "pelib/ResourceDirectory.h"

namespace PeLib
{

// -------------------------------------------------- ResourceChild -------------------------------------------

	ResourceChild::ResourceChild() : child(nullptr)
	{
	}

	ResourceChild::ResourceChild(const ResourceChild& rhs)
	{
		entry = rhs.entry;
		if (dynamic_cast<ResourceNode*>(rhs.child))
		{
			ResourceNode* oldnode = static_cast<ResourceNode*>(rhs.child);

			child = new ResourceNode;
			child->uiElementRva = rhs.child->getElementRva();
			static_cast<ResourceNode*>(child)->header = oldnode->header;
			static_cast<ResourceNode*>(child)->children = oldnode->children;
		}
		else if (dynamic_cast<ResourceLeaf*>(rhs.child))
		{
			ResourceLeaf* oldnode = static_cast<ResourceLeaf*>(rhs.child);

			child = new ResourceLeaf;
			child->uiElementRva = rhs.child->getElementRva();
			static_cast<ResourceLeaf*>(child)->m_data = oldnode->m_data;
			static_cast<ResourceLeaf*>(child)->entry = oldnode->entry;
		}
		else
			child = 0;
	}

	ResourceChild& ResourceChild::operator=(const ResourceChild& rhs)
	{
		if (this != &rhs)
		{
			entry = rhs.entry;
			if (dynamic_cast<ResourceNode*>(rhs.child))
			{
				ResourceNode* oldnode = static_cast<ResourceNode*>(rhs.child);

				child = new ResourceNode;
				child->uiElementRva = rhs.child->getElementRva();
				static_cast<ResourceNode*>(child)->header = oldnode->header;
				static_cast<ResourceNode*>(child)->children = oldnode->children;
			}
			else if (dynamic_cast<ResourceLeaf*>(rhs.child))
			{
				ResourceLeaf* oldnode = static_cast<ResourceLeaf*>(rhs.child);

				child = new ResourceLeaf;
				child->uiElementRva = rhs.child->getElementRva();
				static_cast<ResourceLeaf*>(child)->m_data = oldnode->m_data;
				static_cast<ResourceLeaf*>(child)->entry = oldnode->entry;
			}
			else
				child = 0;
		}

		return *this;
	}

	ResourceChild::~ResourceChild()
	{
		delete child;
	}

	/**
	* Compares the resource child's id to the parameter dwId.
	* @param dwId ID of a resource.
	* @return True, if the resource child's id equals the parameter.
	**/
	bool ResourceChild::equalId(dword dwId) const
	{
		return entry.irde.Name == dwId;
	}

	/**
	* Compares the resource child's name to the parameter strName.
	* @param strName ID of a resource.
	* @return True, if the resource child's name equals the parameter.
	**/
	bool ResourceChild::equalName(std::string strName) const
	{
		return entry.wstrName == strName;
	}

	/**
	* Returns true if the resource was given a name.
	**/
	bool ResourceChild::isNamedResource() const
	{
		return entry.wstrName.size() != 0;
	}

	/**
	* The children of a resource must be ordered in a certain way. First come the named resources
	* in sorted order, afterwards followed the unnamed resources in sorted order.
	**/
	bool ResourceChild::operator<(const ResourceChild& rc) const
	{
		if (this->isNamedResource() && !rc.isNamedResource())
		{
			return true;
		}
		else if (!this->isNamedResource() && rc.isNamedResource())
		{
			return false;
		}
		else if (this->isNamedResource() && rc.isNamedResource())
		{
			return this->entry.wstrName < rc.entry.wstrName;
		}
		else
		{
			return this->entry.irde.Name < rc.entry.irde.Name;
		}
	}

	/**
	* Returns the node's number of children.
	*/
	unsigned int ResourceChild::getNumberOfChildren() const
	{
		if (!child || child->isLeaf())
		{
			return 0;
		}

		auto *childNode = dynamic_cast<ResourceNode*>(child);
		return !childNode ? 0 : childNode->getNumberOfChildren();
	}

	/**
	* Returns a child of this child.
	*/
	ResourceChild* ResourceChild::getChildOfThisChild(std::size_t uiIndex)
	{
		if (!child || child->isLeaf())
		{
			return nullptr;
		}

		auto *childNode = dynamic_cast<ResourceNode*>(child);
		return !childNode ? nullptr : childNode->getChild(uiIndex);
	}

	/**
	* Returns a child of this child.
	*/
	const ResourceChild* ResourceChild::getChildOfThisChild(std::size_t uiIndex) const
	{
		if (!child || child->isLeaf())
		{
			return nullptr;
		}

		auto *childNode = dynamic_cast<const ResourceNode*>(child);
		return !childNode ? nullptr : childNode->getChild(uiIndex);
	}

	/**
	 * Returns ResourceElement associated with this ResourceChild. It can be either ResourceNode or ResourceLeaf.
	 *
	 * @return Associated ResourceElement.
	 */
	ResourceElement* ResourceChild::getNode()
	{
		return child;
	}

	/**
	 * Returns ResourceElement associated with this ResourceChild. It can be either ResourceNode or ResourceLeaf.
	 *
	 * @return Associated ResourceElement.
	 */
	const ResourceElement* ResourceChild::getNode() const
	{
		return child;
	}

	/**
	 * Sets ResourceElement associated with this ResourceChild. It can be either ResourceNode or ResourceLeaf.
	 *
	 * @param node ResourceElement to associate with this ResourceChild.
	 */
	void ResourceChild::setNode(ResourceElement* node)
	{
		child = node;
	}

	/**
	 * Returns the name of the node.
	 *
	 * @return Name of the node.
	 */
	std::string ResourceChild::getName() const
	{
		return entry.wstrName;
	}

	/**
	 * Returns the Name value of the node.
	 *
	 * @return Name value of the node.
	 */
	dword ResourceChild::getOffsetToName() const
	{
		return entry.irde.Name;
	}

	/**
	 * Returns the OffsetToData value of the node.
	 *
	 * @return OffsetToData value of the node.
	 */
	dword ResourceChild::getOffsetToData() const
	{
		return entry.irde.OffsetToData;
	}

	/**
	 * Sets the name of the node.
	 *
	 * @param strNewName New node name.
	 */
	void ResourceChild::setName(const std::string& strNewName)
	{
		entry.wstrName = strNewName;
	}

	/**
	 * Sets the Name value of the node.
	 *
	 * @param dwNewOffset Name value to set.
	 */
	void ResourceChild::setOffsetToName(dword dwNewOffset)
	{
		entry.irde.Name = dwNewOffset;
	}

	/**
	 * Sets the OffsetToData value of the node.
	 *
	 * @param dwNewOffset OffsetToData value to set.
	 */
	void ResourceChild::setOffsetToData(dword dwNewOffset)
	{
		entry.irde.OffsetToData = dwNewOffset;
	}

/*	unsigned int ResourceChild::size() const
	{
		return PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size()
			   + child->size()
			   + (entry.wstrName.size() ? entry.wstrName.size() + 2 : 0);
	}
*/
// -------------------------------------------------- ResourceElement -------------------------------------------

	/**
	* Returns the RVA of a ResourceElement. This is the RVA where the ResourceElement can be
	* found in the file.
	* @return RVA of the ResourceElement.
	**/
	unsigned int ResourceElement::getElementRva() const
	{
		return uiElementRva;
	}

	ResourceElement::ResourceElement() : uiElementRva(0)
	{

	}

// -------------------------------------------------- ResourceLeaf -------------------------------------------

	/**
	* Checks if a ResourceElement is a leaf or not.
	* @return Always returns true.
	**/
	bool ResourceLeaf::isLeaf() const
	{
		return true;
	}

	/**
	* Reads the next resource leaf from the input file.
	* @param inStream An input stream.
	* @param uiRsrcOffset Offset of resource directory in the file.
	* @param uiOffset Offset of the resource leaf that's to be read.
	* @param uiRva RVA of the beginning of the resource directory.
	* @param uiFileSize Size of the input file.
	* @param uiSizeOfImage Size of the image.
	* @param resDir Resource directory.
	**/
	int ResourceLeaf::read(
			std::istream& inStream,
			unsigned int uiRsrcOffset,
			unsigned int uiOffset,
			unsigned int uiRva,
			unsigned int uiFileSize,
			unsigned int /* uiSizeOfImage */,
			ResourceDirectory* resDir)
	{
		IStreamWrapper inStream_w(inStream);

		// Invalid leaf.
		if (uiRsrcOffset + uiOffset + PELIB_IMAGE_RESOURCE_DATA_ENTRY::size() > fileSize(inStream_w))
		{
			return ERROR_INVALID_FILE;
		}

		uiElementRva = uiOffset + uiRva;

		std::vector<unsigned char> vResourceDataEntry(PELIB_IMAGE_RESOURCE_DATA_ENTRY::size());
		inStream_w.seekg(uiRsrcOffset + uiOffset, std::ios_base::beg);
		inStream_w.read(reinterpret_cast<char*>(vResourceDataEntry.data()), PELIB_IMAGE_RESOURCE_DATA_ENTRY::size());

		InputBuffer inpBuffer(vResourceDataEntry);

		inpBuffer >> entry.OffsetToData;
		inpBuffer >> entry.Size;
		inpBuffer >> entry.CodePage;
		inpBuffer >> entry.Reserved;

		resDir->addOccupiedAddressRange(uiElementRva, uiElementRva + PELIB_IMAGE_RESOURCE_DATA_ENTRY::size() - 1);

		m_data.clear();

		unsigned int uiEntrySize = std::min(entry.Size, uiFileSize);

		// No data.
		if (!(entry.OffsetToData - uiRva + entry.Size))
		{
			return ERROR_NONE;
		}
		// Invalid leaf.
		else if (uiRsrcOffset + (entry.OffsetToData - uiRva) + uiEntrySize > uiFileSize)
		{
			return ERROR_NONE;
		}
		else if (entry.OffsetToData < uiRva)
		{
			return ERROR_NONE;
		}

		m_data.resize(uiEntrySize);

		inStream_w.seekg(uiRsrcOffset + (entry.OffsetToData - uiRva), std::ios_base::beg);
		inStream_w.read(reinterpret_cast<char*>(m_data.data()), uiEntrySize);

		if (uiEntrySize > 0)
		{
			resDir->addOccupiedAddressRange(entry.OffsetToData, entry.OffsetToData + uiEntrySize - 1);
		}

		return ERROR_NONE;
	}

	/**
	* Rebuilds the current resource leaf.
	* @param obBuffer OutputBuffer where the rebuilt resource leaf is stored.
	* @param uiOffset Offset of the resource leaf inside the resource directory.
	* @param uiRva RVA of the resource directory.
	**/
	void ResourceLeaf::rebuild(OutputBuffer& obBuffer, unsigned int uiOffset, unsigned int uiRva, const std::string&) const
	{
//		std::cout << std::hex << pad << "Leaf: " << uiOffset << std::endl;

//		obBuffer << entry.OffsetToData;
//		obBuffer << uiOffset;
		obBuffer.insert(uiOffset, entry.OffsetToData);
		obBuffer.insert(uiOffset + 4, entry.Size);
		obBuffer.insert(uiOffset + 8, entry.CodePage);
		obBuffer.insert(uiOffset + 12, entry.Reserved);

		for (unsigned int i=0;i<m_data.size();i++)
		{
			// If it is less than RVA, it means that data are out of directory
			// This is not ordinary but needs to be handled, otherwise few, usually packed samples won't work
			// Don't do nothing and let caller to make sure those data are present at the desired offset in the file
			if (entry.OffsetToData < uiRva)
				continue;

			obBuffer.insert(entry.OffsetToData - uiRva + i, m_data[i]);
		}
//		std::cout << "LeafChild: " << std::endl;
	}

	/**
	 * Recalculates the current node for directory with new RVA.
	 *
	 * @param uiCurrentOffset The current offset of the node in the new directory.
	 * @param uiNewRva The RVA of the new directory.
	 */
	void ResourceLeaf::recalculate(unsigned int& uiCurrentOffset, unsigned int uiNewRva)
	{
		uiCurrentOffset += PELIB_IMAGE_RESOURCE_DATA_ENTRY::size();
		setOffsetToData(uiCurrentOffset + uiNewRva);
		uiCurrentOffset += getSize();
	}

	void ResourceLeaf::makeValid()
	{
		entry.Size = static_cast<unsigned int>(m_data.size());
	}

/*	/// Returns the size of a resource leaf.
	unsigned int ResourceLeaf::size() const
	{
		return PELIB_IMAGE_RESOURCE_DATA_ENTRY::size() + m_data.size();
	}
*/

	/**
	* Returns a vector that contains the raw data of a resource leaf.
	* @return Raw data of the resource.
	**/
	std::vector<byte> ResourceLeaf::getData() const
	{
		return m_data;
	}

	/**
	* Overwrites the raw data of a resource.
	* @param vData New data of the resource.
	**/
	void ResourceLeaf::setData(const std::vector<byte>& vData)
	{
		m_data = vData;
	}

	/**
	* Returns the leaf's OffsetToData value. That's the RVA where the raw data of the resource
	* can be found.
	* @return The leaf's OffsetToData value.
	**/
	dword ResourceLeaf::getOffsetToData() const
	{
		return entry.OffsetToData;
	}

	/**
	* Returns the leaf's Size value. That's the size of the raw data of the resource.
	* @return The leaf's Size value.
	**/
	dword ResourceLeaf::getSize() const
	{
		return entry.Size;
	}

	/**
	* Returns the leaf's CodePage value.
	* @return The leaf's CodePage value.
	**/
	dword ResourceLeaf::getCodePage() const
	{
		return entry.CodePage;
	}

	/**
	* Returns the leaf's Reserved value.
	* @return The leaf's Reserved value.
	**/
	dword ResourceLeaf::getReserved() const
	{
		return entry.Reserved;
	}

	/**
	* Sets the leaf's OffsetToData value.
	* @param dwValue The leaf's new OffsetToData value.
	**/
	void ResourceLeaf::setOffsetToData(dword dwValue)
	{
		entry.OffsetToData = dwValue;
	}

	/**
	* Sets the leaf's Size value.
	* @param dwValue The leaf's new Size value.
	**/
	void ResourceLeaf::setSize(dword dwValue)
	{
		entry.Size = dwValue;
	}

	/**
	* Sets the leaf's CodePage value.
	* @param dwValue The leaf's new CodePage value.
	**/
	void ResourceLeaf::setCodePage(dword dwValue)
	{
		entry.CodePage = dwValue;
	}

	/**
	* Sets the leaf's Reserved value.
	* @param dwValue The leaf's new Reserved value.
	**/
	void ResourceLeaf::setReserved(dword dwValue)
	{
		entry.Reserved = dwValue;
	}

	ResourceLeaf::ResourceLeaf() : ResourceElement()
	{

	}

	ResourceLeaf::~ResourceLeaf()
	{

	}

// -------------------------------------------------- ResourceNode -------------------------------------------

	/**
	* Checks if a ResourceElement is a leaf or not.
	* @return Always returns false.
	**/
	bool ResourceNode::isLeaf() const
	{
		return false;
	}

	/**
	* Sorts the node's children and corrects the node's header.
	**/
	void ResourceNode::makeValid()
	{
		std::sort(children.begin(), children.end());
		header.NumberOfNamedEntries = static_cast<PeLib::word>(std::count_if(
				children.begin(),
				children.end(),
				[](const auto& i) { return i.isNamedResource(); }
		));
		header.NumberOfIdEntries = static_cast<unsigned int>(children.size()) - header.NumberOfNamedEntries;
	}

	/**
	* Rebuilds the current resource node.
	* @param obBuffer OutputBuffer where the rebuilt resource node is stored.
	* @param uiOffset Offset of the resource node inside the resource directory.
	* @param uiRva RVA of the resource directory.
	* @param pad Used for debugging.
	**/
	void ResourceNode::rebuild(OutputBuffer& obBuffer, unsigned int uiOffset, unsigned int uiRva, const std::string& pad) const
	{
/*		std::cout << std::hex << pad << uiOffset << std::endl;

		std::cout << std::hex << pad << "header.Characteristics: " << header.Characteristics << std::endl;
		std::cout << std::hex << pad << "header.TimeDateStamp: " << header.TimeDateStamp << std::endl;
		std::cout << std::hex << pad << "header.MajorVersion: "  << header.MajorVersion << std::endl;
		std::cout << std::hex << pad << "header.MinorVersion: "  << header.MinorVersion << std::endl;
		std::cout << std::hex << pad << "header.NumberOfNamedEntries: "  << header.NumberOfNamedEntries << std::endl;
		std::cout << std::hex << pad << "header.NumberOfIdEntries: "  << header.NumberOfIdEntries << std::endl;
*/
		obBuffer.insert(uiOffset, header.Characteristics);
		obBuffer.insert(uiOffset + 4, header.TimeDateStamp);
		obBuffer.insert(uiOffset + 8, header.MajorVersion);
		obBuffer.insert(uiOffset + 10, header.MinorVersion);
		//std::cout << pad << "Children: " << children.size() << std::endl;
		obBuffer.insert(uiOffset + 12, header.NumberOfNamedEntries);
		obBuffer.insert(uiOffset + 14, header.NumberOfIdEntries);

		uiOffset += PELIB_IMAGE_RESOURCE_DIRECTORY::size();

		for (unsigned int i=0;i<children.size();i++)
		{
			// (i << 3) == i * 8
			unsigned int uiChildOffset = uiOffset + (i << 3);

			obBuffer.insert(uiChildOffset, children[i].entry.irde.Name);
			obBuffer.insert(uiChildOffset + 4, children[i].entry.irde.OffsetToData);

			if (children[i].entry.irde.Name & PELIB_IMAGE_RESOURCE_NAME_IS_STRING)
			{
				unsigned int uiNameOffset = children[i].entry.irde.Name & ~PELIB_IMAGE_RESOURCE_NAME_IS_STRING;
				obBuffer.insert(uiNameOffset, (word)children[i].entry.wstrName.size());
				uiNameOffset += 2;

				for (unsigned int j = 0; j < children[i].entry.wstrName.size(); ++j)
				{
					obBuffer.insert(uiNameOffset, (word)children[i].entry.wstrName[j]);
					uiNameOffset += 2;
				}
			}

			if (children[i].entry.irde.OffsetToData & PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY)
				children[i].child->rebuild(obBuffer, children[i].entry.irde.OffsetToData & ~PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY, uiRva, pad);
			else
				children[i].child->rebuild(obBuffer, children[i].entry.irde.OffsetToData, uiRva, pad);
		}
	}

	/**
	 * Recalculates the current node and child nodes for directory with new RVA.
	 *
	 * @param uiCurrentOffset The current offset of the node in the new directory.
	 * @param uiNewRva The RVA of the new directory.
	 */
	void ResourceNode::recalculate(unsigned int& uiCurrentOffset, unsigned int uiNewRva)
	{
		// There is always directory and its entries at the beginning
		uiCurrentOffset += PELIB_IMAGE_RESOURCE_DIRECTORY::size();
		uiCurrentOffset += (PeLib::PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size() * getNumberOfChildren());

		for (unsigned int i = 0; i < getNumberOfChildren(); ++i)
		{
			// We need to store name of the named resource
			if (children[i].getOffsetToName() & PELIB_IMAGE_RESOURCE_NAME_IS_STRING)
			{
				children[i].setOffsetToName(PELIB_IMAGE_RESOURCE_NAME_IS_STRING | uiCurrentOffset);
				uiCurrentOffset = (unsigned int)(uiCurrentOffset + 2 + (children[i].getName().length() << 1));
			}

			// In case of non-leaf node, we recursively call this method on the current node
			if (children[i].getOffsetToData() & PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY)
			{
				children[i].setOffsetToData(PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY | uiCurrentOffset);
				children[i].getNode()->recalculate(uiCurrentOffset, uiNewRva);
			}
			else
			{
				children[i].setOffsetToData(uiCurrentOffset);
				children[i].getNode()->recalculate(uiCurrentOffset, uiNewRva);
			}
		}
	}

	/**
	* Reads the next resource node from the input file.
	* @param inStream An input stream.
	* @param uiRsrcOffset Offset of resource directory in the file.
	* @param uiOffset Offset of the resource node that's to be read.
	* @param uiRva RVA of the beginning of the resource directory.
	* @param uiFileSize Size of the input file.
	* @param uiSizeOfImage Size of the image.
	* @param resDir Resource directory.
	**/
	int ResourceNode::read(
			std::istream& inStream,
			unsigned int uiRsrcOffset,
			unsigned int uiOffset,
			unsigned int uiRva,
			unsigned int uiFileSize,
			unsigned int uiSizeOfImage,
			ResourceDirectory* resDir)
	{
		IStreamWrapper inStream_w(inStream);

		// Not enough space to be a valid node.
		if (!resDir || uiRsrcOffset + uiOffset + PELIB_IMAGE_RESOURCE_DIRECTORY::size() > fileSize(inStream_w))
		{
			return ERROR_INVALID_FILE;
		}

		uiElementRva = uiOffset + uiRva;

		std::vector<unsigned char> vResourceDirectory(PELIB_IMAGE_RESOURCE_DIRECTORY::size());
		inStream_w.seekg(uiRsrcOffset + uiOffset, std::ios_base::beg);
		inStream_w.read(reinterpret_cast<char*>(vResourceDirectory.data()), PELIB_IMAGE_RESOURCE_DIRECTORY::size());

		InputBuffer inpBuffer(vResourceDirectory);

		inpBuffer >> header.Characteristics;
		inpBuffer >> header.TimeDateStamp;
		inpBuffer >> header.MajorVersion;
		inpBuffer >> header.MinorVersion;
		inpBuffer >> header.NumberOfNamedEntries;
		inpBuffer >> header.NumberOfIdEntries;

		unsigned int uiNumberOfEntries = header.NumberOfNamedEntries + header.NumberOfIdEntries;

		resDir->addOccupiedAddressRange(uiElementRva, uiElementRva + PELIB_IMAGE_RESOURCE_DIRECTORY::size() - 1);

		// Windows loader check (PspLocateInPEManifest -> LdrpResGetResourceDirectory):
		// If the total number of resource entries goes beyond the image, the file is refused to run
		// Sample: 6318b0a1b57fc70bce5314aefb6cb06c90b7991afeae4e91ffc05ee0c88947d7
		// However, such sample can still be executed in Windows XP - based emulator
		if ((uiRva + (uiNumberOfEntries * PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size())) > uiSizeOfImage)
		{
			resDir->setLoaderError(LDR_ERROR_RSRC_OVER_END_OF_IMAGE);
			return ERROR_NONE;
		}

		// Not enough space to be a valid node.
		if (uiRsrcOffset + uiOffset + PELIB_IMAGE_RESOURCE_DIRECTORY::size() + uiNumberOfEntries * PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size() > fileSize(inStream_w))
		{
			return ERROR_INVALID_FILE;
		}

		std::vector<unsigned char> vResourceChildren(uiNumberOfEntries * PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size());
		inStream_w.read(reinterpret_cast<char*>(vResourceChildren.data()), uiNumberOfEntries * PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size());
		InputBuffer childInpBuffer(vResourceChildren);

		resDir->insertNodeOffset(uiOffset);
		if (uiNumberOfEntries > 0)
		{
			resDir->addOccupiedAddressRange(
					uiElementRva + PELIB_IMAGE_RESOURCE_DIRECTORY::size(),
					uiElementRva + PELIB_IMAGE_RESOURCE_DIRECTORY::size() + uiNumberOfEntries * PELIB_IMAGE_RESOURCE_DIRECTORY_ENTRY::size() - 1
				);
		}

		for (unsigned int i = 0; i < uiNumberOfEntries; ++i)
		{
			ResourceChild rc;
			childInpBuffer >> rc.entry.irde.Name;
			childInpBuffer >> rc.entry.irde.OffsetToData;

			unsigned int lastPos = inStream_w.tellg();

			if (rc.entry.irde.Name & PELIB_IMAGE_RESOURCE_NAME_IS_STRING)
			{
				// Enough space to read string length?
				if ((rc.entry.irde.Name & ~PELIB_IMAGE_RESOURCE_NAME_IS_STRING) + 2 < fileSize(inStream_w))
				{
					unsigned int uiNameOffset = rc.entry.irde.Name & ~PELIB_IMAGE_RESOURCE_NAME_IS_STRING;
					if (uiRsrcOffset + uiNameOffset + sizeof(word) > fileSize(inStream_w))
					{
						return ERROR_INVALID_FILE;
					}

					inStream_w.seekg(uiRsrcOffset + uiNameOffset, std::ios_base::beg);

					word len;
					inStream_w.read(reinterpret_cast<char*>(&len), sizeof(word));

					// Enough space to read string?
					if (uiRsrcOffset + uiNameOffset + 2 * len > fileSize(inStream_w))
					{
						return ERROR_INVALID_FILE;
					}

					// jk: This construction is incorrect on 64bit systems
					// wchar_t c;
					word c;
					for (word ii=0; ii<len; ++ii)
					{
						inStream_w.read(reinterpret_cast<char*>(&c), sizeof(word));
						rc.entry.wstrName += c;
					}
				}

				inStream_w.seekg(lastPos, std::ios_base::beg);
			}

			const auto value = (rc.entry.irde.OffsetToData & PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY) ?
				(rc.entry.irde.OffsetToData & ~PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY) : rc.entry.irde.OffsetToData;
			// Detect cycles to prevent infinite recursion.
			if (resDir->hasNodeOffset(value))
			{
				return ERROR_NONE;
			}

			if (rc.entry.irde.OffsetToData & PELIB_IMAGE_RESOURCE_DATA_IS_DIRECTORY)
			{
				rc.child = new ResourceNode;
			}
			else
			{
				rc.child = new ResourceLeaf;
			}

			if (rc.child->read(inStream_w, uiRsrcOffset, value, uiRva, uiFileSize, uiSizeOfImage, resDir) != ERROR_NONE)
			{
				return ERROR_INVALID_FILE;
			}

			children.push_back(rc);
			inStream_w.seekg(lastPos, std::ios_base::beg);
		}

		return ERROR_NONE;
	}

	/**
	* Returns the number of children of the current node. Note that this number is the number
	* of defined children, not the value from the header.
	* @return Number of node's children.
	**/
	unsigned int ResourceNode::getNumberOfChildren() const
	{
		return static_cast<unsigned int>(children.size());
	}

	/**
	* Adds another child to the current node.
	* @return Newly created ResourceChild.
	**/
	ResourceChild* ResourceNode::addChild()
	{
		ResourceChild c;
		c.child = 0;
		children.push_back(c);
		return &children[getNumberOfChildren() - 1];
	}

	/**
	* Returns a node's child.
	* @param uiIndex Index of the child.
	* @return The child identified by uiIndex.
	**/
	ResourceChild* ResourceNode::getChild(std::size_t uiIndex)
	{
		return &children[uiIndex];
	}

	/**
	* Returns a node's child.
	* @param uiIndex Index of the child.
	* @return The child identified by uiIndex.
	**/
	const ResourceChild* ResourceNode::getChild(std::size_t uiIndex) const
	{
		return &children[uiIndex];
	}

	/**
	* Removes a child from the current node.
	* @param uiIndex Index of the child.
	**/
	void ResourceNode::removeChild(unsigned int uiIndex)
	{
		children.erase(children.begin() + uiIndex);
	}

	/**
	* Returns the name of a child.
	* @param uiIndex Index of the child.
	* @return Either the name of the specified child or an empty string.
	**/
	std::string ResourceNode::getChildName(unsigned int uiIndex) const
	{
		return children[uiIndex].getName();
	}

	/**
	* Returns the Name value of a child.
	* @param uiIndex Index of the child.
	* @return Name value of a child.
	**/
	dword ResourceNode::getOffsetToChildName(unsigned int uiIndex) const
	{
		return children[uiIndex].getOffsetToName();
	}

	/**
	* Returns the OffsetToData value of a child.
	* @param uiIndex Index of the child.
	* @return OffsetToData value of a child.
	**/
	dword ResourceNode::getOffsetToChildData(unsigned int uiIndex) const
	{
		return children[uiIndex].getOffsetToData();
	}

	/**
	* Sets the name of a child.
	* @param uiIndex Index of the child.
	* @param strNewName New name of the resource.
	**/
	void ResourceNode::setChildName(unsigned int uiIndex, const std::string& strNewName)
	{
		children[uiIndex].setName(strNewName);
	}

	/**
	* Sets the Name value of a child.
	* @param uiIndex Index of the child.
	* @param dwNewOffset New Name value of the resource.
	**/
	void ResourceNode::setOffsetToChildName(unsigned int uiIndex, dword dwNewOffset)
	{
		children[uiIndex].setOffsetToName(dwNewOffset);
	}

	/**
	* Sets the OffsetToData value of a child.
	* @param uiIndex Index of the child.
	* @param dwNewOffset New OffsetToData value of the resource.
	**/
	void ResourceNode::setOffsetToChildData(unsigned int uiIndex, dword dwNewOffset)
	{
		children[uiIndex].setOffsetToData(dwNewOffset);
	}

	/**
	* Returns the Characteristics value of the node.
	* @return Characteristics value of the node.
	**/
	dword ResourceNode::getCharacteristics() const
	{
		return header.Characteristics;
	}

	/**
	* Returns the TimeDateStamp value of the node.
	* @return TimeDateStamp value of the node.
	**/
	dword ResourceNode::getTimeDateStamp() const
	{
		return header.TimeDateStamp;
	}

	/**
	* Returns the MajorVersion value of the node.
	* @return MajorVersion value of the node.
	**/
	word ResourceNode::getMajorVersion() const
	{
		return header.MajorVersion;
	}

	/**
	* Returns the MinorVersion value of the node.
	* @return MinorVersion value of the node.
	**/
	word ResourceNode::getMinorVersion() const
	{
		return header.MinorVersion;
	}

	/**
	* Returns the NumberOfNamedEntries value of the node.
	* @return NumberOfNamedEntries value of the node.
	**/
	word ResourceNode::getNumberOfNamedEntries() const
	{
		return header.NumberOfNamedEntries;
	}

	/**
	* Returns the NumberOfIdEntries value of the node.
	* @return NumberOfIdEntries value of the node.
	**/
	word ResourceNode::getNumberOfIdEntries() const
	{
		return header.NumberOfIdEntries;
	}

	/**
	* Sets the Characteristics value of the node.
	* @param value New Characteristics value of the node.
	**/
	void ResourceNode::setCharacteristics(dword value)
	{
		header.Characteristics = value;
	}

	/**
	* Sets the TimeDateStamp value of the node.
	* @param value New TimeDateStamp value of the node.
	**/
	void ResourceNode::setTimeDateStamp(dword value)
	{
		header.TimeDateStamp = value;
	}

	/**
	* Sets the MajorVersion value of the node.
	* @param value New MajorVersion value of the node.
	**/
	void ResourceNode::setMajorVersion(word value)
	{
		header.MajorVersion = value;
	}

	/**
	* Sets the MinorVersion value of the node.
	* @param value New MinorVersion value of the node.
	**/
	void ResourceNode::setMinorVersion(word value)
	{
		header.MinorVersion = value;
	}

	/**
	* Sets the NumberOfNamedEntries value of the node.
	* @param value New NumberOfNamedEntries value of the node.
	**/
	void ResourceNode::setNumberOfNamedEntries(word value)
	{
		header.NumberOfNamedEntries = value;
	}

	/**
	* Sets the NumberOfIdEntries value of the node.
	* @param value New NumberOfIdEntries value of the node.
	**/
	void ResourceNode::setNumberOfIdEntries(word value)
	{
		header.NumberOfIdEntries = value;
	}

/*	/// Returns the size of a resource node.
	unsigned int ResourceNode::size() const
	{
		if (children.size())
		{
			std::cout << std::accumulate(children.begin(), children.end(), 0, accumulate<ResourceChild>) << std::endl;
			return PELIB_IMAGE_RESOURCE_DIRECTORY::size()
					 + std::accumulate(children.begin(), children.end(), 0, accumulate<ResourceChild>);
		}
		else
		{
			return 0;
		}
	}
*/

	ResourceNode::ResourceNode() : ResourceElement()
	{

	}

	ResourceNode::~ResourceNode()
	{

	}

// -------------------------------------------------- ResourceDirectory -------------------------------------------

	/**
	* Constructor
	*/
	ResourceDirectory::ResourceDirectory() : m_readOffset(0), m_ldrError(LDR_ERROR_NONE)
	{

	}

	/**
	* Returns the root node of the resource directory.
	* @return Root node of the resource directory.
	**/
	ResourceNode* ResourceDirectory::getRoot()
	{
		return &m_rnRoot;
	}

	/**
	* Returns the root node of the resource directory.
	* @return Root node of the resource directory.
	**/
	const ResourceNode* ResourceDirectory::getRoot() const
	{
		return &m_rnRoot;
	}

	/**
	* Get the error that was detected during resource parsing
	**/
	LoaderError ResourceDirectory::loaderError() const
	{
		return m_ldrError;
	}

	void ResourceDirectory::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	/**
	* Correctly sorts the resource nodes of the resource tree. This function should be called
	* before calling rebuild.
	**/
	void ResourceDirectory::makeValid()
	{
		m_rnRoot.makeValid();
	}

	/**
	* Rebuilds the resource directory.
	* @param vBuffer Buffer the source directory will be written to.
	* @param uiRva RVA of the resource directory.
	**/
	void ResourceDirectory::rebuild(std::vector<byte>& vBuffer, unsigned int uiRva) const
	{
		OutputBuffer obBuffer(vBuffer);
		unsigned int offs = 0;
//		std::cout << "Root: " << m_rnRoot.children.size() << std::endl;
		m_rnRoot.rebuild(obBuffer, offs, uiRva, "");
	}

	/**
	 * Recalculates the resource directory for directory with new RVA.
	 *
	 * @param uiNewSize The size of the new directory. Is recalculated after the whole resource tree is traversed.
	 * @param uiNewRva The RVA of the new directory.
	 */
	void ResourceDirectory::recalculate(unsigned int& uiNewSize, unsigned int uiNewRva)
	{
		uiNewSize = 0;
		m_rnRoot.recalculate(uiNewSize, uiNewRva);
	}

	/**
	* Returns the size of the entire rebuilt resource directory. That's the size of the entire
	* structure as it's written back to a file.
	**/
/*	unsigned int ResourceDirectory::size() const
	{
		return m_rnRoot.size();
	}
*/
	/**
	* Writes the current resource directory back into a file.
	* @param strFilename Name of the output file.
	* @param uiOffset File offset where the resource directory will be written to.
	* @param uiRva RVA of the file offset.
	**/
	int ResourceDirectory::write(const std::string& strFilename, unsigned int uiOffset, unsigned int uiRva) const
	{
		std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

		if (!ofFile)
		{
			ofFile.clear();
			ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
		}
		else
		{
			ofFile.close();
			ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		}

		if (!ofFile)
		{
			return ERROR_OPENING_FILE;
		}

		ofFile.seekp(uiOffset, std::ios::beg);

		std::vector<unsigned char> vBuffer;
		rebuild(vBuffer, uiRva);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Adds another resource type. The new resource type is identified by the ID dwResTypeId.
	* @param dwResTypeId ID which identifies the resource type.
	**/
	int ResourceDirectory::addResourceType(dword dwResTypeId)
	{
		std::vector<ResourceChild>::iterator Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalId(dwResTypeId); }
		);
		if (Iter != m_rnRoot.children.end())
		{
			return ERROR_DUPLICATE_ENTRY;
			// throw Exceptions::EntryAlreadyExists(ResourceDirectoryId, __LINE__);
		}

		ResourceChild rcCurr;
		rcCurr.child = new ResourceNode;
		rcCurr.entry.irde.Name = dwResTypeId;
		m_rnRoot.children.push_back(rcCurr);

		return ERROR_NONE;
	}

	/**
	* Adds another resource type. The new resource type is identified by the name strResTypeName.
	* @param strResTypeName Name which identifies the resource type.
	**/
	int ResourceDirectory::addResourceType(const std::string& strResTypeName)
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalName(strResTypeName); }
		);
		if (Iter != m_rnRoot.children.end())
		{
			return ERROR_DUPLICATE_ENTRY;
//			throw Exceptions::EntryAlreadyExists(ResourceDirectoryId, __LINE__);
		}

		ResourceChild rcCurr;
		rcCurr.entry.wstrName = strResTypeName;
		rcCurr.child = new ResourceNode;
		m_rnRoot.children.push_back(rcCurr);

		return ERROR_NONE;
	}

	/**
	* Removes the resource type identified by the ID dwResTypeId.
	* @param dwResTypeId ID which identifies the resource type.
	**/
	int ResourceDirectory::removeResourceType(dword dwResTypeId)
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalId(dwResTypeId); }
		);
		if (Iter == m_rnRoot.children.end())
		{
			return ERROR_ENTRY_NOT_FOUND;
//			throw Exceptions::ResourceTypeDoesNotExist(ResourceDirectoryId, __LINE__);
		}

		bool isNamed = false;
		if (Iter->isNamedResource()) isNamed = true;

		m_rnRoot.children.erase(Iter);

		if (isNamed) m_rnRoot.header.NumberOfNamedEntries = static_cast<PeLib::word>(m_rnRoot.children.size());
		else m_rnRoot.header.NumberOfIdEntries = static_cast<PeLib::word>(m_rnRoot.children.size());

		return ERROR_NONE;
	}

	/**
	* Removes the resource type identified by the name strResTypeName.
	* @param strResTypeName Name which identifies the resource type.
	**/
	int ResourceDirectory::removeResourceType(const std::string& strResTypeName)
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalName(strResTypeName); }
		);
		if (Iter == m_rnRoot.children.end())
		{
			return ERROR_ENTRY_NOT_FOUND;
		//	throw Exceptions::ResourceTypeDoesNotExist(ResourceDirectoryId, __LINE__);
		}

		bool isNamed = false;
		if (Iter->isNamedResource()) isNamed = true;

		m_rnRoot.children.erase(Iter);

		if (isNamed) m_rnRoot.header.NumberOfNamedEntries = static_cast<PeLib::word>(m_rnRoot.children.size());
		else m_rnRoot.header.NumberOfIdEntries = static_cast<PeLib::word>(m_rnRoot.children.size());

		return ERROR_NONE;
	}

	/**
	* Removes the resource type identified by the index uiIndex.
	* @param uiIndex Index which identifies the resource type.
	**/
	int ResourceDirectory::removeResourceTypeByIndex(unsigned int uiIndex)
	{
		bool isNamed = false;
		if (m_rnRoot.children[uiIndex].isNamedResource()) isNamed = true;

		m_rnRoot.children.erase(m_rnRoot.children.begin() + uiIndex);

		if (isNamed) m_rnRoot.header.NumberOfNamedEntries = static_cast<PeLib::word>(m_rnRoot.children.size());
		else m_rnRoot.header.NumberOfIdEntries = static_cast<PeLib::word>(m_rnRoot.children.size());

		return ERROR_NONE;
	}

	/**
	* Adds another resource to the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param dwResTypeId ID of the resource type.
	* @param dwResId ID of the resource.
	**/
	int ResourceDirectory::addResource(dword dwResTypeId, dword dwResId)
	{
		ResourceChild rcCurr;
		rcCurr.entry.irde.Name = dwResId;
		return addResourceT(dwResTypeId, dwResId, rcCurr);
	}

	/**
	* Adds another resource to the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param dwResTypeId ID of the resource type.
	* @param strResName Name of the resource.
	**/
	int ResourceDirectory::addResource(dword dwResTypeId, const std::string& strResName)
	{
		ResourceChild rcCurr;
		rcCurr.entry.wstrName = strResName;
		return addResourceT(dwResTypeId, strResName, rcCurr);
	}

	/**
	* Adds another resource to the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param strResTypeName Name of the resource type.
	* @param dwResId ID of the resource.
	**/
	int ResourceDirectory::addResource(const std::string& strResTypeName, dword dwResId)
	{
		ResourceChild rcCurr;
		rcCurr.entry.irde.Name = dwResId;
		return addResourceT(strResTypeName, dwResId, rcCurr);
	}

	/**
	* Adds another resource to the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param strResTypeName Name of the resource type.
	* @param strResName Name of the resource.
	**/
	int ResourceDirectory::addResource(const std::string& strResTypeName, const std::string& strResName)
	{
		ResourceChild rcCurr;
		rcCurr.entry.wstrName = strResName;
		return addResourceT(strResTypeName, strResName, rcCurr);
	}

	/**
	* Removes a resource from the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param dwResTypeIndex ID of the resource type.
	* @param dwResId ID of the resource.
	**/
	int ResourceDirectory::removeResource(dword dwResTypeIndex, dword dwResId)
	{
		return removeResourceT(dwResTypeIndex, dwResId);
	}

	/**
	* Removes a resource from the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param dwResTypeIndex ID of the resource type.
	* @param strResName Name of the resource.
	**/
	int ResourceDirectory::removeResource(dword dwResTypeIndex, const std::string& strResName)
	{
		return removeResourceT(dwResTypeIndex, strResName);
	}

	/**
	* Removes a resource from the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param strResTypeName Name of the resource type.
	* @param dwResId ID of the resource.
	**/
	int ResourceDirectory::removeResource(const std::string& strResTypeName, dword dwResId)
	{
		return removeResourceT(strResTypeName, dwResId);
	}

	/**
	* Removes a resource from the resource tree. The first parameter identifies the resource type
	* of the new resource, the second parameter identifies the resource itself.
	* @param strResTypeName Name of the resource type.
	* @param strResName Name of the resource.
	**/
	int ResourceDirectory::removeResource(const std::string& strResTypeName, const std::string& strResName)
	{
		return removeResourceT(strResTypeName, strResName);
	}

	/**
	* Returns start offset of resource directory in file.
	**/
	unsigned int ResourceDirectory::getOffset() const
	{
		return m_readOffset;
	}

	/**
	* Returns the number of resource types.
	**/
	unsigned int ResourceDirectory::getNumberOfResourceTypes() const
	{
		return static_cast<unsigned int>(m_rnRoot.children.size());
	}

	/**
	* Returns the ID of a resource type which was specified through an index.
	* The valid range of the parameter uiIndex is 0...getNumberOfResourceTypes() - 1.
	* Leaving the invalid range leads to undefined behaviour.
	* @param uiIndex Index which identifies a resource type.
	* @return The ID of the specified resource type.
	**/
	dword ResourceDirectory::getResourceTypeIdByIndex(unsigned int uiIndex) const
	{
		return m_rnRoot.children[uiIndex].entry.irde.Name;
	}

	/**
	* Returns the name of a resource type which was specified through an index.
	* The valid range of the parameter uiIndex is 0...getNumberOfResourceTypes() - 1.
	* Leaving the invalid range leads to undefined behaviour.
	* @param uiIndex Index which identifies a resource type.
	* @return The name of the specified resource type.
	**/
	std::string ResourceDirectory::getResourceTypeNameByIndex(unsigned int uiIndex) const
	{
		return m_rnRoot.children[uiIndex].entry.wstrName;
	}

	/**
	* Converts the ID of a resource type to an index.
	* @param dwResTypeId ID of the resource type.
	* @return Index of that resource type.
	**/
	int ResourceDirectory::resourceTypeIdToIndex(dword dwResTypeId) const
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalId(dwResTypeId); }
		);
		if (Iter == m_rnRoot.children.end()) return -1;
		return static_cast<unsigned int>(std::distance(m_rnRoot.children.begin(), Iter));
	}

	/**
	* Converts the name of a resource type to an index.
	* @param strResTypeName ID of the resource type.
	* @return Index of that resource type.
	**/
	int ResourceDirectory::resourceTypeNameToIndex(const std::string& strResTypeName) const
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalName(strResTypeName); }
		);
		if (Iter == m_rnRoot.children.end()) return -1;
		return static_cast<unsigned int>(std::distance(m_rnRoot.children.begin(), Iter));
	}

	/**
	* Returns the number of resources of a specific resource type.
	* @param dwId ID of the resource type.
	* @return Number of resources of resource type dwId.
	**/
	unsigned int ResourceDirectory::getNumberOfResources(dword dwId) const
	{
//		std::vector<ResourceChild>::const_iterator IterD = m_rnRoot.children.begin();
//		std::cout << dwId << std::endl;
//		while (IterD != m_rnRoot.children.end())
//		{
//			std::cout << IterD->entry.irde.Name << std::endl;
//			++IterD;
//		}

		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalId(dwId); }
		);
		if (Iter == m_rnRoot.children.end())
		{
			return 0xFFFFFFFF;
		}
		else
		{
			ResourceNode* currNode = static_cast<ResourceNode*>(Iter->child);
			return static_cast<unsigned int>(currNode->children.size());
		}
	}

	/**
	* Returns the number of resources of a specific resource type.
	* @param strResTypeName Name of the resource type.
	* @return Number of resources of resource type strResTypeName.
	**/
	unsigned int ResourceDirectory::getNumberOfResources(const std::string& strResTypeName) const
	{
		auto Iter = std::find_if(
				m_rnRoot.children.begin(),
				m_rnRoot.children.end(),
				[&](const auto& i) { return i.equalName(strResTypeName); }
		);
		if (Iter == m_rnRoot.children.end())
		{
			return 0xFFFFFFFF;
		}
		else
		{
			ResourceNode* currNode = static_cast<ResourceNode*>(Iter->child);
			return static_cast<unsigned int>(currNode->children.size());
		}
	}

	/**
	* Returns the number of resources of a resource type which was specified through an index.
	* The valid range of the parameter uiIndex is 0...getNumberOfResourceTypes() - 1.
	* Leaving the invalid range leads to undefined behaviour.
	* @param uiIndex Index which identifies a resource type.
	* @return The number of resources of the specified resource type.
	**/
	unsigned int ResourceDirectory::getNumberOfResourcesByIndex(unsigned int uiIndex) const
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiIndex].child);
		return static_cast<unsigned int>(currNode->children.size());
	}

	/**
	* Gets the resource data of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param data Vector where the data is stored.
	**/
	void ResourceDirectory::getResourceData(dword dwResTypeId, dword dwResId, std::vector<byte>& data) const
	{
		getResourceDataT(dwResTypeId, dwResId, data);
	}

	/**
	* Gets the resource data of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param data Vector where the data is stored.
	**/
	void ResourceDirectory::getResourceData(dword dwResTypeId, const std::string& strResName, std::vector<byte>& data) const
	{
		getResourceDataT(dwResTypeId, strResName, data);
	}

	/**
	* Gets the resource data of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param data Vector where the data is stored.
	**/
	void ResourceDirectory::getResourceData(const std::string& strResTypeName, dword dwResId, std::vector<byte>& data) const
	{
		getResourceDataT(strResTypeName, dwResId, data);
	}

	/**
	* Gets the resource data of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param data Vector where the data is stored.
	**/
	void ResourceDirectory::getResourceData(const std::string& strResTypeName, const std::string& strResName, std::vector<byte>& data) const
	{
		getResourceDataT(strResTypeName, strResName, data);
	}

	/**
	* Gets the resource data of a specific resource by index.
	* The valid range of the parameter uiResTypeIndex is 0...getNumberOfResourceTypes() - 1.
	* The valid range of the parameter uiResIndex is 0...getNumberOfResources() - 1.
	* Leaving the invalid range leads to undefined behaviour.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @param data Vector where the data is stored.
	**/
	void ResourceDirectory::getResourceDataByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex, std::vector<byte>& data) const
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		currNode = static_cast<ResourceNode*>(currNode->children[uiResIndex].child);
		ResourceLeaf* currLeaf = static_cast<ResourceLeaf*>(currNode->children[0].child);

		data.assign(currLeaf->m_data.begin(), currLeaf->m_data.end());
	}

	/**
	* Sets the resource data of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param data The new resource data.
	**/
	void ResourceDirectory::setResourceData(dword dwResTypeId, dword dwResId, std::vector<byte>& data)
	{
		setResourceDataT(dwResTypeId, dwResId, data);
	}

	/**
	* Sets the resource data of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param data The new resource data.
	**/
	void ResourceDirectory::setResourceData(dword dwResTypeId, const std::string& strResName, std::vector<byte>& data)
	{
		setResourceDataT(dwResTypeId, strResName, data);
	}

	/**
	* Sets the resource data of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param data The new resource data.
	**/
	void ResourceDirectory::setResourceData(const std::string& strResTypeName, dword dwResId, std::vector<byte>& data)
	{
		setResourceDataT(strResTypeName, dwResId, data);
	}

	/**
	* Sets the resource data of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param data The new resource data.
	**/
	void ResourceDirectory::setResourceData(const std::string& strResTypeName, const std::string& strResName, std::vector<byte>& data)
	{
		setResourceDataT(strResTypeName, strResName, data);
	}

	/**
	* Sets the resource data of a specific resource by index.
	* The valid range of the parameter uiResTypeIndex is 0...getNumberOfResourceTypes() - 1.
	* The valid range of the parameter uiResIndex is 0...getNumberOfResources() - 1.
	* Leaving the invalid range leads to undefined behaviour.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @param data The new resource data.
	**/
	void ResourceDirectory::setResourceDataByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex, std::vector<byte>& data)
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		currNode = static_cast<ResourceNode*>(currNode->children[uiResIndex].child);
		ResourceLeaf* currLeaf = static_cast<ResourceLeaf*>(currNode->children[0].child);
		currLeaf->m_data.assign(data.begin(), data.end());
	}

	/**
	* Gets the ID of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @return ID of the specified resource.
	**/
	dword ResourceDirectory::getResourceId(dword dwResTypeId, const std::string& strResName) const
	{
		return getResourceIdT(dwResTypeId, strResName);
	}

	/**
	* Gets the ID of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @return ID of the specified resource.
	**/
	dword ResourceDirectory::getResourceId(const std::string& strResTypeName, const std::string& strResName) const
	{
		return getResourceIdT(strResTypeName, strResName);
	}

	/**
	* Gets the ID of a specific resource by index.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @return ID of the specified resource.
	**/
	dword ResourceDirectory::getResourceIdByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex) const
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		return currNode->children[uiResIndex].entry.irde.Name;
	}

	/**
	* Sets the ID of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param dwNewResId New ID of the resource.
	**/
	void ResourceDirectory::setResourceId(dword dwResTypeId, dword dwResId, dword dwNewResId)
	{
		setResourceIdT(dwResTypeId, dwResId, dwNewResId);
	}

	/**
	* Sets the ID of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param dwNewResId New ID of the resource.
	**/
	void ResourceDirectory::setResourceId(dword dwResTypeId, const std::string& strResName, dword dwNewResId)
	{
		setResourceIdT(dwResTypeId, strResName, dwNewResId);
	}

	/**
	* Sets the ID of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param dwNewResId New ID of the resource.
	**/
	void ResourceDirectory::setResourceId(const std::string& strResTypeName, dword dwResId, dword dwNewResId)
	{
		setResourceIdT(strResTypeName, dwResId, dwNewResId);
	}

	/**
	* Sets the ID of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param dwNewResId New ID of the resource.
	**/
	void ResourceDirectory::setResourceId(const std::string& strResTypeName, const std::string& strResName, dword dwNewResId)
	{
		setResourceIdT(strResTypeName, strResName, dwNewResId);
	}

	/**
	* Sets the ID of a specific resource by index.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @param dwNewResId New ID of the specified resource.
	**/
	void ResourceDirectory::setResourceIdByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex, dword dwNewResId)
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		currNode->children[uiResIndex].entry.irde.Name = dwNewResId;
	}

	/**
	* Gets the Name of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @return Name of the specified resource.
	**/
	std::string ResourceDirectory::getResourceName(dword dwResTypeId, dword dwResId) const
	{
		return getResourceNameT(dwResTypeId, dwResId);
	}

	/**
	* Gets the Name of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @return Name of the specified resource.
	**/
	std::string ResourceDirectory::getResourceName(const std::string& strResTypeName, dword dwResId) const
	{
		return getResourceNameT(strResTypeName, dwResId);
	}

	/**
	* Gets the name of a specific resource by index.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @return Name of the specified resource.
	**/
	std::string ResourceDirectory::getResourceNameByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex) const
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		return currNode->children[uiResIndex].entry.wstrName;
	}

	/**
	* Sets the name of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param strNewResName New name of the specified resource.
	**/
	void ResourceDirectory::setResourceName(dword dwResTypeId, dword dwResId, const std::string& strNewResName)
	{
		setResourceNameT(dwResTypeId, dwResId, strNewResName);
	}

	/**
	* Sets the name of a specific resource.
	* @param dwResTypeId Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param strNewResName New name of the specified resource.
	**/
	void ResourceDirectory::setResourceName(dword dwResTypeId, const std::string& strResName, const std::string& strNewResName)
	{
		setResourceNameT(dwResTypeId, strResName, strNewResName);
	}

	/**
	* Sets the name of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param dwResId Identifies the resource.
	* @param strNewResName New name of the specified resource.
	**/
	void ResourceDirectory::setResourceName(const std::string& strResTypeName, dword dwResId, const std::string& strNewResName)
	{
		setResourceNameT(strResTypeName, dwResId, strNewResName);
	}

	/**
	* Sets the name of a specific resource.
	* @param strResTypeName Identifies the resource type of the resource.
	* @param strResName Identifies the resource.
	* @param strNewResName New name of the specified resource.
	**/
	void ResourceDirectory::setResourceName(const std::string& strResTypeName, const std::string& strResName, const std::string& strNewResName)
	{
		setResourceNameT(strResTypeName, strResName, strNewResName);
	}

	/**
	* Sets the name of a specific resource by index.
	* @param uiResTypeIndex Identifies the resource type of the resource.
	* @param uiResIndex Identifies the resource.
	* @param strNewResName New name of the specified resource.
	**/
	void ResourceDirectory::setResourceNameByIndex(unsigned int uiResTypeIndex, unsigned int uiResIndex, const std::string& strNewResName)
	{
		ResourceNode* currNode = static_cast<ResourceNode*>(m_rnRoot.children[uiResTypeIndex].child);
		currNode->children[uiResIndex].entry.wstrName = strNewResName;
	}

	/**
	* Insert offset of loaded node.
	* @param nodeOffset Offset of loaded node.
	*/
	void ResourceDirectory::insertNodeOffset(std::size_t nodeOffset)
	{
		m_resourceNodeOffsets.insert(nodeOffset);
	}

	/**
	* Check if node with specified offset was loaded.
	* @param nodeOffset Offset of node.
	*/
	bool ResourceDirectory::hasNodeOffset(std::size_t nodeOffset) const
	{
		return m_resourceNodeOffsets.find(nodeOffset) != m_resourceNodeOffsets.end();
	}

	void ResourceDirectory::addOccupiedAddressRange(unsigned int start, unsigned int end)
	{
		m_occupiedAddresses.emplace_back(start, end);
	}

	const std::vector<std::pair<unsigned int, unsigned int>>& ResourceDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}
}
