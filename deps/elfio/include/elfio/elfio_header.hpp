/*
Copyright (C) 2001-2015 by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef ELF_HEADER_HPP
#define ELF_HEADER_HPP

#include <iostream>

namespace ELFIO {

class elf_header
{
  public:
    virtual ~elf_header() {};
    virtual bool load( std::istream& stream )       = 0;
    virtual bool save( std::ostream& stream ) const = 0;

    // ELF header functions
    ELFIO_GET_ACCESS_DECL( unsigned char, class              );
    ELFIO_GET_ACCESS_DECL( unsigned char, elf_version        );
    ELFIO_GET_ACCESS_DECL( unsigned char, encoding           );
    ELFIO_GET_ACCESS_DECL( Elf_Word,      version            );
    ELFIO_GET_ACCESS_DECL( Elf_Half,      header_size        );
    ELFIO_GET_ACCESS_DECL( Elf_Half,      section_entry_size );
    ELFIO_GET_ACCESS_DECL( Elf_Half,      segment_entry_size );

    ELFIO_GET_SET_ACCESS_DECL( unsigned char, os_abi          );
    ELFIO_GET_SET_ACCESS_DECL( unsigned char, abi_version     );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Half,      type            );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Half,      machine         );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Word,      flags           );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Addr,    entry           );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Half,      sections_num    );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Off,     sections_offset );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Half,      segments_num    );
    ELFIO_GET_SET_ACCESS_DECL( Elf64_Off,     segments_offset );
    ELFIO_GET_SET_ACCESS_DECL( Elf_Half,      section_name_str_index );
};

template< class T > struct elf_header_impl_types;
template<> struct elf_header_impl_types<Elf32_Ehdr> {
    typedef Elf32_Phdr Phdr_type;
    typedef Elf32_Shdr Shdr_type;
    static const unsigned char file_class = ELFCLASS32;
};
template<> struct elf_header_impl_types<Elf64_Ehdr> {
    typedef Elf64_Phdr Phdr_type;
    typedef Elf64_Shdr Shdr_type;
    static const unsigned char file_class = ELFCLASS64;
};

template< class T > class elf_header_impl : public elf_header
{
  public:
    elf_header_impl( endianess_convertor* convertor_,
                     unsigned char encoding )
    {
        convertor = convertor_;

        std::fill_n( reinterpret_cast<char*>( &header ), sizeof( header ), '\0' );

        header.e_ident[EI_MAG0]    = ELFMAG0;
        header.e_ident[EI_MAG1]    = ELFMAG1;
        header.e_ident[EI_MAG2]    = ELFMAG2;
        header.e_ident[EI_MAG3]    = ELFMAG3;
        header.e_ident[EI_CLASS]   = elf_header_impl_types<T>::file_class;
        header.e_ident[EI_DATA]    = encoding;
        header.e_ident[EI_VERSION] = EV_CURRENT;
        header.e_version           = EV_CURRENT;
        header.e_version           = (*convertor)( header.e_version );
        header.e_ehsize            = ( sizeof( header ) );
        header.e_ehsize            = (*convertor)( header.e_ehsize );
        header.e_shstrndx          = (*convertor)( (Elf_Half)1 );
        header.e_phentsize         = sizeof( typename elf_header_impl_types<T>::Phdr_type );
        header.e_shentsize         = sizeof( typename elf_header_impl_types<T>::Shdr_type );
        header.e_phentsize         = (*convertor)( header.e_phentsize );
        header.e_shentsize         = (*convertor)( header.e_shentsize );
    }

    bool
    load( std::istream& stream )
    {
        stream.seekg( 0 );
        stream.read( reinterpret_cast<char*>( &header ), sizeof( header ) );
        header.e_ident[EI_CLASS] = elf_header_impl_types<T>::file_class;

        return (stream.gcount() == sizeof( header ) );
    }

    bool
    save( std::ostream& stream ) const
    {
        stream.seekp( 0 );
        stream.write( reinterpret_cast<const char*>( &header ), sizeof( header ) );

        return stream.good();
    }

    // ELF header functions
    ELFIO_GET_ACCESS( unsigned char, class,              header.e_ident[EI_CLASS] );
    ELFIO_GET_ACCESS( unsigned char, elf_version,        header.e_ident[EI_VERSION] );
    ELFIO_GET_ACCESS( unsigned char, encoding,           header.e_ident[EI_DATA] );
    ELFIO_GET_ACCESS( Elf_Word,      version,            header.e_version );
    ELFIO_GET_ACCESS( Elf_Half,      header_size,        header.e_ehsize );
    ELFIO_GET_ACCESS( Elf_Half,      section_entry_size, header.e_shentsize );
    ELFIO_GET_ACCESS( Elf_Half,      segment_entry_size, header.e_phentsize );

    ELFIO_GET_SET_ACCESS( unsigned char, os_abi,          header.e_ident[EI_OSABI] );
    ELFIO_GET_SET_ACCESS( unsigned char, abi_version,     header.e_ident[EI_ABIVERSION] );
    ELFIO_GET_SET_ACCESS( Elf_Half,      type,            header.e_type );
    ELFIO_GET_SET_ACCESS( Elf_Half,      machine,         header.e_machine );
    ELFIO_GET_SET_ACCESS( Elf_Word,      flags,           header.e_flags );
    ELFIO_GET_SET_ACCESS( Elf_Half,      section_name_str_index, header.e_shstrndx );
    ELFIO_GET_SET_ACCESS( Elf64_Addr,    entry,           header.e_entry );
    ELFIO_GET_SET_ACCESS( Elf_Half,      sections_num,    header.e_shnum );
    ELFIO_GET_SET_ACCESS( Elf64_Off,     sections_offset, header.e_shoff );
    ELFIO_GET_SET_ACCESS( Elf_Half,      segments_num,    header.e_phnum );
    ELFIO_GET_SET_ACCESS( Elf64_Off,     segments_offset, header.e_phoff );

  private:
    T header;
    endianess_convertor* convertor;
};

} // namespace ELFIO

#endif // ELF_HEADER_HPP
