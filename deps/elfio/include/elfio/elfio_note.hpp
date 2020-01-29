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

#ifndef ELFIO_NOTE_HPP
#define ELFIO_NOTE_HPP

namespace ELFIO {

//------------------------------------------------------------------------------
// There are discrepancies in documentations. SCO documentation
// (http://www.sco.com/developers/gabi/latest/ch5.pheader.html#note_section)
// requires 8 byte entries alignment for 64-bit ELF file,
// but Oracle's definition uses the same structure
// for 32-bit and 64-bit formats.
// (https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-18048.html)
//
// It looks like EM_X86_64 Linux implementation is similar to Oracle's
// definition. Therefore, the same alignment works for both formats
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
class note_section_accessor
{
  public:
//------------------------------------------------------------------------------
    note_section_accessor( const elfio& elf_file_, section* section_ ) :
                           elf_file( elf_file_ ), note_section( section_ )
    {
        process_section();
    }

//------------------------------------------------------------------------------
    Elf_Word
    get_notes_num() const
    {
        return (Elf_Word)note_start_positions.size();
    }

//------------------------------------------------------------------------------
    bool
    get_note( Elf_Word     index,
              Elf_Word&    type,
              std::string& name,
              void*&       desc,
              Elf_Word&    descSize ) const
    {
        if ( index >= note_section->get_size() ) {
            return false;
        }

        const char* pData = note_section->get_data() + note_start_positions[index];
        int align = sizeof( Elf_Word );

        const endianess_convertor& convertor = elf_file.get_convertor();
        type = convertor( *(Elf_Word*)( pData + 2*align ) );
        Elf_Word namesz = convertor( *(Elf_Word*)( pData ) );
        descSize = convertor( *(Elf_Word*)( pData + sizeof( namesz ) ) );
        Elf_Word max_name_size = note_section->get_size() - note_start_positions[index];
        if ( namesz            > max_name_size ||
             namesz + descSize > max_name_size ) {
            return false;
        }
        name.assign( pData + 3*align, namesz - 1);
        if ( 0 == descSize ) {
            desc = 0;
        }
        else {
            desc = const_cast<char*> ( pData + 3*align +
                                       ( ( namesz + align - 1 )/align )*align );
        }

        return true;
    }

//------------------------------------------------------------------------------
    void add_note( Elf_Word           type,
                   const std::string& name,
                   const void*        desc,
                   Elf_Word           descSize )
    {
        const endianess_convertor& convertor = elf_file.get_convertor();

        int align            = sizeof( Elf_Word );
        Elf_Word nameLen     = (Elf_Word)name.size() + 1;
        Elf_Word nameLenConv = convertor( nameLen );
        std::string buffer( reinterpret_cast<char*>( &nameLenConv ), align );
        Elf_Word descSizeConv = convertor( descSize );
        buffer.append( reinterpret_cast<char*>( &descSizeConv ), align );
        type = convertor( type );
        buffer.append( reinterpret_cast<char*>( &type ), align );
        buffer.append( name );
        buffer.append( 1, '\x00' );
        const char pad[] = { '\0', '\0', '\0', '\0' };
        if ( nameLen % align != 0 ) {
            buffer.append( pad, align - nameLen % align );
        }
        if ( desc != 0 && descSize != 0 ) {
            buffer.append( reinterpret_cast<const char*>( desc ), descSize );
            if ( descSize % align != 0 ) {
                buffer.append( pad, align - descSize % align );
            }
        }

        note_start_positions.push_back( note_section->get_size() );
        note_section->append_data( buffer );
    }

  private:
//------------------------------------------------------------------------------
    void process_section()
    {
        const endianess_convertor& convertor = elf_file.get_convertor();
        const char* data                     = note_section->get_data();
        Elf_Xword   size                     = note_section->get_size();
        Elf_Xword   current                  = 0;

        note_start_positions.clear();

        // Is it empty?
        if ( 0 == data || 0 == size ) {
            return;
        }

        int align = sizeof( Elf_Word );
        while ( current + 3*align <= size ) {
            note_start_positions.push_back( current );
            Elf_Word namesz = convertor(
                            *(Elf_Word*)( data + current ) );
            Elf_Word descsz = convertor(
                            *(Elf_Word*)( data + current + sizeof( namesz ) ) );

            current += 3*sizeof( Elf_Word ) +
                       ( ( namesz + align - 1 ) / align ) * align +
                       ( ( descsz + align - 1 ) / align ) * align;
        }
    }

//------------------------------------------------------------------------------
  private:
    const elfio&           elf_file;
    section*               note_section;
    std::vector<Elf_Xword> note_start_positions;
};

} // namespace ELFIO

#endif // ELFIO_NOTE_HPP
