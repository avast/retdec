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

#ifndef ELFIO_STRINGS_HPP
#define ELFIO_STRINGS_HPP

#include <cstdlib>
#include <cstring>
#include <string>

namespace ELFIO {

//------------------------------------------------------------------------------
class string_section_accessor
{
  public:
//------------------------------------------------------------------------------
    string_section_accessor( section* section_ ) :
                             string_section( section_ )
    {
    }

//------------------------------------------------------------------------------
// DECOMPILER BEGIN
    std::string
    get_string( Elf_Word index ) const
    {
        std::string result;

        if ( string_section ) {
            std::size_t data_size = string_section->get_data_size();
            if ( index < data_size ) {
                const char* data = string_section->get_data();
                if ( 0 == data ) {
                    return result;
                }

                for ( const char* p = data + index; p < data + data_size; ++p ) {
                    if ( *p == '\0' ) {
                        break;
                    }

                    result.push_back( *p );
                }
            }
        }

        return result;
    }
// DECOMPILER END

//------------------------------------------------------------------------------
    Elf_Word
    add_string( const char* str )
    {
        Elf_Word current_position = 0;

        if (string_section) {
            // Strings are addeded to the end of the current section data
            current_position = (Elf_Word)string_section->get_size();

            if ( current_position == 0 ) {
                char empty_string = '\0';
                string_section->append_data( &empty_string, 1 );
                current_position++;
            }
            string_section->append_data( str, (Elf_Word)std::strlen( str ) + 1 );
        }

        return current_position;
    }

//------------------------------------------------------------------------------
    Elf_Word
    add_string( const std::string& str )
    {
        return add_string( str.c_str() );
    }

//------------------------------------------------------------------------------
  private:
    section* string_section;
};

} // namespace ELFIO

#endif // ELFIO_STRINGS_HPP
