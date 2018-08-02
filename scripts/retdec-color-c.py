#!/usr/bin/env python3
"""
	retdec-color-c
	~~~~~~~

	Color given C file using the IDA pro tags.
"""

#=====================================================================================

import sys
import re

from pygments import highlight
from pygments.formatter import Formatter
from pygments.formatters import RawTokenFormatter
from pygments.lexers import CppLexer
from pygments.lexers import CLexer
from pygments.token import Token

import json
from pprint import pprint

#=====================================================================================

externalFunctionList = []
userFunctionList = []
globalVariableList = []

#=====================================================================================

# Same constants as in <IDASDK>/include/lines.hpp.
#
SCOLOR_DEFAULT   = '\x01'  # Default                                 # default blue
SCOLOR_REGCMT    = '\x02'  # Regular comment                         # default blue
SCOLOR_RPTCMT    = '\x03'  # Repeatable comment (defined not here)   # grey
SCOLOR_AUTOCMT   = '\x04'  # Automatic comment                       # grey
SCOLOR_INSN      = '\x05'  # Instruction                             # dark blue, as SCOLOR_KEYWORD
SCOLOR_DATNAME   = '\x06'  # Dummy Data Name                         # dark blue, as SCOLOR_KEYWORD
SCOLOR_DNAME     = '\x07'  # Regular Data Name                       # default blue
SCOLOR_DEMNAME   = '\x08'  # Demangled Name                          # default blue
SCOLOR_SYMBOL    = '\x09'  # Punctuation                             # dark blue, as SCOLOR_KEYWORD
SCOLOR_CHAR      = '\x0A'  # Char constant in instruction            # default blue + \n
SCOLOR_STRING    = '\x0B'  # String constant in instruction          # light green
SCOLOR_NUMBER    = '\x0C'  # Numeric constant in instruction         # dark green
SCOLOR_VOIDOP    = '\x0D'  # Void operand                            # orange
SCOLOR_CREF      = '\x0E'  # Code reference                          # dark green, as SCOLOR_NUMBER
SCOLOR_DREF      = '\x0F'  # Data reference                          # light purple
SCOLOR_CREFTAIL  = '\x10'  # Code reference to tail byte             # red
SCOLOR_DREFTAIL  = '\x11'  # Data reference to tail byte             # khaki
SCOLOR_ERROR     = '\x12'  # Error or problem                        # black on red background
SCOLOR_PREFIX    = '\x13'  # Line prefix                             # white on white :D
SCOLOR_BINPREF   = '\x14'  # Binary line prefix bytes                # default blue
SCOLOR_EXTRA     = '\x15'  # Extra line                              # default blue
SCOLOR_ALTOP     = '\x16'  # Alternative operand                     # default blue
SCOLOR_HIDNAME   = '\x17'  # Hidden name                             # grey
SCOLOR_LIBNAME   = '\x18'  # Library function name                   # light blue
SCOLOR_LOCNAME   = '\x19'  # Local variable name                     # dark green, as SCOLOR_NUMBER
SCOLOR_CODNAME   = '\x1A'  # Dummy code name                         # dark blue, as SCOLOR_KEYWORD
SCOLOR_ASMDIR    = '\x1B'  # Assembler directive                     # default blue
SCOLOR_MACRO     = '\x1C'  # Macro                                   # purple
SCOLOR_DSTR      = '\x1D'  # String constant in data directive       # dark green, as SCOLOR_NUMBER
SCOLOR_DCHAR     = '\x1E'  # Char constant in data directive         # dark green, as SCOLOR_NUMBER
SCOLOR_DNUM      = '\x1F'  # Numeric constant in data directive      # dark green, as SCOLOR_NUMBER
SCOLOR_KEYWORD   = '\x20'  # Keywords                                # dark blue / black
SCOLOR_REG       = '\x21'  # Register name                           # dark blue, as SCOLOR_KEYWORD
SCOLOR_IMPNAME   = '\x22'  # Imported name                           # pink
SCOLOR_SEGNAME   = '\x23'  # Segment name                            # khaki
SCOLOR_UNKNAME   = '\x24'  # Dummy unknown name                      # dark blue, as SCOLOR_KEYWORD
SCOLOR_CNAME     = '\x25'  # Regular code name                       # default blue
SCOLOR_UNAME     = '\x26'  # Regular unknown name                    # dark blue, as SCOLOR_KEYWORD
SCOLOR_COLLAPSED = '\x27'  # Collapsed line                          # default blue
SCOLOR_ADDR      = '\x28'  # Hidden address mark                     # default blue, removes characters from start

SCOLOR_ON        = '\x01'  # Escape character (ON)
SCOLOR_OFF       = '\x02'  # Escape character (OFF)

def idaformat(color, text):
	"""
	Format `text` with a color: ``'\\1 COLOR text \\2 COLOR'``.
	"""
	if color is None:
		return text

	return SCOLOR_ON + color + text + SCOLOR_OFF + color


#=====================================================================================

#: Map token types to a IDA Pro color value.
#
# NOTE: matula: Originally there was support for bold, blink, underlined, etc. tags.
#       but since this is not supported in IDA (as far as I known) it was removed.
#       If we needed it, and we found a way to display it in IDA, implement it again.
#

TERMINAL_COLORS = {
	Token.Token:              '',              # Empty => default blue.

	Token.Whitespace:         '',
	Token.Comment:            SCOLOR_AUTOCMT,
	Token.Comment.Preproc:    SCOLOR_AUTOCMT,
	Token.Keyword:            SCOLOR_MACRO,
    Token.Keyword.Type:       SCOLOR_AUTOCMT,

	Token.String:             SCOLOR_NUMBER,   # SCOLOR_CREFTAIL,
	Token.Number:             SCOLOR_NUMBER,

	Token.Punctuation:        SCOLOR_KEYWORD,
	Token.Operator:           SCOLOR_KEYWORD,  # SCOLOR_MACRO
	Token.Name:               SCOLOR_DREF,     # variables and functions uses
	Token.Name.Function:      SCOLOR_DEFAULT,  # function definition

	Token.Generic.Deleted:    '',
	Token.Generic.Inserted:   '',
	Token.Generic.Heading:    '',
	Token.Generic.Subheading: '',
	Token.Generic.Error:      SCOLOR_ERROR,

	Token.Error:              SCOLOR_ERROR,
}

class IDAFormatter(Formatter):
    """
    Format tokens with IDA Pro color sequences.
    """
    def format(self, tokensource, outfile):
        """ Format all provided tokens and dump them into output file. """
        for ttype, value in tokensource:
            color = self.getColor(ttype, value)
            while color is None:
                ttype = ttype[:-1]
                color = self.getColor(ttype, value)
            if color:
                spl = value.split('\n')
                for line in spl[:-1]:
                    if line:
                        outfile.write(idaformat(color, line))
                    outfile.write('\n')
                val = spl[-1]
                if val:
                    outfile.write(idaformat(color, val))
            else:
                outfile.write(value)

    def getColor(self, ttype, value):
        """ Return color for provided token type and value. """
        if ttype == Token.Name:
            if value in externalFunctionList:
                return SCOLOR_IMPNAME
            if value in userFunctionList:
                return SCOLOR_DEFAULT
            if value in globalVariableList:
                return SCOLOR_DEFAULT

        return TERMINAL_COLORS.get(ttype)

#=====================================================================================

inSitu    = True          # do coloring in situ
extension = '.colored.c'  # extension to use if inSitu is false

if len(sys.argv) != 3:
	print('Error: script expects two arguments, a file to color and its decompilation config database (json).')
	sys.exit(1)

inConfigName = sys.argv[2]
with open(inConfigName, 'r') as inConfigFile:
    data = json.load(inConfigFile)
for f in data.get('functions', []):
    if (f.get('fncType') == 'userDefined'):
        userFunctionList.append(f.get('name'))
    else:
        externalFunctionList.append(f.get('name'))
for g in data.get('globals', []):
    globalVariableList.append(g.get('name'))

inFileName = sys.argv[1]
with open(inFileName, 'r') as f:
	code = f.read()
code = highlight(code, CppLexer(), IDAFormatter())

# This comes in handy when we want to find out token name for same particular lexeme.
# It just dumps all the lexemes and their token names that can be used in TERMINAL_COLORS mapping.
#
#code = highlight(code, CppLexer(), RawTokenFormatter())

# Enable only during debugging.
#
#print(code)

outFileName = inFileName if inSitu else inFileName + extension
with open(outFileName, 'w') as f:
	f.write(code)
