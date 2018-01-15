/**
 * @file include/retdec/config/doxygen.h
 * @brief Doxygen documentation of the config namespace.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

// As there is no better place to comment this namespace, we do this in the
// present file.

/**

@namespace config A library providing access to configuration of
decompilations.

@section intro_sec Introduction

@c config library defines many objects used throughout all decompiler's parts
and groups them together into an instance of Config class.
Its main purpose is to hold all relevant information gathered about the
input binary file and make them persistent by serialization into human-readable
text file in JSON data format.

Possible uses of this library include:
<ul>
  <li> Propagate information between all decompiler's parts. If, for example,
  front-end detects functions and their properties (e.g. addresses),
  it fills these information into Config instance, serialize it and therefore
  makes it available to all upcoming decompilation parts.
  <li> Propagate information to the decompilation itself. It is possible to provide
  decompilation with the input JSON  config file, which is then deserialized into
  Config instance and used by the decompiler. This allows other tools such as
  IDA Pro plugin to guide and enrich decompilation results.
  <li> Generated Config JSON file may also serve as a persistent database
  for completed decompilations. It can be changed, archived or shared, and
  if needed fed back to the decompiler to repeat the decompilation.
</ul>

@section cpp_naming Naming Conventions

The library uses the following naming conventions.
<ul>
  <li> Source files (i.e. @c *.{h,cpp}) are named by using @c snake_case,
       e.g. architecture.h or calling_convention.cpp.
  <li> Functions and variables are named by using @c camelCase,
       e.g. Parameters::outputFile or Architecture::setIsEndianLittle().
  <li> Classes are named by using @c CamelCase, e.g. Architecture.
  <li> No name contains two or more successive uppercase letters,
       even if it corresponds to an abbreviation, e.g ToolInfoContainer::isPspGcc()
       is used instead of @c ToolInfoContainer::isPSPGCC().
  <li> All setters are prefixed wtih @c set, boolean getters with @c is
       and all other getters with @c get. If a setter sets a boolean value
       or explicit @c enum variant, it is prefixed with @c setIs.
</ul>

@section modules_sec Current modules

This is a short description of all current @c config library modules.
See classes documentation for more details.
<ul>
  <li> Config - the main class which encapsulates all of the other data.
  <li> Architecture - information about input binary's target architecture
       (e.g. x86, little-arm, big-mips).
  <li> CallingConvention - represents all known function calling conventions.
  <li> FileFormat - information about input binary's file format (e.g. PE, ELF, COFF).
  <li> FileType - describes input's binary file type (e.g. shared library, archive,
       executable, object file).
  <li> Parameters - holds all decompilation options.
  <li> Function - contains relevant information about function.
       Functions are gathered in FunctionContainer.
  <li> Language - describes language used to create binary file.
       Possible languages are kept in LanguageContainer.
  <li> Object - represents objects like global variables, registers, etc.
       Objects are gathered into ObjectContainer or other derived containers
       (e.g GlobalVarContainer).
  <li> Segment - represents input binary's segment. All segments are
       stored in SegmentContainer.
  <li> Storage - represents storage of objects.
  <li> ToolInfo - tools that may have been used to create/manipulate input
       binary (e.g. compiler, packer). Tools are kept in ToolInfoContainer.
  <li> Type - represents data type for objects or functions.
       All used types are in TypeContainer.
</ul>

@section includes Includes

To use entire @c config library, include only the main @c config.h file
using the full @c decdev path:
@code{.cpp}
#include "retdec/config/config.h"
@endcode
However, if you want to use only specific parts of the library, you can
include just the used header files:
@code{.cpp}
#include "retdec/config/architecture.h"
@endcode

@section Namespaces

All the classes, functions, and constants the library provides are
in the config namespace.

@section error_handling Error Handling

All excaptions thrown by library are derived from @c Exception class,
which can be used to catch them all.
The library throws @c ParseException exception if JSON parsing failed.
@c ConfigException contains information necessary to track the problem.
(see its documentation for more details).
The library throws @c FileNotFoundException exception if input file can
not be parsed.

The library evaluates asserts on some critical places. This can help during
the development, but can be disabled in a release version. Code should be written
in such a way, that it will not fail even if assert that would go off is disabled.

You also need to check return values of methods which may not succeed.
For example, method:
@code{.cpp}
config::Function* FunctionContainer::getFunctionByName(const std::string& name);
@endcode
returns @c nullptr rather than throwing an exception, if function of
the specified name is not found. All other methods behave like this as well.

@section json_naming JSON naming convention

These are the guidelines for JSON names.
It would be best if once used names never changed.
Therefore, use this conventions and think twice before adding a new name.
These guidelines are based on
<a href="http://google-styleguide.googlecode.com/svn/trunk/jsoncstyleguide.xml#Property_Name_Format">Google JSON Style Guide</a>.

For the purposes of this style guide, we define the following terms:
<ul>
  <li>property = a name/value pair inside a JSON object.
  <li>property name = the name (or key) portion of the property.
  <li>property value = the value portion of the property.
</ul>
Example:
@code{.json}
{ "propertyName" : "propertyValue" } ///< property
@endcode
Guidelines:
<ul>
  <li>No comments in JSON objects.
  <li>Use double quotes.
  <li>Choose meaningful property names.
  <li>Property names must be @c camelCase, ASCII 0-127 strings.
  <li>Array types should have plural property names. All other property
      names should be singular.
  <li>Avoid naming conflicts by choosing a new property name or versioning
      the API.
  <li>Enum values should be represented as strings.
  <li>Data and time must be formatted the same way as in {front,back}-end.
</ul>

@section complete_example A Complete Example

In the following example, function @c createJson() creates an empty config instance,
fills it up with data, serialize it into JSON file and returns
a string with the name of this file. Then, function @c parseJson() takes the file name,
deserializes its content into Config internal representation and accesses its data.

@code{.cpp}
#include <iostream>
#include "retdec/config/config.h"

std::string createJson()
{
    // Create an empty config file.
    // All config entries are initialized to their default values.
    config::Config config;

    // Fill some basic information in to the file.
    // Nothing complicated yet, a lot of stuff can be set only by using
    // simple set*() methods.
    config.architecture.setIsMips();
    config.architecture.setIsEndianLittle();
    config.fileType.setIsExecutable();
    config.fileFormat.setIsElf32();

    // Some set*() methods need a value to set.
    config.setImageBase(0x1000);
    config.parameters.setOutputFile("/decompilation/output/file.c");

    // Other members are containers in which we can insert values.
    config.parameters.abiPaths.insert("/path/to/abi");
    config.parameters.selectedRanges.insert( config::AddressRangeJson(0x1000, 0x2000) );

    // Some containers need a little bit more work to properly fill up.
    // Here we create a function name 'my_function', set its calling convention
    // and add parameter and local variable into it.
    // Do not forget to add the function into config function container.
    config::Function fnc("my_function");
    fnc.callingConvention.setIsStdcall();

    config::Object param("param", config::Storage::undefined());
    param.type.setLlvmIr("i32");

    config::Object local("local", config::Storage::onStack(-20));
    param.type.setLlvmIr("i8*");

    fnc.parameters.insert(param);
    fnc.locals.insert(local);

    config.functions.insert(fnc);

    // Finally, we can serialize the config instance into a JSON string.
    std::string json = config.generateJsonString();

    // We return this JSON string, so that others can use it.
    return json;
}

void parseJson(const std::string& json)
{
	std::stringstream out;

    // We again create an empty config file.
    // We can initialize it manually like in the createJson() function,
    // or by JSON string or JSON file like in this function.
    config::Config config;

    // String used in initialization must contain a valid JSON string.
    // Empty JSON string is valid.
    // It does not have to contain any obligatory values.
    // Any missing values are set to default.
    config.readJsonString("{}");

    // Therefore, it might contain very little (or none) information.
    config.readJsonString("{ \"inputPath\" : \"/input/path\" }");

    // We can parse any JSON string.
    // Any successful parsing by readJsonString() or readJsonFile() resets
    // all existing values to their defaults before setting them again.
    // Therefore, no previously set data survive these methods.
    // For example, this call will reset "inputPath" property set in the
    // previous line.
    config.readJsonString(json);

    // Now we can access all information from the file.
    out << config.architecture.getName() << "\n";
    out << config.architecture.isMips() << "\n";
    out << config.parameters.getOutputFile() << "\n";

    config::Function* fnc = config.functions.getFunctionByName("my_function");
    if (fnc)
    {
        out << fnc->getName() << "\n";
    }
}

int main()
{
    std::string json = createJson();
    parseJson(json);
    return 0;
}

@endcode

The example works with JSON string generated by @c generateJsonString() and
processed by @c readJsonString(). However, it is possible to serialize the
config instance directly into file using @c generateJsonFile() method, and
parse it using @c readJsonFile() method.

*/
