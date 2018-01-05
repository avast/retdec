"""Units tests for the type_extractor.remove_json_types module."""

import unittest

from type_extractor.remove_json_types import remove_qualifier_json_types
from type_extractor.remove_json_types import remove_unused_json_types


class RemoveUnusedJsonTypesTests(unittest.TestCase):
    def test_all_unused_type_are_removed(self):
        functions = {
            "f": {
                "decl": "int f();",
                "header": "tx.h",
                "name": "f",
                "params": [],
                "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "const",
                "type": "qualifier",
                "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            },
            "685e80366130387cb75c055248326976d16fdf8d": {
                "name": "float",
                "type": "floating_point_type"
            },
            "d8c550a1f49f312b1bf5709f7f7c7e25e1dfe210": {
                "dimensions": [
                    10
                ],
                "element_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2",
                "type": "array"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "members": [
                    {
                        "name": "a",
                        "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                ],
                "name": "struct s",
                "type": "struct",
            }
        }
        expected_types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), expected_types)

    def test_all_func_parameter_types_are_kept(self):
        functions = {
            "f": {
                "decl": "int f(char a, float f);",
                "header": "tx.h",
                "name": "f",
                "params": [
                    {
                        "name": "a",
                        "type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
                    },
                    {
                        "name": "f",
                        "type": "685e80366130387cb75c055248326976d16fdf8d"
                    }
                ],
                "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "685e80366130387cb75c055248326976d16fdf8d": {
                "name": "float",
                "type": "floating_point_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "char",
                "type": "integral_type"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_element_type_of_array_is_kept(self):
        functions = {
            "f": {
                "decl": "int f(char a[10]);",
                "header": "tx.h",
                "name": "f",
                "params": [
                    {
                        "name": "a",
                        "type": "d8c550a1f49f312b1bf5709f7f7c7e25e1dfe210"
                    },
                ],
                "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "char",
                "type": "integral_type"
            },
            "d8c550a1f49f312b1bf5709f7f7c7e25e1dfe210": {
                "dimensions": [
                    10
                ],
                "element_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2",
                "type": "array"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_typedefed_type_is_kept(self):
        functions = {
            "f": {
                "decl": "INT f();",
                "header": "tx.h",
                "name": "f",
                "params": [],
                "ret_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "INT",
                "type": "typedef",
                "typedefed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_function_type_params_are_kept(self):
        functions = {
            "f": {
                "decl": "int f(int f(char));",
                "header": "tx.h",
                "name": "f",
                "params": [
                    {
                        "name": "f",
                        "type": "361d6282a400aca2fb0ce4b769c85ee086a9ee4c"
                    }
                ],
                "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }
        types = {
            "361d6282a400aca2fb0ce4b769c85ee086a9ee4c": {
                "params": [
                    {
                        "name": "",
                        "type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
                    }
                ],
                "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                "type": "function"
            },
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "char",
                "type": "integral_type"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_pointed_type_is_kept(self):
        functions = {
            "f": {
                "decl": "int * f();",
                "header": "tx.h",
                "name": "f",
                "params": [],
                "ret_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "type": "pointer",
                "pointed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_const_modified_type_is_kept(self):
        functions = {
            "f": {
                "decl": "const int f();",
                "header": "tx.h",
                "name": "f",
                "params": [],
                "ret_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "name": "const",
                "type": "qualifier",
                "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)

    def test_struct_members_are_kept(self):
        functions = {
            "f": {
                "decl": "struct s f();",
                "header": "tx.h",
                "name": "f",
                "params": [],
                "ret_type": "71fafc4e2fc1e47e234762a96b80512b6b5534c2"
            }
        }
        types = {
            "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                "name": "int",
                "type": "integral_type"
            },
            "71fafc4e2fc1e47e234762a96b80512b6b5534c2": {
                "members": [
                    {
                        "name": "a",
                        "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                ],
                "name": "struct s",
                "type": "structure",
            }
        }

        self.assertEqual(remove_unused_json_types(functions, types), types)


class RemoveQualifierTypesTests(unittest.TestCase):
    def test_remove_qualifier_types_from_function(self):
        json = {
            "functions": {
                "f": {
                    "decl": "const int f(const int i);",
                    "header": "tx.h",
                    "name": "f",
                    "params": [
                        {
                            "name": "i",
                            "type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666"
                        }
                    ],
                    "ret_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666"
                }
            },
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "const int f(const int i);",
                        "header": "tx.h",
                        "name": "f",
                        "params": [
                            {
                                "name": "i",
                                "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                            }
                        ],
                        "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                },
                "types": {
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    }
                }
            }
        )

    def test_remove_qualifier_types_from_array(self):
        json = {
            "functions": {
                "f": {
                    "decl": "int f(const int i[]);",
                    "header": "tx.h",
                    "name": "f",
                    "params": [
                        {
                            "name": "i",
                            "type": "8a5702ae4925ef124198af3352b8673ae1b5c623"
                        }
                    ],
                    "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                }
            },
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "8a5702ae4925ef124198af3352b8673ae1b5c623": {
                    "dimensions": [
                        ""
                    ],
                    "element_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666",
                    "type": "array"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "int f(const int i[]);",
                        "header": "tx.h",
                        "name": "f",
                        "params": [
                            {
                                "name": "i",
                                "type": "8a5702ae4925ef124198af3352b8673ae1b5c623"
                            }
                        ],
                        "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                },
                "types": {
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "8a5702ae4925ef124198af3352b8673ae1b5c623": {
                        "dimensions": [
                            ""
                        ],
                        "element_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                        "type": "array"
                    }
                }
            }
        )

    def test_remove_qualifier_types_from_function_type(self):
        json = {
            "functions": {},
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "3962e448d156cb85e3bf7e1216efa8139119f4b4": {
                    "params": [],
                    "ret_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666",
                    "type": "function"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "5e04ab331d26527cb0f2c9d998df6250844e5616": {
                    "name": "f",
                    "type": "typedef",
                    "typedefed_type": "d67c28e05e53598da559c8acdf8e577fc3c70726"
                },
                "d67c28e05e53598da559c8acdf8e577fc3c70726": {
                    "pointed_type": "3962e448d156cb85e3bf7e1216efa8139119f4b4",
                    "type": "pointer"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "3962e448d156cb85e3bf7e1216efa8139119f4b4": {
                        "params": [],
                        "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                        "type": "function"
                    },
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "5e04ab331d26527cb0f2c9d998df6250844e5616": {
                        "name": "f",
                        "type": "typedef",
                        "typedefed_type": "d67c28e05e53598da559c8acdf8e577fc3c70726"
                    },
                    "d67c28e05e53598da559c8acdf8e577fc3c70726": {
                        "pointed_type": "3962e448d156cb85e3bf7e1216efa8139119f4b4",
                        "type": "pointer"
                    },
                }
            }
        )

    def test_remove_qualifier_types_struct_members(self):
        json = {
            "functions": {},
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "3d6186cdc4278ee703981d00c71201ca3344c592": {
                    "members": [
                        {
                            "name": "i",
                            "type": "8219838a8cbd6b107cf558a616256e894f773b5a"
                        },
                        {
                            "name": "j",
                            "type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666"
                        }
                    ],
                    "name": "struct s",
                    "type": "structure"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "8219838a8cbd6b107cf558a616256e894f773b5a": {
                    "name": "CINT",
                    "type": "typedef",
                    "typedefed_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "3d6186cdc4278ee703981d00c71201ca3344c592": {
                        "members": [
                            {
                                "name": "i",
                                "type": "8219838a8cbd6b107cf558a616256e894f773b5a"
                            },
                            {
                                "name": "j",
                                "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                            }
                        ],
                        "name": "struct s",
                        "type": "structure"
                    },
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "8219838a8cbd6b107cf558a616256e894f773b5a": {
                        "name": "CINT",
                        "type": "typedef",
                        "typedefed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                }
            }
        )

    def test_remove_qualifier_types_from_pointer(self):
        json = {
            "functions": {},
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "8c6e2fa96c2304299bc328f9652d0233776b100a": {
                    "name": "PCINT",
                    "type": "typedef",
                    "typedefed_type": "f5e774f604bf7ffbdaf2745cb9e37208465050e2"
                },
                "f5e774f604bf7ffbdaf2745cb9e37208465050e2": {
                    "pointed_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666",
                    "type": "pointer"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "8c6e2fa96c2304299bc328f9652d0233776b100a": {
                        "name": "PCINT",
                        "type": "typedef",
                        "typedefed_type": "f5e774f604bf7ffbdaf2745cb9e37208465050e2"
                    },
                    "f5e774f604bf7ffbdaf2745cb9e37208465050e2": {
                        "pointed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                        "type": "pointer"
                    }
                }
            }
        )

    def test_remove_two_level_qualifier_types(self):
        """'const restrict int' should be substituted to int"""
        json = {
            "functions": {},
            "types": {
                "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666": {
                    "modified_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "name": "const",
                    "type": "qualifier"
                },
                "2eb539806be1e0d28a149acdbc952890d5b52320": {
                    "modified_type": "0ff04d04cf6c73308eda9ef3c2a850b0b80e5666",
                    "name": "restrict",
                    "type": "qualifier"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "a8bff8de7eac4c7fa1f24f64d1b73b8aae268620": {
                    "name": "CRINT",
                    "type": "typedef",
                    "typedefed_type": "2eb539806be1e0d28a149acdbc952890d5b52320"
                }
            }
        }

        remove_qualifier_json_types(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "a8bff8de7eac4c7fa1f24f64d1b73b8aae268620": {
                        "name": "CRINT",
                        "type": "typedef",
                        "typedefed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                    }
                }
            }
        )
