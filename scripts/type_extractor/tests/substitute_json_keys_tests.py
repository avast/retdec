"""Unit tests for the substitute_json_keys module."""

import unittest

from type_extractor.substitute_json_keys import substitute_json_keys_with_natural_numbers


class SimplifyJsonKeysTests(unittest.TestCase):
    def test_substitute_func_params_and_ret_type_keys(self):
        json = {
            "functions": {
                "f": {
                    "decl": "void f(float g, struct s);",
                    "header": "tx.h",
                    "name": "f",
                    "params": [
                        {
                            "name": "g",
                            "type": "685e80366130387cb75c055248326976d16fdf8d"
                        },
                        {
                            "name": "",
                            "type": "3d6186cdc4278ee703981d00c71201ca3344c592"
                        }
                    ],
                    "ret_type": "e9cede9b80ea3abd89c755f1117337d429162c86"
                }
            },
            "types": {
                "3d6186cdc4278ee703981d00c71201ca3344c592": {
                    "members": [],
                    "name": "struct s",
                    "type": "structure"
                },
                "685e80366130387cb75c055248326976d16fdf8d": {
                    "name": "float",
                    "type": "floating_point_type"
                },
                "e9cede9b80ea3abd89c755f1117337d429162c86": {
                    "type": "void"
                }
            }
        }
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "void f(float g, struct s);",
                        "header": "tx.h",
                        "name": "f",
                        "params": [
                            {
                                "name": "g",
                                "type": "2"
                            },
                            {
                                "name": "",
                                "type": "1"
                            }
                        ],
                        "ret_type": "3"
                    }
                },
                "types": {
                    "1": {
                        "members": [],
                        "name": "struct s",
                        "type": "structure"
                    },
                    "2": {
                        "name": "float",
                        "type": "floating_point_type"
                    },
                    "3": {
                        "type": "void"
                    }
                }
            }
        )

    def test_substitute_struct_members_keys(self):
        json = {
            "functions": {},
            "types": {
                "3d6186cdc4278ee703981d00c71201ca3344c592": {
                    "members": [
                        {
                            "name": "i",
                            "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                        },
                        {
                            "name": "f",
                            "type": "685e80366130387cb75c055248326976d16fdf8d"
                        }
                    ],
                    "name": "struct s",
                    "type": "structure"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "685e80366130387cb75c055248326976d16fdf8d": {
                    "name": "float",
                    "type": "floating_point_type"
                }
            }
        }
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "1": {
                        "members": [
                            {
                                "name": "i",
                                "type": "2"
                            },
                            {
                                "name": "f",
                                "type": "3"
                            }
                        ],
                        "name": "struct s",
                        "type": "structure"
                    },
                    "2": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "3": {
                        "name": "float",
                        "type": "floating_point_type"
                    }
                }
            }
        )

    def test_substitute_array_element_type_key(self):
        json = {
            "functions": {
                "f": {
                    "decl": "void f(int a[]);",
                    "header": "tx.h",
                    "name": "f",
                    "params": [
                        {
                            "name": "a",
                            "type": "5d9eaa5b0567f6d962763d20115ece2661a87230"
                        }
                    ],
                    "ret_type": "e9cede9b80ea3abd89c755f1117337d429162c86"
                }
            },
            "types": {
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "5d9eaa5b0567f6d962763d20115ece2661a87230": {
                    "dimensions": [
                        ""
                    ],
                    "element_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "type": "array"
                },
                "e9cede9b80ea3abd89c755f1117337d429162c86": {
                    "type": "void"
                }
            }
        }
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "void f(int a[]);",
                        "header": "tx.h",
                        "name": "f",
                        "params": [
                            {
                                "name": "a",
                                "type": "2"
                            }
                        ],
                        "ret_type": "3"
                    }
                },
                "types": {
                    "1": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "2": {
                        "dimensions": [
                            ""
                        ],
                        "element_type": "1",
                        "type": "array"
                    },
                    "3": {
                        "type": "void"
                    }
                }
            }
        )

    def test_substitute_pointer_to_function_type_keys(self):
        json = {
            "functions": {
                "f": {
                    "decl": "int f(int(* f)(int));",
                    "header": "tx.h",
                    "name": "f",
                    "params": [
                        {
                            "name": "f",
                            "type": "3c3d53921dd5483b5627bca319d79a6defc2bec5"
                        }
                    ],
                    "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                }
            },
            "types": {
                "3c3d53921dd5483b5627bca319d79a6defc2bec5": {
                    "pointed_type": "ff960066816ea5557fd43a4d7bb814e635e6f13e",
                    "type": "pointer"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                },
                "ff960066816ea5557fd43a4d7bb814e635e6f13e": {
                    "params": [
                        {
                            "name": "",
                            "type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                        }
                    ],
                    "ret_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315",
                    "type": "function"
                }
            }
        }
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "int f(int(* f)(int));",
                        "header": "tx.h",
                        "name": "f",
                        "params": [
                            {
                                "name": "f",
                                "type": "1"
                            }
                        ],
                        "ret_type": "2"
                    }
                },
                "types": {
                    "1": {
                        "pointed_type": "3",
                        "type": "pointer"
                    },
                    "2": {
                        "name": "int",
                        "type": "integral_type"
                    },
                    "3": {
                        "params": [
                            {
                                "name": "",
                                "type": "2"
                            }
                        ],
                        "ret_type": "2",
                        "type": "function"
                    }
                }
            }
        )

    def test_substitute_const_type_keys(self):
        json = {
            "functions": {
                "f": {
                    "decl": "const int f();",
                    "header": "tx.h",
                    "name": "f",
                    "params": [],
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
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {
                    "f": {
                        "decl": "const int f();",
                        "header": "tx.h",
                        "name": "f",
                        "params": [],
                        "ret_type": "1"
                    }
                },
                "types": {
                    "1": {
                        "modified_type": "2",
                        "name": "const",
                        "type": "qualifier"
                    },
                    "2": {
                        "name": "int",
                        "type": "integral_type"
                    }
                }
            }
        )

    def test_substitute_typedefed_type_keys(self):
        json = {
            "functions": {},
            "types": {
                "0c2f1eb1c3c04a87d71f37c517f701cc4da9325e": {
                    "name": "INT",
                    "type": "typedef",
                    "typedefed_type": "46f8ab7c0cff9df7cd124852e26022a6bf89e315"
                },
                "46f8ab7c0cff9df7cd124852e26022a6bf89e315": {
                    "name": "int",
                    "type": "integral_type"
                }
            }
        }
        substitute_json_keys_with_natural_numbers(json)

        self.assertEqual(
            json,
            {
                "functions": {},
                "types": {
                    "1": {
                        "name": "INT",
                        "type": "typedef",
                        "typedefed_type": "2"
                    },
                    "2": {
                        "name": "int",
                        "type": "integral_type"
                    }
                }
            }
        )
