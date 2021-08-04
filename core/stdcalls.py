from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Iterable, List, Optional, Tuple
from itertools import count
from random import choice
from core import ast

import logging

LOGGER = logging.getLogger(__name__)


class StandardCall(ABC):
    """Base class for invocation of function from standard lib"""

    DEFAULT_ARGS = iter("arg_" + str(c) for c in count())

    @property
    @abstractmethod
    def lib(self) -> str:
        """Name of library containing function"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of function"""

    @property
    @abstractmethod
    def use_in_simple_call(self) -> bool:
        """True if function has side effect, meaning it can be called in simple
        statement and not be deleted by compiler optimization"""

    @property
    @abstractmethod
    def use_in_expression(self) -> bool:
        """True if function should be called in expressions"""

    @property
    @abstractmethod
    def return_type(self) -> ast.Type:
        """Return type of function"""

    @property
    @abstractmethod
    def arg_types(self) -> List[ast.Type]:
        """Argument types of function"""

    @property
    @abstractmethod
    def arg_names(self) -> Optional[Iterable[str]]:
        """Argument names of function"""

    @property
    def param_types(self) -> List[Tuple[str, ast.Type]]:
        """Parameter names with types of function"""
        arg_names = self.arg_names if self.arg_names else self.DEFAULT_ARGS
        return list(zip(arg_names, self.arg_types))

    def __repr__(self) -> str:
        args = ", ".join(
            f"{arg_type} {arg_name}" for arg_name, arg_type in self.param_types
        )
        return f"{self.return_type} {self.name}({args});"


class Strlen(StandardCall):
    """size_t strlen(char*)"""

    lib = "string.h"
    name = "strlen"
    return_type = ast.UnsignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


class Memset(StandardCall):
    """void* memset(void*, int, size_t)"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "memset"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [ast.Pointer(ast.UnsignedInt()), ast.SignedInt(), ast.UnsignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Memcmp(StandardCall):
    """int memcmp(const void *buf1, const void *buf2, size_t count);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "memcmp"
    return_type = ast.SignedInt()
    arg_types = [
        ast.Pointer(ast.UnsignedInt()),
        ast.Pointer(ast.UnsignedInt()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


class Memchr(StandardCall):
    """void *memchr(const void *buf, int c, size_t count);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "memchr"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [
        ast.Pointer(ast.UnsignedInt()),
        ast.SignedInt(),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = False  # maybe?
    use_in_simple_call = True  # maybe?


class Memcpy(StandardCall):
    """void *memcpy(void *dest, const void *src, size_t count);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "memcpy"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [
        ast.Pointer(ast.UnsignedInt()),
        ast.Pointer(ast.UnsignedInt()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Malloc(StandardCall):
    """void *malloc(size_t size);"""

    lib = "stdlib.h"
    name = "malloc"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [ast.UnsignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Putchar(StandardCall):
    """int putchar(int c);"""

    # void pointer not supported by generator
    lib = "stdio.h"
    name = "putchar"
    return_type = ast.SignedInt()
    arg_types = [ast.SignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Puts(StandardCall):
    """int puts(const char *string);"""

    # void pointer not supported by generator
    lib = "stdio.h"
    name = "puts"
    return_type = ast.SignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Realloc(StandardCall):
    """void *realloc(void *ptr, size_t size);"""

    # void pointer not supported by generator
    lib = "stdlib.h"
    name = "realloc"
    return_type = ast.Pointer(ast.UnsignedInt())
    arg_types = [ast.Pointer(ast.UnsignedInt()), ast.UnsignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Scanf(StandardCall):
    """int scanf(const char *format-string, arg-list);"""

    # void pointer not supported by generator
    lib = "stdio.h"
    name = "scanf"
    return_type = ast.SignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.UnsignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Strcasecmp(StandardCall):
    """int strcasecmp(const char *string1, const char *string2);"""

    # void pointer not supported by generator
    lib = "strings.h"
    name = "strcasecmp"
    return_type = ast.SignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Strcat(StandardCall):
    """char *strcat(char *string1, const char *string2);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strcat"
    return_type = ast.Pointer(ast.UnsignedChar())
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Strchr(StandardCall):
    """char *strchr(const char *string, int c);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strchr"
    return_type = ast.Pointer(ast.UnsignedChar())
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.SignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = True


class Strcmp(StandardCall):
    """int strcmp(const char *string1, const char *string2);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strcmp"
    return_type = ast.SignedInt()
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


class Strcpy(StandardCall):
    """char *strcpy(char *string1, const char *string2);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strcpy"
    return_type = ast.Pointer(ast.UnsignedChar())
    arg_types = [ast.Pointer(ast.UnsignedChar()), ast.Pointer(ast.UnsignedChar())]
    arg_names = None
    use_in_expression = False
    use_in_simple_call = True


class Strncasecmp(StandardCall):
    """int strncasecmp(const char *string1, const char *string2, size_t count);"""

    # void pointer not supported by generator
    lib = "strings.h"
    name = "strncasecmp"
    return_type = ast.SignedInt()
    arg_types = [
        ast.Pointer(ast.UnsignedChar()),
        ast.Pointer(ast.UnsignedChar()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


class Strncmp(StandardCall):
    """int strncmp(const char *string1, const char *string2, size_t count);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strncmp"
    return_type = ast.SignedInt()
    arg_types = [
        ast.Pointer(ast.UnsignedChar()),
        ast.Pointer(ast.UnsignedChar()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


class Strncpy(StandardCall):
    """char *strncpy(char *string1, const char *string2, size_t count);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "strncpy"
    return_type = ast.Pointer(ast.UnsignedChar())
    arg_types = [
        ast.Pointer(ast.UnsignedChar()),
        ast.Pointer(ast.UnsignedChar()),
        ast.UnsignedInt(),
    ]
    arg_names = None
    use_in_expression = False
    use_in_simple_call = True


class Toascii(StandardCall):
    """int toascii(int c);"""

    # void pointer not supported by generator
    lib = "string.h"
    name = "toascii"
    return_type = ast.SignedInt()
    arg_types = [ast.SignedInt()]
    arg_names = None
    use_in_expression = True
    use_in_simple_call = False


methods = StandardCall.__subclasses__()
methods_by_return_type = defaultdict(list)
methods_for_use_in_simple_call = [
    method for method in methods if method.use_in_simple_call
]

for method in methods:
    methods_by_return_type[method.return_type].append(method)


def get_method_for_call_inside_expression(return_type):
    candidates = methods_by_return_type[return_type]
    if not candidates:
        LOGGER.debug("no method for return type '%s'", return_type)
        return None
    std_method = choice(candidates)
    return std_method()


def get_method_for_simple_call():
    if not methods_for_use_in_simple_call:
        LOGGER.warning("no std methods with side effects")
        return None
    std_method = choice(methods_for_use_in_simple_call)
    return std_method()


def get_std_method():
    if not methods:
        LOGGER.warning("no std methods")
        return None
    std_method = choice(methods)
    return std_method()
