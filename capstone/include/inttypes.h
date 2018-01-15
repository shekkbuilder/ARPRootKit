#ifndef INTTYPES_H
#define INTTYPES_H

#if defined __x86_64__ && !defined __ILP32__
# define __WORDSIZE 64
#else
# define __WORDSIZE 32
#endif

# if __WORDSIZE == 64
#  define __PRI64_PREFIX    "l"
#  define __PRIPTR_PREFIX   "l"
# else
#  define __PRI64_PREFIX    "ll"
#  define __PRIPTR_PREFIX
# endif

# define PRIx64     __PRI64_PREFIX "x"
# define PRIu64     __PRI64_PREFIX "u"

#endif
