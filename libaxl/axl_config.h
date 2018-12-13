// This is some configuration written manually on a Linux x86-64 system. Not
// tested/adapted for other systems yet.

#if _WIN64 || __x86_64__ || __ppc64__
#  define PTR_TO_INT(ptr) ((int) (long) (ptr))
#  define INT_TO_PTR(integer) ((axlPointer) (long) ((int)integer))
#else
#  define PTR_TO_INT(ptr) ((int) (ptr))
#  define INT_TO_PTR(integer) ((axlPointer) ((int)integer))
#endif

#if _WIN32
#  define AXL_OS_WIN32
#else
#  define AXL_OS_UNIX
#endif

#define AXL_HAVE_VASPRINTF
