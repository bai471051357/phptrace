PHP_ARG_ENABLE(trace, whether to enable trace support,
[  --enable-trace          Enable trace support])

PHP_ARG_ENABLE(chain, whether to enable chain support,
[  --enable-chain          Enable chain support])

if test "$PHP_TRACE" != "no"; then

  dnl check ZTS support
  if test "$PHP_THREAD_SAFETY" == "yes"; then
    AC_MSG_ERROR([Trace does not support ZTS])
  fi

  dnl check mmap functions
  AC_CHECK_FUNCS(mmap)
  AC_CHECK_FUNCS(munmap)

  PHP_TRACE_COMMON_FILES="\
    common/trace_comm.c \
    common/trace_ctrl.c \
    common/trace_mmap.c \
    common/trace_type.c \
    common/trace_filter.c \
    deps/sds/sds.c"
    
  PHP_TRACE_SOURCE_FILES="trace.c \
    $PHP_TRACE_COMMON_FILES"
    
  dnl check chain support
  if test "$PHP_CHAIN" != "no"; then
      AC_DEFINE(TRACE_CHAIN,1,[Inlcude support chain])
      PHP_TRACE_SOURCE_FILES="$PHP_TRACE_SOURCE_FILES\
        trace_chain.c"
  fi

  dnl $ext_srcdir available after PHP_NEW_EXTENSION
  PHP_NEW_EXTENSION(trace, $PHP_TRACE_SOURCE_FILES, $ext_shared)

  dnl configure can't use ".." as a source filename, so we make a link here
  ln -sf $ext_srcdir/../common $ext_srcdir
  ln -sf $ext_srcdir/../deps $ext_srcdir

  dnl add common include path
  PHP_ADD_INCLUDE($ext_srcdir)
  PHP_ADD_INCLUDE($ext_srcdir/common)
  PHP_ADD_INCLUDE($ext_srcdir/deps)

  PHP_ADD_MAKEFILE_FRAGMENT

fi

dnl vim:et:ts=2:sw=2
