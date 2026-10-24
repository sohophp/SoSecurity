PHP_ARG_ENABLE(sosecurity_monotonic, whether to enable the local PHP 7.2 monotonic test adapter,
[  --enable-sosecurity-monotonic  Enable local monotonic test adapter], no)

if test "$PHP_SOSECURITY_MONOTONIC" != "no"; then
  PHP_NEW_EXTENSION(sosecurity_monotonic, sosecurity_monotonic.c, $ext_shared)
fi
