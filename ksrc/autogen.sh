#!/bin/sh

echo "Running aclocal..."
aclocal || exit 1
echo "Running autoheader..."
autoheader || exit 1
echo "Running autoconf..."
autoconf || exit 1
