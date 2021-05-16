#!/bin/bash

FORMATTER="clang-format -i"

for sfile in $(find ./ -type f \( -iname \*.cpp -o -iname \*.hpp \) ) ; do
        ${FORMATTER} "$sfile";
done

