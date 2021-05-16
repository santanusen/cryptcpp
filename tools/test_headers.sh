#!/bin/bash

incpath="../include"
tstcpp="test.cpp"
for hpath in ${incpath}/cryptcpp/*.hpp ; do
	hdr=$(basename $hpath)
	echo -n "$hdr ... "
	echo "#include <cryptcpp/${hdr}>" > ${tstcpp}
	echo "int main() { return 0; }" >> ${tstcpp}

	g++ -Wall -Wextra -Werror -I ${incpath} ${tstcpp}
	if [ $? -ne 0 ] ; then
		break
	fi
	echo "[ OK ]"
done

rm -f ${tstcpp} a.out

