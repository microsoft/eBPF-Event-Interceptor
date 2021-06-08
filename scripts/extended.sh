#!/bin/bash 

set -e 

bcc="https://github.com/iovisor/bcc/blob/master/INSTALL.md"

echo -e "\n\nInstall \033[1mbcc\033[0m"

echo -e "Hint: See \033[1m$bcc\033[0m for installing bcc"
echo "---------------------------------------------------------------------------------------"
echo -e "\033[1mWarning:\033[0m This will try as \033[1mroot\033[0m to setup bcc and its pre-requisite packages."
echo -e "Warning: If unsure, cancel and setup bcc as appropriate for your environment."
echo "---------------------------------------------------------------------------------------"
while true; do 
	echo -en "Enter \033[1mno\033[0m to skip, \033[1myes\033[0m to proceed: "
	read resp;
	egrep -qwi "yes" <<< $resp && break
	egrep -qwi "no" <<< $resp && { 
		echo "Exiting."
		exit 1
	}
done

echo -e "Setting up packages required for \033[1mbcc\033[0m"
echo -e "Note: We will require \033[1msudo\033[0m access"



if grep -q "20.04" /etc/os-release; then
	sudo apt-get -y install bison build-essential cmake flex git libedit-dev libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev
elif grep -q "18.04" /etc/os-release; then
	sudo apt-get -y install bison build-essential cmake flex git libedit-dev libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev libfl-dev
else 
	sudo apt-get -y install bison build-essential cmake flex git libedit-dev libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev
fi

cd /tmp && git clone https://github.com/iovisor/bcc.git && mkdir bcc/build && cd bcc/build && cmake ../ && make -j`nproc --ignore=1` && sudo make install
