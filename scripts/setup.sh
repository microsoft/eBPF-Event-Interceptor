#!/bin/bash 

set -e 

bcc="https://github.com/iovisor/bcc/blob/master/INSTALL.md"

echo -e "\n\nInstall Packages required for \033[1mbcc\033[0m"
echo -e "Hint: See \033[1m$bcc\033[0m for installing bcc"
echo -en "Enter \033[1mno\033[0m to skip: "
read resp
grep -qwi "no" <<< $resp && exit 0
echo -e "We are \033[1mon!\033[0m "
echo -en "\nAre you sure? [Yn]:"
while true; do 
	read answer;
	egrep -qwi "y" <<< $answer && break
	egrep -qwi "n" <<< $answer && exit 0
	echo -en "\nAre you sure? [Yn]:"
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

