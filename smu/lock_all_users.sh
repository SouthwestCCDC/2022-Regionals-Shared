#!/bin/bash

[[ $EUID -ne 0 ]] && echo "This script must be run as root." && exit 1
UNDO=false
if [[ ${@:1} == "--oops" || ${@:1} == "-o" ]]; then
	UNDO=true
fi
for user in $(getent passwd):
do
	NAME=$(echo $user | awk -F: '{print $1}')
	SHELL=$(echo $user | awk -F: '{print $NF}')
	if [[ ! " $@ " =~ " ${NAME} " ]] && [[ -n $(grep '^[^#]' /etc/shells | grep "$SHELL") ]]; then
		if $UNDO; then
			chage -E 0 $NAME && echo "$NAME unlocked"
		else
			chage -E -1 $NAME && echo "$NAME locked"
		fi		
	fi 

done
