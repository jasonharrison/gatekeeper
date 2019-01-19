#!/bin/bash
red=`tput bold; tput setaf 1`
green=`tput bold; tput setaf 2`
reset=`tput sgr0`

set -o allexport
source ../config.env.example
set +o allexport

files="gatekeeper.py"
whitelist="whitelist_gatekeeper.py"

if pipenv run vulture --min-confidence 60 $files $whitelist; then
  echo "Run vulture at 60% confidence: ${green}PASS${reset}"
else
  echo "Run vulture at 60% confidence: ${red}FAIL${reset}"
  exit
fi

if pipenv run yapf -d --style google $files; then
  echo "Check formatting: ${green}PASS${reset}"
else
  echo "Check formatting: ${red}FAIL${reset}"
  exit
fi

if pipenv run isort --check-only --diff $files; then
  echo "Check order of imports: ${green}PASS${reset}"
else
  echo "Check order of imports: ${red}FAIL${reset}"
  exit
fi
