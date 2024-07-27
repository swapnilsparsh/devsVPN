#!/bin/bash

# Bash completion generator for privateline CLI
# (generates a bash completion script for the `privateline` CLI)
# https://github.com/jordan-privateline/bash-completion-generator-privateline-cli/
#
# Usage:
#   Install the privateline CLI package first: https://www.privateline.net/apps-linux/
#
#   $ bash-completion-generator-privateline-connect-cli.sh > privateline.bash
#   $ source privateline.bash
#   $ sudo mv privateline.bash /usr/share/bash-completion/completions/privateline
#   $ sudo chown root:root /usr/share/bash-completion/completions/privateline
#
# Info: 
#   1)  The recommended directory is `completionsdir`, which you can get with `pkg-config --variable=completionsdir bash-completion`
#       https://github.com/scop/bash-completion
#

# exit on error
set -e

# By default, the source command is `privateline-connect-cli`. 
# Also you can specify custom path to PRIVATELINE CLI binary in the first argument to this script (e.g. `bash-completion-generator-privateline-connect-cli.sh /usr/local/bin/privateline-connect-cli`)
cli="privateline-connect-cli"
if [ ! -z "$1" ]
then
  cli="$1"
fi

# Check if the command/binary exists
if ! command -v "$cli" > /dev/null 2>&1; then
    echo "Error: $cli not found or not executable"
    exit 1
fi

# print header
echo "# bash completion for privateline-connect-cli"
echo ""
echo "_privateline-connect-cli()"
echo "{"
echo '    local cur opts'
echo '    COMPREPLY=()'
echo '    cur="${COMP_WORDS[COMP_CWORD]}" # current word'
echo '    cmd="${COMP_WORDS[1]}"          # next word after "privateline-connect-cli", e.g.: $ privateline-connect-cli <cmd> ...'
echo ""

# determine command list and print list
# first awk bit from: https://stackoverflow.com/a/22222219
COMMAND_LIST=$( $cli -h | grep -Ev ^$ | awk '/Tips:/{f=0} f; /COMMANDS:/{f=1}' | awk '{ print $1 }')

echo "    opts="'"'$COMMAND_LIST" -h"'"'
echo ""
echo '    case "${cmd}" in'

# iterate over commands and print case entries for sub-commands
for i in $COMMAND_LIST; do
    echo "        "$i")"
    SUB_LIST=$($cli $i -h | grep -E '^  -' | awk '{ print $1 }' | tr "|" " ")
    echo "            local "$i"_opts="'"'$SUB_LIST" -h"'"'
    echo "            COMPREPLY=( \$(compgen -W "'"'"\${"$i"_opts}"'"'" -- \${cur}) )"
    echo "            return 0"
    echo "            ;;"
done


# print footer
echo "        -*)"
echo "            return 0"
echo "            ;;"
echo "    esac"
echo ""
echo '   COMPREPLY=($(compgen -W "${opts}" -- ${cur}))'
echo "   return 0"
echo "}"
echo "complete -F _privateline-connect-cli privateline-connect-cli"
echo ""

exit 0
