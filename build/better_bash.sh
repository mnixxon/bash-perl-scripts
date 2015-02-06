# This script adds aliases and other customizations to make bash faster 

# In order to add this to your environment you will need to source this file.
# Just add this file anywhere you like such as your home directory or
# /etc/profile.d if you wish to add it for all users on the system.

# Then add this block of code to your ~/.bashrc file.  The located of the git.sh
# file is dependent upon when you put it.

#    if [ -f ~/better_bash.sh ]; then
#        . ~/better_bash.sh
#    fi
export CLICOLOR=1
#export LSCOLORS=GxFxCxDxBxegedabagaced
export CDPATH=~
alias p='pushd'
alias d='dirs -v'
alias ll='ls -la'
alias ..='cd ..'
alias ..2='cd ../..'
alias ..3='cd ../../..'
alias ..4='cd ../../../..'
dc() { builtin cd "$@" && ls; } # 'dc' will change directory and then do an 'ls'
export PS1='\u@\h:\W\$'
