# This script is for custom aliases and other things to make git faster.

# In order to add this to your environment you will need to source this file.
# Just add this file anywhere you like such as your home directory or
# /etc/profile.d if you wish to add it for all users on the system.

# Then add this block of code to your ~/.bashrc file.  The located of the git.sh
# file is dependent upon when you put it.

#    if [ -f ~/git.sh ]; then
#        . ~/git.sh
#    fi

alias gl='git log --all --decorate --graph --oneline'
alias gs='git status'
alias gr='git remote -v'
alias gb='git branch -v'
alias gc='git commit'
alias ga='git add'
alias gp='git push'
