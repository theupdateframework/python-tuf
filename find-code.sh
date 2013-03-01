find \( -name "*.py" \) -type f -print | xargs grep -nis -IC1 --color=always "$1" | less -R
