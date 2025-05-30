# Introduction to AWK

AWK is a powerful text-processing tool available in UNIX and Linux systems. It is particularly useful for handling structured data, such as logs, tables, and configuration files. AWK reads input line by line, splits each line into fields, and applies specified operations on them.

## Basic Syntax
An AWK command follows this structure:
```bash
awk 'pattern {action}' filename
```

- Pattern: A condition to match lines (optional)
- Action: What AWK should do when the pattern matches

Example:
```bash
awk '{print $1}' file.txt
```

This prints the first column of each line.

## Working with /etc/passwd
The /etc/passwd file contains user account information. Each line has fields separated by colons (:), including username, password placeholder, user ID, group ID, home directory, and shell.

## Extracting Usernames and Shells
To display only the username and shell, use:
```bash
awk -F: '{print $1, $7}' /etc/passwd
```
- -F: sets the field separator to :
- $1 represents the username
- $7 represents the login shell

Example output:
```bash
root /bin/bash
user1 /bin/zsh
user2 /usr/sbin/nologin
```

## Filtering Users with /bin/bash
To show only users using /bin/bash:
```bash
awk -F: '$7 == "/bin/bash" {print $1}' /etc/passwd
```

Print Lines with More than 5 Fields
```bash
awk -F: 'NF > 5' /etc/passwd
```

To count the number of users:
```bash
awk -F: 'END {print NR}' /etc/passwd
```

- NR represents the total number of processed lines.
