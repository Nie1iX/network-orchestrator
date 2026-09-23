#!/bin/sh
# Synthetic credentials used only by the disposable OpenVPN peer container.
set -eu

[ "$#" -eq 1 ] || exit 1
{
    IFS= read -r username
    IFS= read -r password
} < "$1"
[ "$username" = alice ] && [ "$password" = correct-horse ]
