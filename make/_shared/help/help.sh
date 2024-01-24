#!/usr/bin/env bash

# Copyright 2023 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu -o pipefail

RULE_COLOR="$(tput setaf 6)"
CATEGORY_COLOR="$(tput setaf 3)"
CLEAR_STYLE="$(tput sgr0)"
PURPLE=$(tput setaf 125)

EMPTYLINE_REGEX="^\s*$"
DOCBLOCK_REGEX="^##\s*(.*)$"
CATEGORY_REGEX="^##\s*@category\s*(.*)$"
TARGET_REGEX="^([a-zA-Z0-9%_\/%-\$\(\)]+):.*$"

EMPTY_ITEM="<start-category><end-category><start-target><end-target><start-comment><end-comment>"


# shellcheck disable=SC2086
raw_lines=$(cat ${MAKEFILE_LIST} | tr '\t' '    ' | grep -E "($TARGET_REGEX|$DOCBLOCK_REGEX|$EMPTYLINE_REGEX)")
extracted_lines=""
extracted_current="$EMPTY_ITEM"
max_target_length=0

## Extract all the commented targets from the Makefile
while read -r line; do
    if [[ $line =~ $EMPTYLINE_REGEX ]]; then
        # Reset current item.
        extracted_current="$EMPTY_ITEM"
    elif [[ $line =~ $CATEGORY_REGEX ]]; then
        extracted_current=${extracted_current//<start-category><end-category>/<start-category>${BASH_REMATCH[1]}<end-category>}
    elif [[ $line =~ $TARGET_REGEX ]]; then
        # only keep the target if there is a comment
        if [[ $extracted_current != *"<start-comment><end-comment>"* ]]; then
            max_target_length=$(( ${#BASH_REMATCH[1]} > max_target_length ? ${#BASH_REMATCH[1]} : max_target_length ))
            extracted_current=${extracted_current//<start-target><end-target>/<start-target>${BASH_REMATCH[1]}<end-target>}
            extracted_lines="$extracted_lines\n$extracted_current"
        fi

        extracted_current="$EMPTY_ITEM"
    elif [[ $line =~ $DOCBLOCK_REGEX ]]; then
        extracted_current=${extracted_current//<end-comment>/${BASH_REMATCH[1]}<newline><end-comment>}
    fi
done <<< "$raw_lines"

extracted_lines=$(echo -e "$extracted_lines" | LC_ALL=C sort -r)
current_category=""

## Print the help
echo "Usage: make [target1] [target2] ..."

IFS=$'\n'; for line in $extracted_lines; do
    category=$([[ $line =~ \<start-category\>(.*)\<end-category\> ]] && echo "${BASH_REMATCH[1]}")
    target=$([[ $line =~ \<start-target\>(.*)\<end-target\> ]] && echo "${BASH_REMATCH[1]}")
    comment=$([[ $line =~ \<start-comment\>(.*)\<end-comment\> ]] && echo -e "${BASH_REMATCH[1]//<newline>/\\n}")

    if [[ "$current_category" != "$category" ]]; then
        current_category=$category
        echo -e "\n${CATEGORY_COLOR}${current_category}${CLEAR_STYLE}"
    fi

    is_first_line=true
    while read -r comment_line; do
        if [[ "$is_first_line" == true ]]; then
            is_first_line=false
            padding=$(( max_target_length - ${#target} ))
            printf "    %s%${padding}s ${PURPLE}>${CLEAR_STYLE} %s\n" "${RULE_COLOR}${target}${CLEAR_STYLE}" "" "${comment_line}"
        else
            printf "    %${max_target_length}s   %s\n" "" "${comment_line}"
        fi
    done <<< "$comment"
done
