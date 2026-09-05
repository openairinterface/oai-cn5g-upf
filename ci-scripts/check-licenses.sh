#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Verify that every source file declares one of this project's ALLOWED
# licences -- an allowlist, not a hunt for specific bad ones.
# The script checks only the files which are added using git add, as it uses
# git ls-files.
#
# The allowlist is read from LICENSES/preferred/, so adding a licence to the
# project is a single act: drop its text in that directory. Nothing here needs
# editing, and a licence that is not in that directory cannot slip in.
#
# Two outcomes per file:
#
#   ok         SPDX-License-Identifier names an allowed licence
#   FAIL       SPDX-License-Identifier names anything else
#   note       no SPDX tag -- images, dotfiles, templates, and generated files
#
# Usage: ci-scripts/check-licenses.sh [-v|--verbose]
# Exit:  0 all declared licences allowed, 1 violations found, 2 usage error

set -u -o pipefail

VERBOSE=0
case "${1:-}" in
  "") ;;
  -v|--verbose) VERBOSE=1 ;;
  -h|--help)
    sed -n '3,20p' "$0"
    echo
    echo 'Options: -v, --verbose  list skipped and untagged files'
    echo '        -h, --help     display this help'
    echo 'Exit codes: 0 pass, 1 violations, 2 usage/internal error'
    exit 0
    ;;
  *) echo "Usage: $0 [-v|--verbose]" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.." || exit 2

# Submodules carry their own NOTICE and are reviewed in their own repositories.
readonly SKIP_PATHS='^(src/common-src|build/common-build|ci-scripts/common)/'

# Files whose subject IS licensing; they quote licence names by definition.
readonly SKIP_FILES='^(NOTICE|LICENSE|LICENSES/.*|CHANGELOG\.md|README\.md|ci-scripts/check-licenses\.sh|src/upf_app/cmake/Configuration\.(cpp|h)\.in)$'

# ---------------------------------------------------------------- allowlist
if [[ ! -d LICENSES/preferred ]]; then
  echo "check-licenses: LICENSES/preferred/ not found" >&2
  exit 2
fi

ALLOWED=()
for f in LICENSES/preferred/*.txt; do
  [[ -e "$f" ]] || continue
  base=$(basename "$f" .txt)
  # A licence file named CSSL-v1.0.txt is declared as LicenseRef-CSSL-1.0, so
  # accept the bare name, a LicenseRef- form, and the "-v<digit>" collapsed.
  norm=${base//-v/-}
  ALLOWED+=( "$base" "LicenseRef-$base" "$norm" "LicenseRef-$norm" )
done

if [[ ${#ALLOWED[@]} -eq 0 ]]; then
  echo "check-licenses: no licence files in LICENSES/preferred/" >&2
  exit 2
fi

is_allowed() {
  local id=$1 a
  for a in "${ALLOWED[@]}"; do [[ "$id" == "$a" ]] && return 0; done
  return 1
}

expression_allowed() {
  local expression=$1 token
  # SPDX expressions are composed of license IDs and the OR/AND/WITH
  # operators. Every license ID in the expression must be allowlisted.
  expression=${expression//\(/ }
  expression=${expression//\)/ }
  for token in $expression; do
    case "$token" in OR|AND|WITH) continue ;; esac
    is_allowed "$token" || return 1
  done
  return 0
}

echo "Allowed licences (from LICENSES/preferred/):"
for f in LICENSES/preferred/*.txt; do
  [[ -e "$f" ]] && echo "  - $(basename "$f" .txt)"
done
echo

# ---------------------------------------------------------------- scan
if [[ $VERBOSE -eq 1 ]]; then
  while IFS= read -r skipped; do
    [[ "$skipped" =~ $SKIP_PATHS || "$skipped" =~ $SKIP_FILES ]] && echo "skip  $skipped"
  done < <(git ls-files)
fi
mapfile -t FILES < <(git ls-files | grep -vE "$SKIP_PATHS" | grep -vE "$SKIP_FILES")
if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "check-licenses: no files to scan -- is this a git checkout?" >&2
  exit 2
fi

violations=0
declared=0
untagged=0
untagged_list=""

for f in "${FILES[@]}"; do
  [[ -f "$f" ]] || continue

  # -I skips binaries. Strip trailing comment terminators: "-->", "*/", " #".
  mapfile -t ids < <(grep -hIoE "SPDX-License-Identifier:[[:print:]]*" "$f" 2>/dev/null \
      | sed -E 's/SPDX-License-Identifier:[[:space:]]*//; s/[[:space:]]*(-->|\*\/).*$//; s/[[:space:]]+$//' \
      | grep -v '^$' | sort -u)

  if [[ ${#ids[@]} -gt 0 ]]; then
    for id in "${ids[@]}"; do
      if expression_allowed "$id"; then
        declared=$((declared + 1))
        [[ $VERBOSE -eq 1 ]] && echo "ok    $f  [$id]"
      else
        violations=$((violations + 1))
        echo "FAIL  $f"
        echo "        declares '$id', which is not in LICENSES/preferred/"
        grep -nIE "SPDX-License-Identifier" "$f" | head -3 | sed 's/^/          /'
      fi
    done
    continue
  fi

  # Untagged files are informational: arbitrary licence wording in prose is
  # not proof that the file itself is distributed under that licence.
  untagged=$((untagged + 1))
  untagged_list="$untagged_list  $f"$'\n'
done

echo "----------------------------------------------------------------------"
if [[ $untagged -gt 0 ]]; then
  echo "note: $untagged file(s) carry no SPDX tag and no licence text"
  echo "      (images, dotfiles, templates -- not a violation)"
  [[ $VERBOSE -eq 1 ]] && printf '%s' "$untagged_list"
  echo
fi

if [[ $violations -eq 0 ]]; then
  echo "check-licenses: PASS -- ${#FILES[@]} files scanned, $declared declaration(s), all allowed"
  exit 0
fi

cat <<EOF
check-licenses: FAIL -- $violations violation(s)

Every file must declare one of the licences in LICENSES/preferred/ via an
SPDX-License-Identifier line.

If a file is legitimately third-party under another licence, record it in
NOTICE and add an SPDX declaration for the actual licence. If the project is
adopting a new licence, add its text to LICENSES/preferred/.
EOF
exit 1
