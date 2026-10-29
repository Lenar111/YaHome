#!/bin/bash
# Сборка приложения без установщика (для разработки и CI).
# Использование: tools/build.sh [выходной_файл] [--typecheck]   (флаг можно ставить в любом месте)
set -e
cd "$(dirname "$0")/.."
OUT=""
TYPECHECK=0
for a in "$@"; do
  case "$a" in
    --typecheck) TYPECHECK=1 ;;
    *) [ -z "$OUT" ] && OUT="$a" ;;
  esac
done
OUT="${OUT:-build/YaHome}"
mkdir -p "$(dirname "$OUT")" build
cat Sources/Icons.swift Sources/YaHome.swift > build/YaHome.all.swift
if [ "$TYPECHECK" = "1" ]; then
  swiftc -typecheck build/YaHome.all.swift
else
  swiftc -O build/YaHome.all.swift -o "$OUT"
fi
echo "OK: $OUT"
