#!/bin/bash
# Paste-safe. Run on the Mac (Terminal with sudo, or Mosyle Unix Command).
# Do not paste get-nessus-agent-version.sh into Unix Command -- it is too long
# and Mosyle will echo the truncated source as the "result".
echo "HOST: $(hostname -s)  DATE: $(date '+%Y-%m-%d %H:%M:%S')"
echo "----- nessuscli -v (running binary) -----"
/Library/NessusAgent/run/sbin/nessuscli -v 2>&1 | head -n 5
echo "----- nessusd -v -----"
/Library/NessusAgent/run/sbin/nessusd -v 2>&1 | head -n 3
echo "----- pkgutil receipts (what a local inventory plugin reads) -----"
pkgutil --pkgs 2>/dev/null | grep -i nessus | while IFS= read -r p; do
  echo "PACKAGE: $p"
  pkgutil --pkg-info "$p" 2>/dev/null
  echo "----"
done
echo "----- Info.plist under /Library/NessusAgent -----"
find /Library/NessusAgent -name Info.plist 2>/dev/null | while IFS= read -r f; do
  echo "PLIST: $f"
  /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$f" 2>/dev/null
  /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$f" 2>/dev/null
done
echo "----- files whose name contains version -----"
find /Library/NessusAgent -iname '*version*' 2>/dev/null | head -n 20
echo "----- nessuscli agent status -----"
/Library/NessusAgent/run/sbin/nessuscli agent status 2>&1 | head -n 40
echo "----- other nessuscli/nessusd on disk -----"
find /Library /Applications /opt /usr/local -maxdepth 5 \( -name nessuscli -o -name nessusd \) 2>/dev/null
echo "DONE"
