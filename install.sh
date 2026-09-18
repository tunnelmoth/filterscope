#!/usr/bin/env bash
# filterscope installer — pipx if available (isolated), else pip --user.
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$DIR"
else
  python3 -m pip install --user --upgrade "$DIR"
  BIN="$(python3 -c 'import sysconfig;print(sysconfig.get_path("scripts", "posix_user"))')"
  case ":$PATH:" in
    *":$BIN:"*) ;;
    *) echo "NOTE: add $BIN to PATH (export PATH=\"$BIN:\$PATH\")" ;;
  esac
fi
echo "installed → run: filterscope --version"
echo "the Tor test needs a 'tor' binary on PATH (apt/pacman/brew install tor)"
