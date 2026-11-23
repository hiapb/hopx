#!/usr/bin/env bash
set -euo pipefail
dir=$1
binary=$dir/hopx-node
state=$dir/state
shift

if [[ -f $state/update.pending ]]; then
  if [[ -f $state/update.attempted ]]; then
    if [[ -x $binary.previous ]]; then
      mv -f -- "$binary.previous" "$binary"
    fi
    reason='候选未通过启动检查'
    if [[ -s $state/update.check ]]; then IFS= read -r reason < "$state/update.check" || true; fi
    printf '%s\n' "$(cat "$state/update.pending"): 上一版本已恢复，$reason" > "$state/update.error"
    rm -f -- "$state/update.pending" "$state/update.attempted" "$state/update.check" "$binary.candidate"
  elif [[ -x $binary.candidate ]]; then
    rm -f -- "$state/update.check"
    cp -p -- "$binary" "$binary.previous"
    touch "$state/update.attempted"
    mv -f -- "$binary.candidate" "$binary"
  else
    printf '%s\n' '候选二进制缺失' > "$state/update.error"
    rm -f -- "$state/update.pending"
  fi
fi

exec "$binary" --state "$state" --update-binary "$binary" --release-key "${HOPX_RELEASE_KEY:-/etc/hopx-node/release.pem}" "$@"
