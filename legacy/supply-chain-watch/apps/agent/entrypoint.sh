#!/bin/sh
# tracepoint 부착에 필요한 tracefs/debugfs를 best-effort로 마운트한 뒤 에이전트를 실행한다.
# (privileged 컨테이너에서만 성공. docs/13 §10)
mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null || true
mount -t debugfs nodev /sys/kernel/debug 2>/dev/null || true
exec /agent "$@"
