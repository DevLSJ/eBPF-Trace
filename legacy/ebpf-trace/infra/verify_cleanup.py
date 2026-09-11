"""Verify SIGKILL releases this service's XDP program/maps and systemd recovers it."""

import json
import subprocess
import time


def bpf(*args):
    return json.loads(subprocess.check_output(["bpftool", "-j", *args], text=True))


def program_id():
    for section in bpf("net"):
        for entry in section.get("xdp", []):
            if entry.get("devname") == "enp0s1":
                return entry["id"]
    return None


def main():
    old_id = program_id()
    if old_id is None:
        raise SystemExit("No collector XDP program attached")
    info = bpf("prog", "show", "id", str(old_id))
    if isinstance(info, list):
        info = info[0]
    maps = set(info["map_ids"])
    subprocess.run(
        ["systemctl", "kill", "--signal=SIGKILL", "--kill-who=main", "ebpf-collector"], check=True
    )
    for _ in range(40):
        remaining_programs = {item["id"] for item in bpf("prog", "show")}
        remaining_maps = {item["id"] for item in bpf("map", "show")}
        if old_id not in remaining_programs and not (maps & remaining_maps):
            break
        time.sleep(0.1)
    else:
        raise AssertionError("Terminated collector retained kernel objects")
    for _ in range(150):
        new_id = program_id()
        if new_id and new_id != old_id:
            print(
                json.dumps(
                    {
                        "released_program": old_id,
                        "released_maps": sorted(maps),
                        "restarted_program": new_id,
                        "passed": True,
                    }
                )
            )
            return
        time.sleep(0.1)
    raise AssertionError("Collector did not recover")


if __name__ == "__main__":
    main()
