import os

rc_local_path = "/etc/rc.local"
nebula_cmd = "/opt/nebula/bin/nebula -config /opt/nebula/etc/nebula.yml"

# Create rc.local if it doesn't exist
if not os.path.exists(rc_local_path):
    with open(rc_local_path, "w") as f:
        f.write("#!/bin/sh -e\n\nexit 0\n")
    os.chmod(rc_local_path, 0o755)

# Read current content
with open(rc_local_path, "r") as f:
    lines = f.readlines()

# Insert the command if not present
if not any(nebula_cmd in line for line in lines):
    exit_index = next((i for i, line in enumerate(lines) if line.strip() == "exit 0"), len(lines))
    lines.insert(exit_index, f"{nebula_cmd}\n")

    with open(rc_local_path, "w") as f:
        f.writelines(lines)
