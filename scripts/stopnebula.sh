#!/bin/bash

os_name=$(uname)

if [[ "$os_name" == "Linux" ]]; then
  running_procs=$(ps -ef | grep /opt/nebula/bin/nebula | grep -v grep | wc -l)
  if (( running_procs > 0 )); then
    ps -ef | grep /opt/nebula/bin/nebula | grep -v grep | awk '{print $2}' | xargs kill
  fi
elif [[ "$os_name" == "Isilon OneFS" ]]; then
  running_procs=$(ps aux | grep /opt/nebula/bin/nebula | grep -v grep | wc -l)
  if (( running_procs > 0 )); then
    ps aux | grep /opt/nebula/bin/nebula | grep -v grep | awk '{print $2}' | xargs kill
  fi
else
  echo "Unknown OS: $os_name"
fi

exit 0


