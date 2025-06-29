# nebdeploy

nebdeploy is a script to download and deploy Nebula on Linux and FreeBSD based systems.

### Warning - Use At Your Own Risk
This is remote execution lab intended only for use in a lab and should not be used in a production environment as there is a risk of dataloss.

## Usage

### Install

python3 nebdeploy.py -i

### Uninstall

python3 nebdeploy.py -u

### Verify (ping all nebula ips)

python3 nebdeploy.py -v

## Installation

### Dependencies

#### Time Sync

All hosts must be in time sync. Even a few seconds difference is enough to prevent nebula from starting. Use of NTP or other mechanism to ensure all hosts are in sync is recommended.

Do Not Proceed Until All Hosts Clocks Are Synced!

#### Python3.10+ Pip3

```python3 --version```

and

```pip3 --version```

#### Clone the Repo

On a linux host clone the repo:

```git clone https://github.com/j-sims/nebdeploy```

#### Change dir

```cd nebdeploy```

#### Run the script
```python3 nebdeploy.py```
