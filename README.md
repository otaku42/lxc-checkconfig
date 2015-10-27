# lxc-checkconfig
===============
Checks whether a given kernel configuration file fulfills all requirements for
LXC. 

This tool is a reimplementation of the lxc-checkconfig.sh script that comes as
part of LXC. It provides a bit more functionality, however, such as returning
the check results in JSON notation.

## Usage

```
usage: lxc-checkconfig.py [options]
   or: lxc-checkconfig.py -h|--help

General options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config CONFIG_FILE
                      Path and name of kernel configuration file to check
  -j, --json            Output in JSON format rather than normal text
  -q, --quiet           Suppress output of test results

Text output options:
  -F, --fancy           If set, output will be beautified a bit
  -m, --monochrome      Don't use colors in output

JSON output options:
  -f, --flat            Don't group results

If CONFIG_FILE is not specified, the tool will look at the environment
variable CONFIG. If that variable is not set either, it will look at
/proc/config.gz, /lib/modules/KVER/build/.config and /boot/config-KVER, in
this order (where KVER is the version of the running kernel).
```

## Output examples

With no arguments passed (or when just using `--config` to specify the
name of the kernel configuration file), the output of the Python version
is almost identical to that of the shell script. The only difference is
that the name of the checked file also be printed on top of the check
results.

The `--fancy` argument will change the output to be more streamlined,
easier to read:

```
# python lxc-checkconfig.py --fancy`
========================================
======== config-3.16.0-4-amd64 =========
========================================

-------------- Namespaces --------------
Namespaces ....................: enabled
Utsname namespace .............: enabled
Ipc namespace .................: enabled
Pid namespace .................: enabled
User namespace ................: enabled
Network namespace .............: enabled
Multiple /dev/pts instances ...: enabled

------------ Control Groups ------------
Cgroup ........................: enabled
Cgroup clone_children flag ....: enabled
Cgroup device .................: enabled
Cgroup sched ..................: enabled
Cgroup cpu account ............: enabled
Cgroup memory controller ......: enabled
Cgroup cpuset .................: enabled

----------------- Misc -----------------
Veth pair device ..............: enabled
Macvlan .......................: enabled
Vlan ..........................: enabled
File capabilities .............: enabled

========================================
18 checks: 0 warnings, 0 errors
```

The colors may be suppressed by adding the `--monochrome` argument.

Using the `--json` argument, the results will be returned in JSON format,
with the results being grouped:
```
python lxc-checkconfig.py --json
{
    "Control Groups": {
        "Cgroup": "enabled",
        "Cgroup clone_children flag": "enabled",
        "Cgroup cpu account": "enabled",
        "Cgroup cpuset": "enabled",
        "Cgroup device": "enabled",
        "Cgroup memory controller": "enabled",
        "Cgroup sched": "enabled"
    },
    "Misc": {
        "File capabilities": "enabled",
        "Macvlan": "enabled",
        "Veth pair device": "enabled",
        "Vlan": "enabled"
    },
    "Namespaces": {
        "Ipc namespace": "enabled",
        "Multiple /dev/pts instances": "enabled",
        "Namespaces": "enabled",
        "Network namespace": "enabled",
        "Pid namespace": "enabled",
        "User namespace": "enabled",
        "Utsname namespace": "enabled"
    },
    "Statistics": {
        "Checked file": "/boot/config-3.16.0-4-amd64",
        "Found errors": 0,
        "Found warnings": 0,
        "Performed checks": 18
    }
}
```

Adding `--flat` suppresses the grouping, though.

To suppress the printout of the check results, use the `--quiet` argument,
which may be useful when calling the tool from within a script.

## Exit code

In any case - with or without printout - the exit code will be set to 1 in
case of any error (such as a failed mandatory check or when no configuration
file could be found), and 0 if all is good.
