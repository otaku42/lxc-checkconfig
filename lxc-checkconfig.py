#!/usr/bin/env python
import sys
import os
import re

from argparse import ArgumentParser


class LxcCcArgumentParser(ArgumentParser):
	""" Parses the arguments passed from the command line when we get
	called.

	Extends the `ArgumentParser` class by automatically setting up
	all supported arguments during object initialization.
	"""

	def __init__(self, *args, **kwargs):
		kwargs["add_help"] = False
		ArgumentParser.__init__(self, *args, **kwargs)

		self.usage = "%(prog)s [options]\n   or: %(prog)s -h|--help"
		self.description = """
			Checks whether a given kernel configuration file fulfills all
			requirements for LXC.
			"""
		self.epilog = """
			If CONFIG_FILE is not specified, the tool will look at the
			environment variable CONFIG. If that variable is not set either,
			it will look at /proc/config.gz, /lib/modules/KVER/build/.config
			and /boot/config-KVER, in this order (where KVER is the version of
			the running kernel).
			"""

		g = self.add_argument_group("General options")
		g.add_argument("-h", "--help",
			dest="show_help", action="store_true", default=False,
			help="show this help message and exit")
		g.add_argument("-c", "--config",
			dest="config_file", default=None,
			help="Path and name of kernel configuration file to check")
		g.add_argument("-j", "--json",
			dest="output_json", action="store_true", default=False,
			help="Output in JSON format rather than normal text")
		g.add_argument("-q", "--quiet",
			dest="quiet", action="store_true", default=False,
			help="Suppress output of test results")

		g = self.add_argument_group("Text output options")
		g.add_argument("-F", "--fancy",
			dest="fancy_mode", action="store_true", default=False,
			help="If set, output will be beautified a bit")
		g.add_argument("-m", "--monochrome",
			dest="colored_mode", action="store_false", default=True,
			help="Don't use colors in output")

		g = self.add_argument_group("JSON output options")
		g.add_argument("-f", "--flat",
			dest="flat_mode", action="store_true", default=False,
			help="Don't group results")



class KernelConfig(object):
	""" Represents the content of a kernel configuration file.
	
	Both, plain text and gzip'ed configurations are supported.
	
	Example usage:
	
		fn = "/proc/config.gz"
		try:
			config = KernelConfig(fn)
		except:
			print("Loading configuration from %s failed, doh!" % fn)
		
		print("Kernel version is %s" % config.version)
		if config.isset("CONFIG_SMP|CONFIG_X86_64_SMP"):
			print("Cool, that's an SMP kernel!")
		print("Output format is " % config["CONFIG_OUTPUT_FORMAT"])
	Pretty straight-foward.
	"""

	def __init__(self, filename = None):
		self.config = {}
		self.version = None
		self.filename = filename
		if filename is not None:
			self.load(filename)

	def load(self, filename):
		""" Load kernel configuration from given `filename`. """
		try:
			fn = str(filename)
			if fn.endswith(".gz") is True:
				import gzip
				fobj = gzip.open(fn, "r")
			else:
				fobj = open(fn, "r")
		except:
			raise

		for line in fobj:
			if line[0] == "#":
				m = re.match(r"^# Linux[^ ]* (\d+\.\d+\.[^ ]+) Kernel Configuration.*$", line)
				if m:
					self.version = KernelVersion(m.group(1))
			elif line.startswith("CONFIG_") is True:
				key, value = line.split("=", 1)
				self.config[key] = value.strip()

	def isset(self, symbol):
		""" Return True if given symbol is defined as either "y" or "m",
		otherwise False. """
		for key in str(symbol).split("|"):
			try:
				return self.config[key] in ["y", "m"]
			except KeyError:
				continue
		return False

	def __getitem__(self, key):
		try:
			return self.config[key]
		except KeyError:
			raise

	def __repr__(self):
		return "KernelConfig(filename=%s)" % ("None" if self.filename is None else self.filename)

	def __str__(self):
		return "<KernelConfig %s>" % ("None" if self.filename is None else self.filename)



class KernelVersion(object):
	""" A simple (read: not fool-proof) representation of Linux kernel
	version numbers.
	
	Example usage:
	
		>>> a = KernelVersion("2.6.32-ckr1")
		>>> b = KernelVersion("3.16.0-4-amd64")
		>>> a < b
		True
		>>> b < a
		False
		>>> a >= "2.6.32"
		True
		>>> b.version
		3
		>>> b.sublevel
		0
		>>> b.extraversion
		'-4-amd64'
		>>> b > "4.0"
		False
	
	Note: when comparing two KernelVersion instances, only the version
	components that are present in both of them get compared:
	
		>>> a = KernelVersion("2.6.32-ckr1")
		>>> b = KernelVersion("2.4")
		>>> a > b
		True
	
	"""

	def __init__(self, version):
		ver = str(version).split(".")
		if "-" in ver[-1]:
			ver[-1], extra = ver[-1].split("-", 1)
			extra = "-%s" % extra
		else:
			extra = None

		if len(ver) < 2:
			raise ValueError()
		for v in ver:
			if v.isdigit() is False:
				raise ValueError()

		self._raw_version = str(version)
		self.version = int(ver[0])
		self.patchlevel = int(ver[1])
		self.sublevel = int(ver[2]) if (len(ver) > 2) else None
		self.extraversion = extra

	def __str__(self):
		return str(self._raw_version)

	def __cmp__(self, version):
		if not isinstance(version, KernelVersion):
			try:
				other = KernelVersion(version)
			except ValueError:
				raise
		else:
			other = version

		if self.version < other.version:
			return -1
		elif self.version > other.version:
			return 1
		# from here on: self.version == other.version
		elif self.patchlevel < other.patchlevel:
			return -1
		elif self.patchlevel > other.patchlevel:
			return 1
		# from here on: self.patchlevel == other.patchlevel
		elif (self.sublevel is not None) and (other.sublevel is not None):
			if self.sublevel < other.sublevel:
				return -1
			elif self.sublevel > other.sublevel:
				return 1
			else:
				return 0
		# ok, so: self == other
		else:
			return 0



class LxcConfigCheck(object):
	""" Performs the actual checks onto a given KernelConfig object and records
	them for further use.
	
	The outcome of the checks may be verified using the properties
	`has_warnings` and `has_errors` (bool). The number of checks as well as the
	number of found warnings and errors are available through the properties
	`checks`, `warnings` and `errors`, respectively.
	
	Use `as_text()` or `as_json()` to get the actual check results as text or
	in JSON format.
	"""

	def __init__(self, config):
		assert(isinstance(config, KernelConfig))
		
		self._config = config
		self._sections = []
		self._results = {}
		self._stats = {
			"checks": 0,
			"warnings": 0,
			"errors": 0,
		}

		self._execute()
		self._update_stats()

	def _execute(self):
		cfg = self._config

		cgmount_paths = []
		try:
			fobj = open("/proc/self/mounts", "r")
			for mount in fobj:
				m = mount.strip().split()
				if m[2] == "cgroup":
					cgmount_paths.append(m[1])
			fobj.close()
			del m, mount, fobj
		except:
			pass

		self._sections.append("Namespaces")
		self._results["Namespaces"] = [
			("Namespaces", cfg.isset("CONFIG_NAMESPACES"), True),
			("Utsname namespace", cfg.isset("CONFIG_UTS_NS"), False),
			("Ipc namespace", cfg.isset("CONFIG_IPC_NS"), True),
			("Pid namespace", cfg.isset("CONFIG_PID_NS"), True),
			("User namespace", cfg.isset("CONFIG_USER_NS"), False),
			("Network namespace", cfg.isset("CONFIG_NET_NS"), False),
			("Multiple /dev/pts instances", cfg.isset("CONFIG_DEVPTS_MULTIPLE_INSTANCES"), False),
		]

		self._sections.append("Control Groups")
		self._results["Control Groups"] = [
			("Cgroup", cfg.isset("CONFIG_CGROUPS"), True),
		]

		if (len(cgmount_paths) > 0):
			x = ("Cgroup clone_children flag", os.path.isfile("%s/cgroup.clone_children" % cgmount_paths[0]), True)
		else:
			x = ("Cgroup namespace", cfg.isset("CONFIG_CGROUP_NS"), True)
		self._results["Control Groups"].append(x)
		del x

		self._results["Control Groups"].extend([
			("Cgroup device", cfg.isset("CONFIG_CGROUP_DEVICE"), False),
			("Cgroup sched", cfg.isset("CONFIG_CGROUP_SCHED"), False),
			("Cgroup cpu account", cfg.isset("CONFIG_CGROUP_CPUACCT"), False),
			("Cgroup memory controller", cfg.isset("CONFIG_MEMCG|CONFIG_CGROUP_MEM_RES_CTLR"), False),
		])
		if cfg.isset("CONFIG_SMP") is True:
			self._results["Control Groups"].append(("Cgroup cpuset", cfg.isset("CONFIG_CPUSETS"), False))

		self._sections.append("Misc")
		self._results["Misc"] = [
			("Veth pair device", cfg.isset("CONFIG_VETH"), False),
			("Macvlan", cfg.isset("CONFIG_MACVLAN"), False),
			("Vlan", cfg.isset("CONFIG_VLAN_8021Q"), False)
		]

		if cfg.version < "2.33":
			x = ("File capabilities", cfg.isset("CONFIG_SECURITY_FILE_CAPABILITIES"), False)
		else:
			x = ("File capabilities", True, False)
		self._results["Misc"].append(x)
		del x

	def _update_stats(self):
		for section in self._sections:
			for (_, result, mandatory) in self._results[section]:
				self._stats["checks"] += 1
				if result is False:
					if mandatory is True:
						self._stats["errors"] += 1
					else:
						self._stats["warnings"] += 1


	# properties

	def _has_warnings(self):
		return int(self._stats["warnings"]) > 0
	has_warnings = property(_has_warnings)

	def _has_errors(self):
		return int(self._stats["errors"]) > 0
	has_errors = property(_has_errors)

	def _get_checks_count(self):
		return int(self._stats["checks"])
	checks = property(_get_checks_count)

	def _get_warning_count(self):
		return int(self._stats["warnings"])
	warnings = property(_get_warning_count)

	def _get_error_count(self):
		return int(self._stats["errors"])
	errors = property(_get_error_count)


	# helper stuff

	def _colored(self, result, mandatory):
		return self._result_as_word(result, mandatory, colored = True)

	def _monochrome(self, result, mandatory):
		return self._result_as_word(result, mandatory, colored = False)

	def _result_as_word(self, result, mandatory, colored):
		if bool(result) is True:
			(color, word) = ("\033[1;32m", "enabled")
		elif bool(mandatory) is True:
			(color, word) = ("\033[1;31m", "required")
		else:
			(color, word) = ("\033[1;33m", "missing")

		if colored is True:
			return "%s%s%s" % (color, word, "\033[0;39m")
		else:
			return "%s" % word


	# getting the results

	def as_text(self, colored = True, fancy = True):
		""" Return the test results in text format.
		
		If `colored` is set, control sequences will be added so that the results
		will be shown in green, yellow or red color - suitable for printing on
		the console.
		
		If `fancy` is set, some nicer formatting will be applied to the text.
		"""

		rv = []
		if fancy is True:
			x = []
			y = []
			for section in self._sections:
				x.extend([ r[0] for r in self._results[section] ])
				y.extend([ self._monochrome(r[1], r[2]) for r in self._results[section] ])
			max_item_len = max( [ len(r) for r in x ] ) + 4
			max_head_len = max( [ len(r) for r in y ] ) + max_item_len + 2
			del r, x, y

			cf = self._config.filename.split("/")[-1]
			rv.append("".center(max_head_len, "="))
			rv.append((" %s " % cf).center(max_head_len, "="))
			rv.append("".center(max_head_len, "="))
		else:
			rv.append("=== %s ===" % self._config.filename)
		rv.append("")

		if colored is True:
			f = self._colored
		else:
			f = self._monochrome

		for section in self._sections:
			if fancy is True:
				h = (" %s " % section).center(max_head_len, "-")
			else:
				h = "--- %s ---" % section
			rv.append(h)

			for (description, result, mandatory) in self._results[section]:
				if fancy is True:
					d = ("%s " % description).ljust(max_item_len, ".")
				else:
					d = description
				rv.append("%s: %s" % (d, f(result, mandatory)))
			rv.append("")

		if fancy is True:
			rv.append("".center(max_head_len, "="))
			rv.append("%d checks: %d warnings, %d errors" % (
				self._stats["checks"],
				self._stats["warnings"], self._stats["errors"]
			))
			rv.append("")

		return "\n".join(rv)

	def as_json(self, flat = False):
		""" Return the test results in JSON format.
		
		By default, the results will be grouped more or less logically:
		
			{
			    "Control Groups": {
			        "Cgroup": "enabled",
			        "Cgroup clone_children flag": "enabled",
					...
			    },
			    "Misc": {
			        "File capabilities": "enabled",
			        "Macvlan": "enabled",
					...
			    },
				...
			}
		
		When `flat` is set, no grouping is applied:
		
			{
			    "Cgroup": "enabled",
			    "Cgroup clone_children flag": "enabled",
			    ...
			    "File capabilities": "enabled",
			    "Macvlan": "enabled",
				...
			}
		"""

		import json

		r = {}
		for section in self._sections:
			if flat is False:
				r[section] = {}
			for (description, result, mandatory) in self._results[section]:
				if flat is True:
					r[description] = self._monochrome(result, mandatory)
				else:
					r[section][description] = self._monochrome(result, mandatory)

		s = {
			"Checked file": self._config.filename, 
			"Performed checks": int(self._stats["checks"]),
			"Found warnings": int(self._stats["warnings"]),
			"Found errors": int(self._stats["errors"]),
		}
		if flat is True:
			r.update(s)
		else:
			r["Statistics"] = s
		del s

		return json.dumps(r, sort_keys = True, indent = 4)



def guestimate_config_filename():
	""" Look at the CONFIG environment variable and various paths, and return
	the name of the name that is hit first, or `None` if no config file is
	found.
	"""

	if os.getenv("CONFIG") is not None:
		return os.getenv("CONFIG")

	import platform
	running_kernel = platform.uname()[2]
	needles = [
		"/proc/config.gz",
		"/lib/modules/%s/build/.config" % running_kernel,
		"/boot/config-%s" % running_kernel,
	]
	for needle in needles:
		if os.path.isfile(needle) is True:
			return needle

	return None



def printerr(msg):
	sys.stderr.write("%s\n" % msg)



if __name__ == "__main__":
	parser = LxcCcArgumentParser()
	opts = parser.parse_args()

	if opts.show_help:
		parser.print_help()
		sys.exit(0)

	config_file = None
	if opts.config_file is not None:
		config_file = opts.config_file
	else:
		config_file = guestimate_config_filename()

	if config_file is None:
		printerr("ERROR: no kernel configuration found; see --help for options")
		sys.exit(1)
	elif os.path.isfile(config_file) is False:
		printerr("ERROR: kernel configuration '%s' not found" % config_file)
		sys.exit(1)

	cfg = KernelConfig(config_file)
	check = LxcConfigCheck(cfg)

	if opts.quiet is not True:
		if opts.output_json is True:
			print(check.as_json(flat = opts.flat_mode))
		else:
			print(check.as_text(colored = opts.colored_mode, fancy = opts.fancy_mode))
	else:
		if check.has_errors:
			sys.exit(1)

	sys.exit(0)
