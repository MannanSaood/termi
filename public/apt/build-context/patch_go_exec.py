#!/usr/bin/env python3
"""Enable GH's Go subprocesses through Termux's existing libc exec adapter.

Go normally invokes the execve syscall directly, bypassing LD_PRELOAD. On
Android with explicit linker mode, first exec the system shell; its libc exec
then applies the already-installed Termux exec policy. Arguments stay positional
parameters, never shell source. CGO remains enabled; no runtime argv surgery.
"""
from pathlib import Path
import sys

path = Path(sys.argv[1]) / "src/os/exec_posix.go"
source = path.read_text()
marker = "// Termi: use the installed libc exec adapter for Android children."
old = "func startProcess(name string, argv []string, attr *ProcAttr) (p *Process, err error) {\n"
new = old + r'''	// Termi: use the installed libc exec adapter for Android children.
	// Positional arguments prevent shell interpretation of executable/arguments.
	// GH uses ordinary argv[0]; custom argv[0] is not preserved by this adapter.
	if runtime.GOOS == "android" && Getenv("TERMUX_EXEC__SYSTEM_LINKER_EXEC__MODE") == "enable" && len(argv) > 0 {
		args := []string{"sh", "-c", "exec \"$@\"", "termi-go-exec", name}
		args = append(args, argv[1:]...)
		name = "/system/bin/sh"
		argv = args
	}
'''
if marker not in source:
    if source.count(old) != 1:
        raise ValueError("Go startProcess changed; review required")
    path.write_text(source.replace(old, new))
