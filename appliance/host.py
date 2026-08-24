"""Host adapter: argv-only subprocess execution, never shell=True."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import pwd
import grp
import shutil
import stat
import subprocess
import sys
from typing import Mapping, Protocol

from appliance.detect import Platform, detect_platform
from appliance.packages import package_install_argv, package_query_available_argv, package_query_installed_argv


class HostError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Host(Protocol):
    def detect_platform(self) -> Platform: ...
    def geteuid(self) -> int: ...
    def exists(self, path: Path) -> bool: ...
    def is_file(self, path: Path) -> bool: ...
    def read_text(self, path: Path) -> str: ...
    def write_file(
        self,
        path: Path,
        content: str,
        *,
        mode: int,
        owner: str,
        group: str,
        overwrite: bool = True,
    ) -> None: ...
    def mkdir(
        self,
        path: Path,
        *,
        mode: int,
        owner: str,
        group: str,
    ) -> None: ...
    def chmod(self, path: Path, mode: int) -> None: ...
    def chown(self, path: Path, owner: str, group: str) -> None: ...
    def unlink(self, path: Path) -> None: ...
    def file_mode(self, path: Path) -> int: ...
    def file_owner(self, path: Path) -> str: ...
    def file_group(self, path: Path) -> str: ...
    def has_setuid(self, path: Path) -> bool: ...
    def user_exists(self, name: str) -> bool: ...
    def group_exists(self, name: str) -> bool: ...
    def user_in_group(self, user: str, group: str) -> bool: ...
    def create_system_user(
        self,
        name: str,
        *,
        home: Path,
        group: str,
    ) -> None: ...
    def ensure_group(self, name: str) -> None: ...
    def add_user_to_group(self, user: str, group: str) -> None: ...
    def package_installed(self, name: str) -> bool: ...
    def package_available(self, name: str) -> bool: ...
    def install_packages(self, names: tuple[str, ...]) -> CommandResult: ...
    def getcap(self, path: Path) -> str: ...
    def setcap(self, path: Path, capabilities: str) -> None: ...
    def which(self, name: str) -> str | None: ...
    def run(
        self,
        argv: list[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        user: str | None = None,
    ) -> CommandResult: ...
    def systemctl_available(self) -> bool: ...


def _require_argv(argv: list[str]) -> tuple[str, ...]:
    if not argv or not argv[0]:
        raise HostError("refusing empty command")
    if any(not isinstance(item, str) for item in argv):
        raise HostError("command arguments must be strings")
    return tuple(argv)


class RealHost:
    def __init__(self) -> None:
        self._platform: Platform | None = None

    def detect_platform(self) -> Platform:
        if self._platform is None:
            self._platform = detect_platform()
        return self._platform

    def _package_manager(self) -> str:
        return self.detect_platform().package_manager

    def geteuid(self) -> int:
        return os.geteuid()

    def exists(self, path: Path) -> bool:
        return path.exists()

    def is_file(self, path: Path) -> bool:
        return path.is_file()

    def read_text(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def write_file(
        self,
        path: Path,
        content: str,
        *,
        mode: int,
        owner: str,
        group: str,
        overwrite: bool = True,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not overwrite:
            self.chmod(path, mode)
            self.chown(path, owner, group)
            return
        path.write_text(content, encoding="utf-8")
        self.chmod(path, mode)
        self.chown(path, owner, group)

    def mkdir(
        self,
        path: Path,
        *,
        mode: int,
        owner: str,
        group: str,
    ) -> None:
        path.mkdir(mode=mode, parents=True, exist_ok=True)
        self.chmod(path, mode)
        self.chown(path, owner, group)

    def chmod(self, path: Path, mode: int) -> None:
        os.chmod(path, mode)

    def chown(self, path: Path, owner: str, group: str) -> None:
        os.chown(path, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)

    def unlink(self, path: Path) -> None:
        if path.exists():
            path.unlink()

    def file_mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def file_owner(self, path: Path) -> str:
        return pwd.getpwuid(path.stat().st_uid).pw_name

    def file_group(self, path: Path) -> str:
        return grp.getgrgid(path.stat().st_gid).gr_name

    def has_setuid(self, path: Path) -> bool:
        return bool(path.stat().st_mode & stat.S_ISUID)

    def user_exists(self, name: str) -> bool:
        try:
            pwd.getpwnam(name)
            return True
        except KeyError:
            return False

    def group_exists(self, name: str) -> bool:
        try:
            grp.getgrnam(name)
            return True
        except KeyError:
            return False

    def user_in_group(self, user: str, group: str) -> bool:
        if not self.user_exists(user) or not self.group_exists(group):
            return False
        record = grp.getgrnam(group)
        if pwd.getpwnam(user).pw_gid == record.gr_gid:
            return True
        return user in record.gr_mem

    def create_system_user(
        self,
        name: str,
        *,
        home: Path,
        group: str,
    ) -> None:
        if self.user_exists(name):
            return
        self.ensure_group(group)
        argv = [
            "useradd",
            "--system",
            "--home-dir",
            str(home),
            "--create-home",
            "--shell",
            self._nologin(),
            "--gid",
            group,
            "--comment",
            "WireScope service",
            name,
        ]
        result = self.run(argv)
        if not result.ok:
            raise HostError(
                f"useradd failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    def ensure_group(self, name: str) -> None:
        if self.group_exists(name):
            return
        result = self.run(["groupadd", "--system", name])
        if not result.ok:
            raise HostError(
                f"groupadd failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    def add_user_to_group(self, user: str, group: str) -> None:
        if self.user_in_group(user, group):
            return
        result = self.run(["usermod", "-aG", group, user])
        if not result.ok:
            raise HostError(
                f"usermod failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    def _nologin(self) -> str:
        for candidate in ("/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin"):
            if Path(candidate).is_file():
                return candidate
        return "/usr/sbin/nologin"

    def package_installed(self, name: str) -> bool:
        manager = self._package_manager()
        result = self.run(package_query_installed_argv(manager, name))
        if manager == "apt":
            return result.ok and "install ok installed" in result.stdout
        return result.ok

    def package_available(self, name: str) -> bool:
        manager = self._package_manager()
        result = self.run(package_query_available_argv(manager, name))
        if manager == "zypper":
            return result.ok and name in result.stdout
        return result.ok

    def install_packages(self, names: tuple[str, ...]) -> CommandResult:
        manager = self._package_manager()
        argv = package_install_argv(manager, names)
        env = dict(os.environ)
        if manager == "apt":
            env["DEBIAN_FRONTEND"] = "noninteractive"
        return self.run(argv, env=env)

    def _capability_binary(self, name: str) -> str:
        found = self.which(name)
        if found:
            return found
        for candidate in (Path("/usr/sbin") / name, Path("/sbin") / name):
            if candidate.is_file():
                return str(candidate)
        return name

    def getcap(self, path: Path) -> str:
        result = self.run([self._capability_binary("getcap"), str(path)])
        if not result.ok:
            return ""
        line = result.stdout.strip()
        if " " in line:
            return line.split(" ", 1)[1].strip()
        if "cap_" in line:
            return line[line.find("cap_") :]
        return line

    def setcap(self, path: Path, capabilities: str) -> None:
        result = self.run(
            [self._capability_binary("setcap"), capabilities, str(path)]
        )
        if not result.ok:
            raise HostError(
                f"setcap failed: {result.stderr.strip() or result.stdout.strip()}"
            )

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(
        self,
        argv: list[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        user: str | None = None,
    ) -> CommandResult:
        command = _require_argv(argv)
        kwargs: dict[str, object] = {
            "args": list(command),
            "cwd": cwd,
            "env": dict(env) if env is not None else None,
            "stdin": subprocess.DEVNULL,
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "shell": False,
        }
        if user is not None:
            kwargs["user"] = user
        completed = subprocess.run(**kwargs)
        return CommandResult(
            argv=command,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def systemctl_available(self) -> bool:
        return Path("/run/systemd/system").exists() and self.which("systemctl") is not None


@dataclass
class MemoryFile:
    content: str = ""
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"
    directory: bool = False
    capabilities: str = ""
    setuid: bool = False


@dataclass
class MemoryHost:
    """In-memory host used by installer tests. Never touches the real OS."""

    platform: Platform
    euid: int = 0
    files: dict[str, MemoryFile] = field(default_factory=dict)
    users: dict[str, str] = field(default_factory=lambda: {"root": "root"})
    groups: dict[str, set[str]] = field(
        default_factory=lambda: {"root": {"root"}, "wireshark": set()}
    )
    packages: set[str] = field(default_factory=set)
    available_packages: set[str] | None = None
    commands: list[tuple[str, ...]] = field(default_factory=list)
    systemctl: bool = True
    binaries: dict[str, str] = field(default_factory=dict)
    command_results: dict[str, CommandResult] = field(default_factory=dict)

    def detect_platform(self) -> Platform:
        return self.platform

    def geteuid(self) -> int:
        return self.euid

    def _key(self, path: Path) -> str:
        return str(path)

    def exists(self, path: Path) -> bool:
        return self._key(path) in self.files

    def is_file(self, path: Path) -> bool:
        record = self.files.get(self._key(path))
        return record is not None and not record.directory

    def read_text(self, path: Path) -> str:
        record = self.files[self._key(path)]
        return record.content

    def write_file(
        self,
        path: Path,
        content: str,
        *,
        mode: int,
        owner: str,
        group: str,
        overwrite: bool = True,
    ) -> None:
        key = self._key(path)
        if key in self.files and not overwrite:
            record = self.files[key]
            record.mode = mode
            record.owner = owner
            record.group = group
            return
        self.files[key] = MemoryFile(
            content=content,
            mode=mode,
            owner=owner,
            group=group,
        )

    def mkdir(
        self,
        path: Path,
        *,
        mode: int,
        owner: str,
        group: str,
    ) -> None:
        self.files[self._key(path)] = MemoryFile(
            content="",
            mode=mode,
            owner=owner,
            group=group,
            directory=True,
        )

    def chmod(self, path: Path, mode: int) -> None:
        self.files[self._key(path)].mode = mode

    def chown(self, path: Path, owner: str, group: str) -> None:
        record = self.files[self._key(path)]
        record.owner = owner
        record.group = group

    def unlink(self, path: Path) -> None:
        self.files.pop(self._key(path), None)

    def file_mode(self, path: Path) -> int:
        return self.files[self._key(path)].mode

    def file_owner(self, path: Path) -> str:
        return self.files[self._key(path)].owner

    def file_group(self, path: Path) -> str:
        return self.files[self._key(path)].group

    def has_setuid(self, path: Path) -> bool:
        return self.files[self._key(path)].setuid

    def user_exists(self, name: str) -> bool:
        return name in self.users

    def group_exists(self, name: str) -> bool:
        return name in self.groups

    def user_in_group(self, user: str, group: str) -> bool:
        return user in self.groups.get(group, set()) or self.users.get(user) == group

    def create_system_user(
        self,
        name: str,
        *,
        home: Path,
        group: str,
    ) -> None:
        self.ensure_group(group)
        if name in self.users:
            return
        self.users[name] = group
        self.groups.setdefault(group, set()).add(name)
        self.mkdir(home, mode=0o750, owner=name, group=group)
        self.commands.append(("useradd", name))

    def ensure_group(self, name: str) -> None:
        self.groups.setdefault(name, set())

    def add_user_to_group(self, user: str, group: str) -> None:
        self.ensure_group(group)
        self.groups[group].add(user)
        self.commands.append(("usermod", "-aG", group, user))

    def package_installed(self, name: str) -> bool:
        return name in self.packages

    def package_available(self, name: str) -> bool:
        if self.available_packages is None:
            return True
        return name in self.available_packages

    def install_packages(self, names: tuple[str, ...]) -> CommandResult:
        self.packages.update(names)
        argv = tuple(package_install_argv(self.platform.package_manager, names))
        self.commands.append(argv)
        return CommandResult(argv=argv, returncode=0)

    def getcap(self, path: Path) -> str:
        record = self.files.get(self._key(path))
        return record.capabilities if record else ""

    def setcap(self, path: Path, capabilities: str) -> None:
        self.files[self._key(path)].capabilities = capabilities
        self.files[self._key(path)].setuid = False
        self.commands.append(("setcap", capabilities, str(path)))

    def which(self, name: str) -> str | None:
        if name in self.binaries:
            return self.binaries[name]
        if name == "python3":
            return sys.executable
        return f"/usr/bin/{name}" if name in {"getcap", "setcap", "systemctl"} else None

    def run(
        self,
        argv: list[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        user: str | None = None,
    ) -> CommandResult:
        command = _require_argv(argv)
        self.commands.append(command)
        preset = self.command_results.get(command[0])
        if preset is not None:
            return CommandResult(
                argv=command,
                returncode=preset.returncode,
                stdout=preset.stdout,
                stderr=preset.stderr,
            )
        if "bootstrap-admin" in command:
            return CommandResult(argv=command, returncode=0, stdout="auditor\n")
        if "-m" in command and "venv" in command:
            venv = Path(command[-1])
            self.mkdir(venv / "bin", mode=0o755, owner="root", group="root")
            self.write_file(
                venv / "bin" / "python",
                "python",
                mode=0o755,
                owner="root",
                group="root",
            )
            self.write_file(
                venv / "bin" / "pip",
                "pip",
                mode=0o755,
                owner="root",
                group="root",
            )
            self.write_file(
                venv / "bin" / "alembic",
                "alembic",
                mode=0o755,
                owner="root",
                group="root",
            )
        return CommandResult(argv=command, returncode=0)

    def systemctl_available(self) -> bool:
        return self.systemctl


def debian_amd64_platform() -> Platform:
    return Platform(
        family="debian",
        package_manager="apt",
        distro_id="debian",
        version_id="13",
        pretty_name="Debian GNU/Linux 13 (trixie)",
        arch="amd64",
        machine="x86_64",
        raspberry_pi=False,
    )


def fedora_amd64_platform() -> Platform:
    return Platform(
        family="rhel",
        package_manager="dnf",
        distro_id="fedora",
        version_id="41",
        pretty_name="Fedora Linux 41",
        arch="amd64",
        machine="x86_64",
        raspberry_pi=False,
    )


def opensuse_amd64_platform() -> Platform:
    return Platform(
        family="suse",
        package_manager="zypper",
        distro_id="opensuse-leap",
        version_id="15.6",
        pretty_name="openSUSE Leap 15.6",
        arch="amd64",
        machine="x86_64",
        raspberry_pi=False,
    )
