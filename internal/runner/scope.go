package runner

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	systemdUnitPrefix = "forcefield-agent-"
	systemdUnitSuffix = ".service"
)

// BuildSystemdScope wraps command in a transient user service. Despite the
// historical name, this deliberately creates a service rather than a scope:
// systemd owns the process tree from exec through teardown and applies the
// resource policy before starting the sandbox command.
func BuildSystemdScope(unit string, resources Resources, command CommandSpec, environment []string, terminal bool) (CommandSpec, error) {
	if !validSystemdUnit(unit) {
		return CommandSpec{}, invalidSystemdCommand("unit name is unsafe")
	}
	if err := validateResources(resources); err != nil {
		return CommandSpec{}, invalidSystemdCommand("resources are unsafe")
	}
	if !validHostCommand(command) {
		return CommandSpec{}, invalidSystemdCommand("sandbox command is unsafe")
	}

	systemdRun, err := findExecutable("systemd-run")
	if err != nil {
		return CommandSpec{}, invalidSystemdCommand("systemd-run executable is unavailable")
	}
	clientEnvironment, err := systemdClientEnvironment(environment)
	if err != nil {
		return CommandSpec{}, err
	}

	args := []string{
		"--user",
		"--quiet",
		"--collect",
		"--wait",
		"--service-type=exec",
		"--unit=" + unit,
		"--property=MemoryMax=" + strconv.FormatUint(resources.MemoryMaxBytes, 10),
		"--property=MemorySwapMax=0",
		"--property=TasksMax=" + strconv.FormatUint(resources.TasksMax, 10),
		"--property=CPUQuota=" + strconv.FormatUint(resources.CPUQuotaPercent, 10) + "%",
		"--property=RuntimeMaxSec=" + strconv.FormatInt(int64((resources.WallTime.Value()+time.Second-1)/time.Second), 10) + "s",
		"--property=TimeoutStopSec=5s",
		"--property=SendSIGKILL=yes",
		"--property=LimitNOFILE=1024",
		"--property=KillMode=control-group",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateDevices=yes",
	}
	if terminal {
		// A Hive spawn is attached to a tmux PTY. systemd cannot directly inherit
		// that descriptor into a transient service, so ask it to allocate and
		// bridge a subordinate PTY; otherwise agent TUIs observe ordinary pipes.
		args = append(args, "--pty")
	} else {
		args = append(args, "--pipe")
	}
	args = append(args, "--", command.Path)
	args = append(args, command.Args...)

	return CommandSpec{Path: systemdRun, Args: args, Env: clientEnvironment}, nil
}

// SystemdMainPIDCommand queries the host PID that systemd assigned to the
// transient sandbox service. Callers may treat a missing/zero value as a
// short-lived unit race; teardown authority is the recorded unit name.
func SystemdMainPIDCommand(unit string, environment []string) (CommandSpec, error) {
	if !validSystemdUnit(unit) {
		return CommandSpec{}, invalidSystemdCommand("unit name is unsafe")
	}
	systemctl, err := findExecutable("systemctl")
	if err != nil {
		return CommandSpec{}, invalidSystemdCommand("systemctl executable is unavailable")
	}
	clientEnvironment, err := systemdClientEnvironment(environment)
	if err != nil {
		return CommandSpec{}, err
	}
	return CommandSpec{
		Path: systemctl,
		Args: []string{"--user", "show", "--property=MainPID", "--value", unit},
		Env:  clientEnvironment,
	}, nil
}

// SystemdStopCommand constructs the trusted teardown command for a runner
// service. It uses the same narrow client environment as BuildSystemdScope.
func SystemdStopCommand(unit string, environment []string) (CommandSpec, error) {
	if !validSystemdUnit(unit) {
		return CommandSpec{}, invalidSystemdCommand("unit name is unsafe")
	}
	systemctl, err := findExecutable("systemctl")
	if err != nil {
		return CommandSpec{}, invalidSystemdCommand("systemctl executable is unavailable")
	}
	clientEnvironment, err := systemdClientEnvironment(environment)
	if err != nil {
		return CommandSpec{}, err
	}
	return CommandSpec{
		Path: systemctl,
		Args: []string{"--user", "stop", unit},
		Env:  clientEnvironment,
	}, nil
}

func validSystemdUnit(unit string) bool {
	if len(unit) > 255 || !strings.HasPrefix(unit, systemdUnitPrefix) || !strings.HasSuffix(unit, systemdUnitSuffix) {
		return false
	}
	identity := strings.TrimSuffix(strings.TrimPrefix(unit, systemdUnitPrefix), systemdUnitSuffix)
	return validIdentifier(identity)
}

func validHostCommand(command CommandSpec) bool {
	if command.Path == "" || !filepath.IsAbs(command.Path) || filepath.Clean(command.Path) != command.Path ||
		command.Path == string(filepath.Separator) || strings.IndexByte(command.Path, 0) >= 0 {
		return false
	}
	for _, argument := range command.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return false
		}
	}
	return true
}

// systemdClientEnvironment keeps only variables needed to find the current
// user's service manager. In particular, PATH and credentials never reach the
// systemd client. The manager's own environment is outside this process; the
// bubblewrap command independently uses --clearenv before entering the
// sandbox.
func systemdClientEnvironment(environment []string) ([]string, error) {
	values := make(map[string]string, 2)
	seen := make(map[string]struct{}, len(environment))
	for _, item := range environment {
		name, value, ok := strings.Cut(item, "=")
		if !ok || !validEnvironmentName(name) || strings.IndexByte(value, 0) >= 0 {
			return nil, invalidSystemdCommand("client environment is malformed")
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, invalidSystemdCommand("client environment contains duplicate names")
		}
		seen[name] = struct{}{}
		if name == "XDG_RUNTIME_DIR" || name == "DBUS_SESSION_BUS_ADDRESS" {
			values[name] = value
		}
	}

	runtimeDirectory := values["XDG_RUNTIME_DIR"]
	if runtimeDirectory != "" && !validRuntimeDirectory(runtimeDirectory) {
		return nil, invalidSystemdCommand("XDG_RUNTIME_DIR is unsafe")
	}
	busAddress := values["DBUS_SESSION_BUS_ADDRESS"]
	if busAddress != "" && !validSessionBusAddress(busAddress, runtimeDirectory) {
		return nil, invalidSystemdCommand("DBUS_SESSION_BUS_ADDRESS is unsafe")
	}

	result := make([]string, 0, 2)
	if runtimeDirectory != "" {
		result = append(result, "XDG_RUNTIME_DIR="+runtimeDirectory)
	}
	if busAddress != "" {
		result = append(result, "DBUS_SESSION_BUS_ADDRESS="+busAddress)
	}
	return result, nil
}

func validRuntimeDirectory(value string) bool {
	return len(value) <= 4096 && value != string(filepath.Separator) && filepath.IsAbs(value) &&
		filepath.Clean(value) == value && !containsControl(value)
}

func validSessionBusAddress(value, runtimeDirectory string) bool {
	const prefix = "unix:path="
	if len(value) > 8192 || !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, ",;") || containsControl(value) {
		return false
	}
	busPath := strings.TrimPrefix(value, prefix)
	if busPath == "" || !filepath.IsAbs(busPath) || filepath.Clean(busPath) != busPath {
		return false
	}
	return runtimeDirectory == "" || hostPathWithin(busPath, runtimeDirectory)
}

func containsControl(value string) bool {
	for _, current := range value {
		if current < 0x20 || current == 0x7f {
			return true
		}
	}
	return false
}

func invalidSystemdCommand(reason string) error {
	return fmt.Errorf("runner: invalid systemd command: %s", reason)
}
