// +build windows

package windows

// Note this is alpha code for the bring up of containers on Windows.

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/execdriver"
	"github.com/microsoft/hcsshim"
)

type layer struct {
	ID   string
	Path string
}

type defConfig struct {
	DefFile string
}

type networkConnection struct {
	NetworkName string
	EnableNat   bool
}
type networkSettings struct {
	MacAddress string
}

type device struct {
	DeviceType string
	Connection interface{}
	Settings   interface{}
}

type containerInit struct {
	SystemType              string
	Name                    string
	Owner                   string
	IsDummy                 bool
	VolumePath              string
	Devices                 []device
	IgnoreFlushesDuringBoot bool
	LayerFolderPath         string
	Layers                  []layer
}

// Run implements the exec driver Driver interface
func (d *Driver) Run(c *execdriver.Command, pipes *execdriver.Pipes, startCallback execdriver.StartCallback) (execdriver.ExitStatus, error) {

	var (
		term execdriver.Terminal
		err  error
	)

	// Make sure the client isn't asking for options which aren't supported
	err = checkSupportedOptions(c)
	if err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	cu := &containerInit{
		SystemType:              "Container",
		Name:                    c.ID,
		Owner:                   "docker",
		IsDummy:                 dummyMode,
		VolumePath:              c.Rootfs,
		IgnoreFlushesDuringBoot: c.FirstStart,
		LayerFolderPath:         c.LayerFolder,
	}

	for i := 0; i < len(c.LayerPaths); i++ {
		_, filename := filepath.Split(c.LayerPaths[i])
		g, err := hcsshim.NameToGuid(filename)
		if err != nil {
			return execdriver.ExitStatus{ExitCode: -1}, err
		}
		cu.Layers = append(cu.Layers, layer{
			ID:   g.ToString(),
			Path: c.LayerPaths[i],
		})
	}

	if c.Network.Interface != nil {
		dev := device{
			DeviceType: "Network",
			Connection: &networkConnection{
				NetworkName: c.Network.Interface.Bridge,
				EnableNat:   false,
			},
		}

		if c.Network.Interface.MacAddress != "" {
			windowsStyleMAC := strings.Replace(
				c.Network.Interface.MacAddress, ":", "-", -1)
			dev.Settings = networkSettings{
				MacAddress: windowsStyleMAC,
			}
		}

		logrus.Debugf("Virtual switch '%s', mac='%s'", c.Network.Interface.Bridge, c.Network.Interface.MacAddress)

		cu.Devices = append(cu.Devices, dev)
	} else {
		logrus.Debugln("No network interface")
	}

	configurationb, err := json.Marshal(cu)
	if err != nil {
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	configuration := string(configurationb)

	err = hcsshim.CreateComputeSystem(c.ID, configuration)
	if err != nil {
		logrus.Debugln("Failed to create temporary container ", err)
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	// Start the container
	logrus.Debugln("Starting container ", c.ID)
	err = hcsshim.StartComputeSystem(c.ID)
	if err != nil {
		logrus.Errorf("Failed to start compute system: %s", err)
		return execdriver.ExitStatus{ExitCode: -1}, err
	}
	defer func() {
		// Stop the container

		if terminateMode {
			logrus.Debugf("Terminating container %s", c.ID)
			if err := hcsshim.TerminateComputeSystem(c.ID); err != nil {
				// IMPORTANT: Don't fail if fails to change state. It could already
				// have been stopped through kill().
				// Otherwise, the docker daemon will hang in job wait()
				logrus.Warnf("Ignoring error from TerminateComputeSystem %s", err)
			}
		} else {
			logrus.Debugf("Shutting down container %s", c.ID)
			if err := hcsshim.ShutdownComputeSystem(c.ID); err != nil {
				// IMPORTANT: Don't fail if fails to change state. It could already
				// have been stopped through kill().
				// Otherwise, the docker daemon will hang in job wait()
				logrus.Warnf("Ignoring error from ShutdownComputeSystem %s", err)
			}
		}
	}()

	createProcessParms := hcsshim.CreateProcessParams{
		EmulateConsole:   c.ProcessConfig.Tty,
		WorkingDirectory: c.WorkingDir,
		ConsoleSize:      c.ProcessConfig.ConsoleSize,
	}

	// Configure the environment for the process
	createProcessParms.Environment = setupEnvironmentVariables(c.ProcessConfig.Env)

	// This should get caught earlier, but just in case - validate that we
	// have something to run
	if c.ProcessConfig.Entrypoint == "" {
		err = errors.New("No entrypoint specified")
		logrus.Error(err)
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	// Build the command line of the process
	createProcessParms.CommandLine = c.ProcessConfig.Entrypoint
	for _, arg := range c.ProcessConfig.Arguments {
		logrus.Debugln("appending ", arg)
		createProcessParms.CommandLine += " " + arg
	}
	logrus.Debugf("CommandLine: %s", createProcessParms.CommandLine)

	// Start the command running in the container.
	pid, stdin, stdout, stderr, err := hcsshim.CreateProcessInComputeSystem(c.ID, pipes.Stdin != nil, true, !c.ProcessConfig.Tty, createProcessParms)
	if err != nil {
		logrus.Errorf("CreateProcessInComputeSystem() failed %s", err)
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	// Now that the process has been launched, begin copying data to and from the named pipes for the std handles.
	if stdin != nil {
		stdinCopy(stdin, pipes.Stdin)
	}
	if stdout != nil {
		stdouterrCopy(stdout, "stdout", pipes.Stdout)
	}
	if stderr != nil {
		stdouterrCopy(stderr, "stderr", pipes.Stderr)
	}

	//Save the PID as we'll need this in Kill()
	logrus.Debugf("PID %d", pid)
	c.ContainerPid = int(pid)

	if c.ProcessConfig.Tty {
		term = NewTtyConsole(c.ID, pid)
	} else {
		term = NewStdConsole()
	}
	c.ProcessConfig.Terminal = term

	// Maintain our list of active containers. We'll need this later for exec
	// and other commands.
	d.Lock()
	d.activeContainers[c.ID] = &activeContainer{
		command: c,
	}
	d.Unlock()

	// Invoke the start callback
	if startCallback != nil {
		startCallback(&c.ProcessConfig, int(pid))
	}

	var exitCode int32
	exitCode, err = hcsshim.WaitForProcessInComputeSystem(c.ID, pid)
	if err != nil {
		logrus.Errorf("Failed to WaitForProcessInComputeSystem %s", err)
		return execdriver.ExitStatus{ExitCode: -1}, err
	}

	logrus.Debugf("Exiting Run() exitCode %d id=%s", exitCode, c.ID)
	return execdriver.ExitStatus{ExitCode: int(exitCode)}, nil
}
