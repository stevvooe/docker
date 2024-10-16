package stack

import (
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/net/context"

	"github.com/aanand/compose-file/loader"
	composetypes "github.com/aanand/compose-file/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/mount"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	servicecmd "github.com/docker/docker/cli/command/service"
	"github.com/docker/docker/opts"
	runconfigopts "github.com/docker/docker/runconfig/opts"
	"github.com/docker/go-connections/nat"
)

const (
	defaultNetworkDriver = "overlay"
)

type deployOptions struct {
	bundlefile       string
	composefile      string
	namespace        string
	sendRegistryAuth bool
}

func newDeployCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts deployOptions

	cmd := &cobra.Command{
		Use:     "deploy [OPTIONS] STACK",
		Aliases: []string{"up"},
		Short:   "Deploy a new stack or update an existing stack",
		Args:    cli.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.namespace = args[0]
			return runDeploy(dockerCli, opts)
		},
		Tags: map[string]string{"experimental": "", "version": "1.25"},
	}

	flags := cmd.Flags()
	addBundlefileFlag(&opts.bundlefile, flags)
	addComposefileFlag(&opts.composefile, flags)
	addRegistryAuthFlag(&opts.sendRegistryAuth, flags)
	return cmd
}

func runDeploy(dockerCli *command.DockerCli, opts deployOptions) error {
	switch {
	case opts.bundlefile == "" && opts.composefile == "":
		return fmt.Errorf("Please specify either a bundle file (with --bundle-file) or a Compose file (with --compose-file).")
	case opts.bundlefile != "" && opts.composefile != "":
		return fmt.Errorf("You cannot specify both a bundle file and a Compose file.")
	case opts.bundlefile != "":
		return deployBundle(dockerCli, opts)
	default:
		return deployCompose(dockerCli, opts)
	}
}

func deployCompose(dockerCli *command.DockerCli, opts deployOptions) error {
	configDetails, err := getConfigDetails(opts)
	if err != nil {
		return err
	}

	config, err := loader.Load(configDetails)
	if err != nil {
		if fpe, ok := err.(*loader.ForbiddenPropertiesError); ok {
			return fmt.Errorf("Compose file contains unsupported options:\n\n%s\n",
				propertyWarnings(fpe.Properties))
		}

		return err
	}

	unsupportedProperties := loader.GetUnsupportedProperties(configDetails)
	if len(unsupportedProperties) > 0 {
		fmt.Fprintf(dockerCli.Err(), "Ignoring unsupported options: %s\n\n",
			strings.Join(unsupportedProperties, ", "))
	}

	deprecatedProperties := loader.GetDeprecatedProperties(configDetails)
	if len(deprecatedProperties) > 0 {
		fmt.Fprintf(dockerCli.Err(), "Ignoring deprecated options:\n\n%s\n\n",
			propertyWarnings(deprecatedProperties))
	}

	ctx := context.Background()
	namespace := namespace{name: opts.namespace}

	networks := convertNetworks(namespace, config.Networks)
	if err := createNetworks(ctx, dockerCli, namespace, networks); err != nil {
		return err
	}
	services, err := convertServices(namespace, config)
	if err != nil {
		return err
	}
	return deployServices(ctx, dockerCli, services, namespace, opts.sendRegistryAuth)
}

func propertyWarnings(properties map[string]string) string {
	var msgs []string
	for name, description := range properties {
		msgs = append(msgs, fmt.Sprintf("%s: %s", name, description))
	}
	sort.Strings(msgs)
	return strings.Join(msgs, "\n\n")
}

func getConfigDetails(opts deployOptions) (composetypes.ConfigDetails, error) {
	var details composetypes.ConfigDetails
	var err error

	details.WorkingDir, err = os.Getwd()
	if err != nil {
		return details, err
	}

	configFile, err := getConfigFile(opts.composefile)
	if err != nil {
		return details, err
	}
	// TODO: support multiple files
	details.ConfigFiles = []composetypes.ConfigFile{*configFile}
	return details, nil
}

func getConfigFile(filename string) (*composetypes.ConfigFile, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	config, err := loader.ParseYAML(bytes)
	if err != nil {
		return nil, err
	}
	return &composetypes.ConfigFile{
		Filename: filename,
		Config:   config,
	}, nil
}

func convertNetworks(
	namespace namespace,
	networks map[string]composetypes.NetworkConfig,
) map[string]types.NetworkCreate {
	if networks == nil {
		networks = make(map[string]composetypes.NetworkConfig)
	}

	// TODO: only add default network if it's used
	networks["default"] = composetypes.NetworkConfig{}

	result := make(map[string]types.NetworkCreate)

	for internalName, network := range networks {
		if network.External.Name != "" {
			continue
		}

		createOpts := types.NetworkCreate{
			Labels:  getStackLabels(namespace.name, network.Labels),
			Driver:  network.Driver,
			Options: network.DriverOpts,
		}

		if network.Ipam.Driver != "" || len(network.Ipam.Config) > 0 {
			createOpts.IPAM = &networktypes.IPAM{}
		}

		if network.Ipam.Driver != "" {
			createOpts.IPAM.Driver = network.Ipam.Driver
		}
		for _, ipamConfig := range network.Ipam.Config {
			config := networktypes.IPAMConfig{
				Subnet: ipamConfig.Subnet,
			}
			createOpts.IPAM.Config = append(createOpts.IPAM.Config, config)
		}
		result[internalName] = createOpts
	}

	return result
}

func createNetworks(
	ctx context.Context,
	dockerCli *command.DockerCli,
	namespace namespace,
	networks map[string]types.NetworkCreate,
) error {
	client := dockerCli.Client()

	existingNetworks, err := getNetworks(ctx, client, namespace.name)
	if err != nil {
		return err
	}

	existingNetworkMap := make(map[string]types.NetworkResource)
	for _, network := range existingNetworks {
		existingNetworkMap[network.Name] = network
	}

	for internalName, createOpts := range networks {
		name := namespace.scope(internalName)
		if _, exists := existingNetworkMap[name]; exists {
			continue
		}

		if createOpts.Driver == "" {
			createOpts.Driver = defaultNetworkDriver
		}

		fmt.Fprintf(dockerCli.Out(), "Creating network %s\n", name)
		if _, err := client.NetworkCreate(ctx, name, createOpts); err != nil {
			return err
		}
	}

	return nil
}

func convertServiceNetworks(
	networks map[string]*composetypes.ServiceNetworkConfig,
	namespace namespace,
	name string,
) []swarm.NetworkAttachmentConfig {
	if len(networks) == 0 {
		return []swarm.NetworkAttachmentConfig{
			{
				Target:  namespace.scope("default"),
				Aliases: []string{name},
			},
		}
	}

	nets := []swarm.NetworkAttachmentConfig{}
	for networkName, network := range networks {
		nets = append(nets, swarm.NetworkAttachmentConfig{
			Target:  namespace.scope(networkName),
			Aliases: append(network.Aliases, name),
		})
	}
	return nets
}

func convertVolumes(
	serviceVolumes []string,
	stackVolumes map[string]composetypes.VolumeConfig,
	namespace namespace,
) ([]mount.Mount, error) {
	var mounts []mount.Mount

	for _, volumeSpec := range serviceVolumes {
		mount, err := convertVolumeToMount(volumeSpec, stackVolumes, namespace)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}
	return mounts, nil
}

func convertVolumeToMount(
	volumeSpec string,
	stackVolumes map[string]composetypes.VolumeConfig,
	namespace namespace,
) (mount.Mount, error) {
	var source, target string
	var mode []string

	// TODO: split Windows path mappings properly
	parts := strings.SplitN(volumeSpec, ":", 3)

	switch len(parts) {
	case 3:
		source = parts[0]
		target = parts[1]
		mode = strings.Split(parts[2], ",")
	case 2:
		source = parts[0]
		target = parts[1]
	case 1:
		target = parts[0]
	default:
		return mount.Mount{}, fmt.Errorf("invald volume: %s", volumeSpec)
	}

	// TODO: catch Windows paths here
	if strings.HasPrefix(source, "/") {
		return mount.Mount{
			Type:        mount.TypeBind,
			Source:      source,
			Target:      target,
			ReadOnly:    isReadOnly(mode),
			BindOptions: getBindOptions(mode),
		}, nil
	}

	stackVolume, exists := stackVolumes[source]
	if !exists {
		return mount.Mount{}, fmt.Errorf("undefined volume: %s", source)
	}

	var volumeOptions *mount.VolumeOptions
	if stackVolume.External.Name != "" {
		source = stackVolume.External.Name
	} else {
		volumeOptions = &mount.VolumeOptions{
			Labels: stackVolume.Labels,
			NoCopy: isNoCopy(mode),
		}

		if stackVolume.Driver != "" {
			volumeOptions.DriverConfig = &mount.Driver{
				Name:    stackVolume.Driver,
				Options: stackVolume.DriverOpts,
			}
		}
		source = namespace.scope(source)
	}
	return mount.Mount{
		Type:          mount.TypeVolume,
		Source:        source,
		Target:        target,
		ReadOnly:      isReadOnly(mode),
		VolumeOptions: volumeOptions,
	}, nil
}

func modeHas(mode []string, field string) bool {
	for _, item := range mode {
		if item == field {
			return true
		}
	}
	return false
}

func isReadOnly(mode []string) bool {
	return modeHas(mode, "ro")
}

func isNoCopy(mode []string) bool {
	return modeHas(mode, "nocopy")
}

func getBindOptions(mode []string) *mount.BindOptions {
	for _, item := range mode {
		if strings.Contains(item, "private") || strings.Contains(item, "shared") || strings.Contains(item, "slave") {
			return &mount.BindOptions{Propagation: mount.Propagation(item)}
		}
	}
	return nil
}

func deployServices(
	ctx context.Context,
	dockerCli *command.DockerCli,
	services map[string]swarm.ServiceSpec,
	namespace namespace,
	sendAuth bool,
) error {
	apiClient := dockerCli.Client()
	out := dockerCli.Out()

	existingServices, err := getServices(ctx, apiClient, namespace.name)
	if err != nil {
		return err
	}

	existingServiceMap := make(map[string]swarm.Service)
	for _, service := range existingServices {
		existingServiceMap[service.Spec.Name] = service
	}

	for internalName, serviceSpec := range services {
		name := namespace.scope(internalName)

		encodedAuth := ""
		if sendAuth {
			// Retrieve encoded auth token from the image reference
			image := serviceSpec.TaskTemplate.ContainerSpec.Image
			encodedAuth, err = command.RetrieveAuthTokenFromImage(ctx, dockerCli, image)
			if err != nil {
				return err
			}
		}

		if service, exists := existingServiceMap[name]; exists {
			fmt.Fprintf(out, "Updating service %s (id: %s)\n", name, service.ID)

			updateOpts := types.ServiceUpdateOptions{}
			if sendAuth {
				updateOpts.EncodedRegistryAuth = encodedAuth
			}
			response, err := apiClient.ServiceUpdate(
				ctx,
				service.ID,
				service.Version,
				serviceSpec,
				updateOpts,
			)
			if err != nil {
				return err
			}

			for _, warning := range response.Warnings {
				fmt.Fprintln(dockerCli.Err(), warning)
			}
		} else {
			fmt.Fprintf(out, "Creating service %s\n", name)

			createOpts := types.ServiceCreateOptions{}
			if sendAuth {
				createOpts.EncodedRegistryAuth = encodedAuth
			}
			if _, err := apiClient.ServiceCreate(ctx, serviceSpec, createOpts); err != nil {
				return err
			}
		}
	}

	return nil
}

func convertServices(
	namespace namespace,
	config *composetypes.Config,
) (map[string]swarm.ServiceSpec, error) {
	result := make(map[string]swarm.ServiceSpec)

	services := config.Services
	volumes := config.Volumes

	for _, service := range services {
		serviceSpec, err := convertService(namespace, service, volumes)
		if err != nil {
			return nil, err
		}
		result[service.Name] = serviceSpec
	}

	return result, nil
}

func convertService(
	namespace namespace,
	service composetypes.ServiceConfig,
	volumes map[string]composetypes.VolumeConfig,
) (swarm.ServiceSpec, error) {
	name := namespace.scope(service.Name)

	endpoint, err := convertEndpointSpec(service.Ports)
	if err != nil {
		return swarm.ServiceSpec{}, err
	}

	mode, err := convertDeployMode(service.Deploy.Mode, service.Deploy.Replicas)
	if err != nil {
		return swarm.ServiceSpec{}, err
	}

	mounts, err := convertVolumes(service.Volumes, volumes, namespace)
	if err != nil {
		// TODO: better error message (include service name)
		return swarm.ServiceSpec{}, err
	}

	resources, err := convertResources(service.Deploy.Resources)
	if err != nil {
		return swarm.ServiceSpec{}, err
	}

	restartPolicy, err := convertRestartPolicy(
		service.Restart, service.Deploy.RestartPolicy)
	if err != nil {
		return swarm.ServiceSpec{}, err
	}

	serviceSpec := swarm.ServiceSpec{
		Annotations: swarm.Annotations{
			Name:   name,
			Labels: getStackLabels(namespace.name, service.Deploy.Labels),
		},
		TaskTemplate: swarm.TaskSpec{
			ContainerSpec: swarm.ContainerSpec{
				Image:           service.Image,
				Command:         service.Entrypoint,
				Args:            service.Command,
				Hostname:        service.Hostname,
				Hosts:           convertExtraHosts(service.ExtraHosts),
				Env:             convertEnvironment(service.Environment),
				Labels:          getStackLabels(namespace.name, service.Labels),
				Dir:             service.WorkingDir,
				User:            service.User,
				Mounts:          mounts,
				StopGracePeriod: service.StopGracePeriod,
				TTY:             service.Tty,
				OpenStdin:       service.StdinOpen,
			},
			Resources:     resources,
			RestartPolicy: restartPolicy,
			Placement: &swarm.Placement{
				Constraints: service.Deploy.Placement.Constraints,
			},
		},
		EndpointSpec: endpoint,
		Mode:         mode,
		Networks:     convertServiceNetworks(service.Networks, namespace, service.Name),
		UpdateConfig: convertUpdateConfig(service.Deploy.UpdateConfig),
	}

	return serviceSpec, nil
}

func convertExtraHosts(extraHosts map[string]string) []string {
	hosts := []string{}
	for host, ip := range extraHosts {
		hosts = append(hosts, fmt.Sprintf("%s %s", host, ip))
	}
	return hosts
}

func convertRestartPolicy(restart string, source *composetypes.RestartPolicy) (*swarm.RestartPolicy, error) {
	// TODO: log if restart is being ignored
	if source == nil {
		policy, err := runconfigopts.ParseRestartPolicy(restart)
		if err != nil {
			return nil, err
		}
		// TODO: is this an accurate convertion?
		switch {
		case policy.IsNone():
			return nil, nil
		case policy.IsAlways(), policy.IsUnlessStopped():
			return &swarm.RestartPolicy{
				Condition: swarm.RestartPolicyConditionAny,
			}, nil
		case policy.IsOnFailure():
			attempts := uint64(policy.MaximumRetryCount)
			return &swarm.RestartPolicy{
				Condition:   swarm.RestartPolicyConditionOnFailure,
				MaxAttempts: &attempts,
			}, nil
		}
	}
	return &swarm.RestartPolicy{
		Condition:   swarm.RestartPolicyCondition(source.Condition),
		Delay:       source.Delay,
		MaxAttempts: source.MaxAttempts,
		Window:      source.Window,
	}, nil
}

func convertUpdateConfig(source *composetypes.UpdateConfig) *swarm.UpdateConfig {
	if source == nil {
		return nil
	}
	return &swarm.UpdateConfig{
		Parallelism:     source.Parallelism,
		Delay:           source.Delay,
		FailureAction:   source.FailureAction,
		Monitor:         source.Monitor,
		MaxFailureRatio: source.MaxFailureRatio,
	}
}

func convertResources(source composetypes.Resources) (*swarm.ResourceRequirements, error) {
	resources := &swarm.ResourceRequirements{}
	if source.Limits != nil {
		cpus, err := opts.ParseCPUs(source.Limits.NanoCPUs)
		if err != nil {
			return nil, err
		}
		resources.Limits = &swarm.Resources{
			NanoCPUs:    cpus,
			MemoryBytes: int64(source.Limits.MemoryBytes),
		}
	}
	if source.Reservations != nil {
		cpus, err := opts.ParseCPUs(source.Reservations.NanoCPUs)
		if err != nil {
			return nil, err
		}
		resources.Reservations = &swarm.Resources{
			NanoCPUs:    cpus,
			MemoryBytes: int64(source.Reservations.MemoryBytes),
		}
	}
	return resources, nil
}

func convertEndpointSpec(source []string) (*swarm.EndpointSpec, error) {
	portConfigs := []swarm.PortConfig{}
	ports, portBindings, err := nat.ParsePortSpecs(source)
	if err != nil {
		return nil, err
	}

	for port := range ports {
		portConfigs = append(
			portConfigs,
			servicecmd.ConvertPortToPortConfig(port, portBindings)...)
	}

	return &swarm.EndpointSpec{Ports: portConfigs}, nil
}

func convertEnvironment(source map[string]string) []string {
	var output []string

	for name, value := range source {
		output = append(output, fmt.Sprintf("%s=%s", name, value))
	}

	return output
}

func convertDeployMode(mode string, replicas *uint64) (swarm.ServiceMode, error) {
	serviceMode := swarm.ServiceMode{}

	switch mode {
	case "global":
		if replicas != nil {
			return serviceMode, fmt.Errorf("replicas can only be used with replicated mode")
		}
		serviceMode.Global = &swarm.GlobalService{}
	case "replicated", "":
		serviceMode.Replicated = &swarm.ReplicatedService{Replicas: replicas}
	default:
		return serviceMode, fmt.Errorf("Unknown mode: %s", mode)
	}
	return serviceMode, nil
}
