package openforked

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rancher/machine/libmachine/drivers"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/utils/openstack/clientconfig"
)

const (
	errorMandatoryEnvOrOption   string = "%s must be specified either using the environment variable %s or the CLI option %s"
	errorMandatoryOption        string = "%s must be specified using the CLI option %s"
	errorExclusiveOptions       string = "either %s or %s must be specified, not both"
	errorBothOptions            string = "both %s and %s must be specified"
	errorWrongEndpointType      string = "endpoint type must be 'publicURL', 'adminURL' or 'internalURL'"
	errorUnknownFlavorName      string = "unable to find flavor named %s"
	errorUnknownImageName       string = "unable to find image named %s"
	errorUnknownServerGroupName string = "unable to find server group named %s"
	errorUnknownNetworkName     string = "unable to find network named %s"
	errorUnknownTenantName      string = "unable to find tenant named %s"

	defaultSSHUser       = "root"
	defaultSSHPort       = 22
	defaultActiveTimeout = 200
)

type Driver struct {
	*drivers.BaseDriver
	AuthUrl                     string
	ActiveTimeout               int
	Insecure                    bool
	CaCert                      string
	DomainId                    string
	DomainName                  string
	UserId                      string
	Username                    string
	Password                    string
	TenantName                  string
	TenantId                    string
	TenantDomainName            string
	TenantDomainId              string
	UserDomainName              string
	UserDomainId                string
	ApplicationCredentialId     string
	ApplicationCredentialName   string
	ApplicationCredentialSecret string
	Region                      string
	AvailabilityZone            string
	EndpointType                string
	MachineId                   string
	FlavorName                  string
	FlavorId                    string
	ImageName                   string
	ImageId                     string
	ServerGroupName             string
	ServerGroupId               string
	KeyPairName                 string
	NetworkNames                []string
	NetworkIds                  []string
	UserData                    []byte
	PrivateKeyFile              string
	SecurityGroups              []string
	FloatingIpPool              string
	ComputeNetwork              bool
	FloatingIpPoolId            string
	IpVersion                   int
	ConfigDrive                 bool
	BootFromVolume              bool
	VolumeName                  string
	VolumeDevicePath            string
	VolumeId                    string
	VolumeType                  string
	VolumeSize                  int
	client                      Client
	// ExistingKey keeps track of whether the key was created by us or we used an existing one. If an existing one was used, we shouldn't delete it when the machine is deleted.
	ExistingKey bool
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "OF_AUTH_URL",
			Name:   "openforked-auth-url",
			Usage:  "OpenStack authentication URL",
			Value:  "",
		},
		mcnflag.BoolFlag{
			EnvVar: "OF_INSECURE",
			Name:   "openforked-insecure",
			Usage:  "Disable TLS credential checking.",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_CACERT",
			Name:   "openforked-cacert",
			Usage:  "CA certificate bundle to verify against",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_DOMAIN_ID",
			Name:   "openforked-domain-id",
			Usage:  "OpenStack domain ID",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_DOMAIN_NAME",
			Name:   "openforked-domain-name",
			Usage:  "OpenStack domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_USER_ID",
			Name:   "openforked-user-id",
			Usage:  "OpenStack user-id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_USERNAME",
			Name:   "openforked-username",
			Usage:  "OpenStack username",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_PASSWORD",
			Name:   "openforked-password",
			Usage:  "OpenStack password",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_TENANT_NAME",
			Name:   "openforked-tenant-name",
			Usage:  "OpenStack tenant name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_TENANT_ID",
			Name:   "openforked-tenant-id",
			Usage:  "OpenStack tenant id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_TENANT_DOMAIN_NAME",
			Name:   "openforked-tenant-domain-name",
			Usage:  "OpenStack tenant domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_TENANT_DOMAIN_ID",
			Name:   "openforked-tenant-domain-id",
			Usage:  "OpenStack tenant domain id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_USER_DOMAIN_NAME",
			Name:   "openforked-user-domain-name",
			Usage:  "OpenStack user domain name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_USER_DOMAIN_ID",
			Name:   "openforked-user-domain-id",
			Usage:  "OpenStack user domain id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_APPLICATION_CREDENTIAL_ID",
			Name:   "openforked-application-credential-id",
			Usage:  "OpenStack application credential id",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_APPLICATION_CREDENTIAL_NAME",
			Name:   "openforked-application-credential-name",
			Usage:  "OpenStack application credential name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_APPLICATION_CREDENTIAL_SECRET",
			Name:   "openforked-application-credential-secret",
			Usage:  "OpenStack application credential secret",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_REGION_NAME",
			Name:   "openforked-region",
			Usage:  "OpenStack region name",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_AVAILABILITY_ZONE",
			Name:   "openforked-availability-zone",
			Usage:  "OpenStack availability zone",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_ENDPOINT_TYPE",
			Name:   "openforked-endpoint-type",
			Usage:  "OpenStack endpoint type (adminURL, internalURL or publicURL)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_FLAVOR_ID",
			Name:   "openforked-flavor-id",
			Usage:  "OpenStack flavor id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_FLAVOR_NAME",
			Name:   "openforked-flavor-name",
			Usage:  "OpenStack flavor name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_IMAGE_ID",
			Name:   "openforked-image-id",
			Usage:  "OpenStack image id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_IMAGE_NAME",
			Name:   "openforked-image-name",
			Usage:  "OpenStack image name to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_KEYPAIR_NAME",
			Name:   "openforked-keypair-name",
			Usage:  "OpenStack keypair to use to SSH to the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_SERVER_GROUP_ID",
			Name:   "openforked-server-group-id",
			Usage:  "OpenStack server group id to use for the instance",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_SERVER_GROUP_NAME",
			Name:   "openforked-server-group-name",
			Usage:  "OpenStack server group name to use for the instance",
			Value:  "",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "OF_NETWORK_ID",
			Name:   "openforked-net-id",
			Usage:  "OpenStack network id the machine will be connected on",
			Value:  nil,
		},
		mcnflag.StringFlag{
			EnvVar: "OF_PRIVATE_KEY_FILE",
			Name:   "openforked-private-key-file",
			Usage:  "Private keyfile to use for SSH (absolute path)",
			Value:  "",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_USER_DATA_FILE",
			Name:   "openforked-user-data-file",
			Usage:  "File containing an openstack userdata script",
			Value:  "",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "OF_NETWORK_NAME",
			Name:   "openforked-net-name",
			Usage:  "OpenStack network name the machine will be connected on",
			Value:  nil,
		},
		mcnflag.StringSliceFlag{
			EnvVar: "OF_SECURITY_GROUP",
			Name:   "openforked-sec-group",
			Usage:  "OpenStack security group for the machine",
			Value:  nil,
		},
		mcnflag.BoolFlag{
			EnvVar: "OF_NOVA_NETWORK",
			Name:   "openforked-nova-network",
			Usage:  "Use the nova networking services instead of neutron.",
		},
		mcnflag.StringFlag{
			EnvVar: "OF_FLOATINGIP_POOL",
			Name:   "openforked-floatingip-pool",
			Usage:  "OpenStack floating IP pool to get an IP from to assign to the instance",
			Value:  "",
		},
		mcnflag.IntFlag{
			EnvVar: "OF_IP_VERSION",
			Name:   "openforked-ip-version",
			Usage:  "OpenStack version of IP address assigned for the machine",
			Value:  4,
		},
		mcnflag.StringFlag{
			EnvVar: "OF_SSH_USER",
			Name:   "openforked-ssh-user",
			Usage:  "OpenStack SSH user",
			Value:  defaultSSHUser,
		},
		mcnflag.IntFlag{
			EnvVar: "OF_SSH_PORT",
			Name:   "openforked-ssh-port",
			Usage:  "OpenStack SSH port",
			Value:  defaultSSHPort,
		},
		mcnflag.IntFlag{
			EnvVar: "OF_ACTIVE_TIMEOUT",
			Name:   "openforked-active-timeout",
			Usage:  "OpenStack active timeout",
			Value:  defaultActiveTimeout,
		},
		mcnflag.BoolFlag{
			EnvVar: "OF_CONFIG_DRIVE",
			Name:   "openforked-config-drive",
			Usage:  "Enables the OpenStack config drive for the instance",
		},
		mcnflag.BoolFlag{
			Name:  "openforked-boot-from-volume",
			Usage: "Enables Openstack instance to boot from volume as ROOT",
		},
		mcnflag.StringFlag{
			Name:  "openforked-volume-name",
			Usage: "OpenStack volume name (creating); Default: 'rancher-machine-name'",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openforked-volume-device-path",
			Usage: "OpenStack volume device path (attaching); Omit for auto '/dev/vdb'",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openforked-volume-id",
			Usage: "OpenStack volume id (existing)",
			Value: "",
		},
		mcnflag.StringFlag{
			Name:  "openforked-volume-type",
			Usage: "OpenStack volume type (ssd, ...)",
			Value: "",
		},
		mcnflag.IntFlag{
			Name:  "openforked-volume-size",
			Usage: "OpenStack volume size (GiB) when creating a volume",
			Value: 0,
		},
	}

}

func NewDriver(hostName, storePath string) drivers.Driver {
	return NewDerivedDriver(hostName, storePath)

}

func NewDerivedDriver(hostName, storePath string) *Driver {
	return &Driver{
		client:        &GenericClient{},
		ActiveTimeout: defaultActiveTimeout,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			SSHPort:     defaultSSHPort,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}

}

func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()

}

func (d *Driver) SetClient(client Client) {
	d.client = client

}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "openforked"

}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.AuthUrl = flags.String("openforked-auth-url")
	d.ActiveTimeout = flags.Int("openforked-active-timeout")
	d.Insecure = flags.Bool("openforked-insecure")
	d.CaCert = flags.String("openforked-cacert")
	d.DomainId = flags.String("openforked-domain-id")
	d.DomainName = flags.String("openforked-domain-name")
	d.UserId = flags.String("openforked-user-id")
	d.Username = flags.String("openforked-username")
	d.Password = flags.String("openforked-password")
	d.TenantName = flags.String("openforked-tenant-name")
	d.TenantId = flags.String("openforked-tenant-id")
	d.TenantDomainName = flags.String("openforked-tenant-domain-name")
	d.TenantDomainId = flags.String("openforked-tenant-domain-id")
	d.UserDomainName = flags.String("openforked-user-domain-name")
	d.UserDomainId = flags.String("openforked-user-domain-id")
	d.ApplicationCredentialId = flags.String("openforked-application-credential-id")
	d.ApplicationCredentialName = flags.String("openforked-application-credential-name")
	d.ApplicationCredentialSecret = flags.String("openforked-application-credential-secret")
	d.Region = flags.String("openforked-region")
	d.AvailabilityZone = flags.String("openforked-availability-zone")
	d.EndpointType = flags.String("openforked-endpoint-type")
	d.FlavorId = flags.String("openforked-flavor-id")
	d.FlavorName = flags.String("openforked-flavor-name")
	d.ImageId = flags.String("openforked-image-id")
	d.ImageName = flags.String("openforked-image-name")
	d.ServerGroupId = flags.String("openforked-server-group-id")
	d.ServerGroupName = flags.String("openforked-server-group-name")
	d.NetworkIds = flags.StringSlice("openforked-net-id")
	d.NetworkNames = flags.StringSlice("openforked-net-name")
	d.SecurityGroups = flags.StringSlice("openforked-sec-group")
	d.FloatingIpPool = flags.String("openforked-floatingip-pool")
	d.IpVersion = flags.Int("openforked-ip-version")
	d.ComputeNetwork = flags.Bool("openforked-nova-network")
	d.SSHUser = flags.String("openforked-ssh-user")
	d.SSHPort = flags.Int("openforked-ssh-port")
	d.ExistingKey = flags.String("openforked-keypair-name") != ""
	d.KeyPairName = flags.String("openforked-keypair-name")
	d.PrivateKeyFile = flags.String("openforked-private-key-file")
	d.ConfigDrive = flags.Bool("openforked-config-drive")

	d.BootFromVolume = flags.Bool("openforked-boot-from-volume")
	d.VolumeName = flags.String("openforked-volume-name")
	d.VolumeDevicePath = flags.String("openforked-volume-device-path")
	d.VolumeId = flags.String("openforked-volume-id")
	d.VolumeType = flags.String("openforked-volume-type")
	d.VolumeSize = flags.Int("openforked-volume-size")

	if flags.String("openforked-user-data-file") != "" {
		userData, err := ioutil.ReadFile(flags.String("openforked-user-data-file"))
		if err == nil {
			d.UserData = userData

		} else {
			return err

		}

	}

	d.SetSwarmConfigFromFlags(flags)

	return d.checkConfig()

}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err

	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err

	}
	if ip == "" {
		return "", nil

	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil

}

func (d *Driver) GetIP() (string, error) {
	if d.IPAddress != "" {
		return d.IPAddress, nil

	}

	log.Debug("Looking for the IP address...", map[string]string{"MachineId": d.MachineId})

	if err := d.initCompute(); err != nil {
		return "", err

	}

	addressType := Fixed
	if d.FloatingIpPool != "" {
		addressType = Floating

	}

	// Looking for the IP address in a retry loop to deal with OpenStack latency
	for retryCount := 0; retryCount < 5; retryCount++ {
		addresses, err := d.client.GetInstanceIPAddresses(d)
		if err != nil {
			return "", err

		}
		for _, a := range addresses {
			if a.AddressType == addressType && a.Version == d.IpVersion {
				return a.Address, nil

			}

		}
		time.Sleep(2 * time.Second)

	}
	return "", fmt.Errorf("no IP found for the machine")

}

func (d *Driver) GetState() (state.State, error) {
	log.Debug("Get status for OpenStack instance...", map[string]string{"MachineId": d.MachineId})
	if err := d.initCompute(); err != nil {
		return state.None, err

	}

	s, err := d.client.GetInstanceState(d)
	if err != nil {
		return state.None, err

	}

	log.Debug("State for OpenStack instance", map[string]string{
		"MachineId": d.MachineId,
		"State":     s,
	})

	switch s {
	case "ACTIVE":
		return state.Running, nil
	case "PAUSED":
		return state.Paused, nil
	case "SUSPENDED":
		return state.Saved, nil
	case "SHUTOFF":
		return state.Stopped, nil
	case "BUILDING":
		return state.Starting, nil
	case "ERROR":
		return state.Error, nil

	}
	return state.None, nil

}

func (d *Driver) failedToCreate(err error) error {
	if e := d.Remove(); e != nil {
		return fmt.Errorf("%v: %v", err, e)

	}
	return err

}

func (d *Driver) Create() error {
	if err := d.resolveIds(); err != nil {
		return err

	}
	if d.KeyPairName != "" {
		if err := d.loadSSHKey(); err != nil {
			return err

		}

	} else {
		d.KeyPairName = fmt.Sprintf("%s-%s", d.MachineName, mcnutils.GenerateRandomID())
		if err := d.createSSHKey(); err != nil {
			return err

		}

	}
	if d.BootFromVolume == false && d.VolumeSize > 0 {
		if err := d.volumeCreate(); err != nil {
			return err

		}

	}
	if err := d.createMachine(); err != nil {
		return err

	}
	if err := d.waitForInstanceActive(); err != nil {
		return d.failedToCreate(err)

	}
	if d.BootFromVolume == false && d.VolumeId != "" {
		if err := d.waitForVolumeAvailable(); err != nil {
			return err

		}
		if err := d.volumeAttach(); err != nil {
			return err

		}

	}
	if d.FloatingIpPool != "" {
		if err := d.assignFloatingIP(); err != nil {
			return d.failedToCreate(err)

		}

	}
	if err := d.lookForIPAddress(); err != nil {
		return d.failedToCreate(err)

	}
	return nil

}

func (d *Driver) Start() error {
	if err := d.initCompute(); err != nil {
		return err

	}

	return d.client.StartInstance(d)

}

func (d *Driver) Stop() error {
	if err := d.initCompute(); err != nil {
		return err

	}

	return d.client.StopInstance(d)

}

func (d *Driver) Restart() error {
	if err := d.initCompute(); err != nil {
		return err

	}

	return d.client.RestartInstance(d)

}

func (d *Driver) Kill() error {
	return d.Stop()

}

func (d *Driver) Remove() error {
	log.Debug("deleting instance...", map[string]string{"MachineId": d.MachineId})
	log.Info("Deleting OpenStack instance...")

	if err := d.resolveIds(); err != nil {
		return err

	}

	if d.FloatingIpPool != "" && d.IPAddress != "" && !d.ComputeNetwork {
		floatingIP, err := d.client.GetFloatingIP(d, d.IPAddress)
		if err != nil {
			return err

		}

		if floatingIP != nil {
			log.Debug("Deleting Floating IP: ", map[string]string{"floatingIP": floatingIP.Ip})
			if err := d.client.DeleteFloatingIP(d, floatingIP); err != nil {
				return err

			}

		}

	}

	if err := d.initCompute(); err != nil {
		return err

	}
	if err := d.client.DeleteInstance(d); err != nil {
		if gopherErr, ok := err.(*gophercloud.ErrUnexpectedResponseCode); ok {
			if gopherErr.Actual == http.StatusNotFound {
				log.Warn("Remote instance does not exist, proceeding with removing local reference")

			} else {
				return err

			}

		} else {
			return err

		}

	}
	if !d.ExistingKey {
		log.Debug("deleting key pair...", map[string]string{"Name": d.KeyPairName})
		if err := d.client.DeleteKeyPair(d, d.KeyPairName); err != nil {
			return err

		}

	}
	return nil

}

func (d *Driver) parseAuthConfig() (*gophercloud.AuthOptions, error) {
	return clientconfig.AuthOptions(
		&clientconfig.ClientOpts{
			// this is needed to disable the clientconfig.AuthOptions func env detection
			EnvPrefix: "_",
			AuthInfo: &clientconfig.AuthInfo{
				AuthURL:                     d.AuthUrl,
				UserID:                      d.UserId,
				Username:                    d.Username,
				Password:                    d.Password,
				ProjectID:                   d.TenantId,
				ProjectName:                 d.TenantName,
				DomainID:                    d.DomainId,
				DomainName:                  d.DomainName,
				ProjectDomainID:             d.TenantDomainId,
				ProjectDomainName:           d.TenantDomainName,
				UserDomainID:                d.UserDomainId,
				UserDomainName:              d.UserDomainName,
				ApplicationCredentialID:     d.ApplicationCredentialId,
				ApplicationCredentialName:   d.ApplicationCredentialName,
				ApplicationCredentialSecret: d.ApplicationCredentialSecret,
			},
		},
	)

}

func (d *Driver) checkConfig() error {
	if _, err := d.parseAuthConfig(); err != nil {
		return err

	}

	if d.FlavorName == "" && d.FlavorId == "" {
		return fmt.Errorf(errorMandatoryOption, "Flavor name or Flavor id", "--openstack-flavor-name or --openstack-flavor-id")

	}
	if d.FlavorName != "" && d.FlavorId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Flavor name", "Flavor id")

	}

	if d.ImageName == "" && d.ImageId == "" {
		return fmt.Errorf(errorMandatoryOption, "Image name or Image id", "--openstack-image-name or --openstack-image-id")

	}
	if d.ImageName != "" && d.ImageId != "" {
		return fmt.Errorf(errorExclusiveOptions, "Image name", "Image id")

	}

	if len(d.NetworkNames)*len(d.NetworkIds) > 0 {
		return fmt.Errorf(errorExclusiveOptions, "Network names", "Network ids")

	}
	if d.EndpointType != "" && (d.EndpointType != "publicURL" && d.EndpointType != "adminURL" && d.EndpointType != "internalURL") {
		return fmt.Errorf(errorWrongEndpointType)

	}
	if (d.KeyPairName != "" && d.PrivateKeyFile == "") || (d.KeyPairName == "" && d.PrivateKeyFile != "") {
		return fmt.Errorf(errorBothOptions, "KeyPairName", "PrivateKeyFile")

	}
	return nil

}

func (d *Driver) resolveIds() error {
	if len(d.NetworkNames) > 0 && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err

		}

		networkIDs, err := d.client.GetNetworkIDs(d)

		if err != nil {
			return err

		}

		if len(networkIDs) == 0 {
			return fmt.Errorf(errorUnknownNetworkName, d.NetworkNames)

		}

		d.NetworkIds = append(d.NetworkIds, networkIDs...)
		log.Debug("Found network id using its name", map[string][]string{
			"Name": d.NetworkNames,
			"ID":   d.NetworkIds,
		})

	}

	if d.FlavorName != "" {
		if err := d.initCompute(); err != nil {
			return err

		}
		flavorID, err := d.client.GetFlavorID(d)

		if err != nil {
			return err

		}

		if flavorID == "" {
			return fmt.Errorf(errorUnknownFlavorName, d.FlavorName)

		}

		d.FlavorId = flavorID
		log.Debug("Found flavor id using its name", map[string]string{
			"Name": d.FlavorName,
			"ID":   d.FlavorId,
		})

	}

	if d.ImageName != "" {
		if err := d.initCompute(); err != nil {
			return err

		}
		imageID, err := d.client.GetImageID(d)

		if err != nil {
			return err

		}

		if imageID == "" {
			return fmt.Errorf(errorUnknownImageName, d.ImageName)

		}

		d.ImageId = imageID
		log.Debug("Found image id using its name", map[string]string{
			"Name": d.ImageName,
			"ID":   d.ImageId,
		})

	}

	if d.ServerGroupName != "" {
		if err := d.initCompute(); err != nil {
			return err
		}
		serverGroupId, err := d.client.GetServerGroupID(d)

		if err != nil {
			return err
		}

		if serverGroupId == "" {
			return fmt.Errorf(errorUnknownServerGroupName, d.ServerGroupName)
		}

		d.ServerGroupId = serverGroupId
		log.Debug("Found server group id using its name", map[string]string{
			"Name": d.ServerGroupName,
			"ID":   d.ServerGroupId,
		})
	}

	if d.FloatingIpPool != "" && !d.ComputeNetwork {
		if err := d.initNetwork(); err != nil {
			return err

		}
		f, err := d.client.GetFloatingIPPoolIDs(d)

		if err != nil {
			return err

		}

		if len(f) == 0 {
			return fmt.Errorf(errorUnknownNetworkName, d.FloatingIpPool)

		}

		d.FloatingIpPoolId = f[0]
		log.Debug("Found floating IP pool id using its name", map[string]string{
			"Name": d.FloatingIpPool,
			"ID":   d.FloatingIpPoolId,
		})

	}

	return nil

}

func (d *Driver) initCompute() error {
	if err := d.client.Authenticate(d); err != nil {
		return err

	}
	if err := d.client.InitComputeClient(d); err != nil {
		return err

	}
	return nil

}

func (d *Driver) initNetwork() error {
	if err := d.client.Authenticate(d); err != nil {
		return err

	}
	if err := d.client.InitNetworkClient(d); err != nil {
		return err

	}
	return nil

}

func (d *Driver) initBlockStorage() error {
	if err := d.client.Authenticate(d); err != nil {
		return err

	}
	if err := d.client.InitBlockStorageClient(d); err != nil {
		return err

	}
	return nil

}

func (d *Driver) loadSSHKey() error {
	log.Debug("Loading Key Pair", d.KeyPairName)
	if err := d.initCompute(); err != nil {
		return err

	}
	log.Debug("Loading Private Key from", d.PrivateKeyFile)
	privateKey, err := ioutil.ReadFile(d.PrivateKeyFile)
	if err != nil {
		return err

	}
	publicKey, err := d.client.GetPublicKey(d.KeyPairName)
	if err != nil {
		return err

	}
	if err := ioutil.WriteFile(d.privateSSHKeyPath(), privateKey, 0600); err != nil {
		return err

	}
	if err := ioutil.WriteFile(d.publicSSHKeyPath(), publicKey, 0600); err != nil {
		return err

	}

	return nil

}

func (d *Driver) createSSHKey() error {
	sanitizeKeyPairName(&d.KeyPairName)
	log.Debug("Creating Key Pair...", map[string]string{"Name": d.KeyPairName})
	if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
		return err

	}
	publicKey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err

	}

	if err := d.initCompute(); err != nil {
		return err

	}
	if err := d.client.CreateKeyPair(d, d.KeyPairName, string(publicKey)); err != nil {
		return err

	}
	return nil

}

func (d *Driver) createMachine() error {
	log.Debug("Creating OpenStack instance...", map[string]string{
		"FlavorId": d.FlavorId,
		"ImageId":  d.ImageId,
	})

	if err := d.initCompute(); err != nil {
		return err

	}

	if d.requiresBlockStorage() {
		if err := d.initBlockStorage(); err != nil {
			return err

		}

	}

	instanceID, err := d.client.CreateInstance(d)
	if err != nil {
		return err

	}
	d.MachineId = instanceID
	return nil

}

func (d *Driver) volumeCreate() error {
	if d.VolumeName == "" {
		d.VolumeName = "rancher-machine-volume"

	}
	log.Debug("Creating OpenStack Volume ...", map[string]string{
		"VolumeName": d.VolumeName,
		"VolumeType": d.VolumeType,
		"VolumeSize": strconv.Itoa(d.VolumeSize),
	})

	if err := d.initBlockStorage(); err != nil {
		return err

	}
	volumeId, err := d.client.VolumeCreate(d)
	if err != nil {
		return err

	}
	d.VolumeId = volumeId
	return nil

}

func (d *Driver) waitForVolumeAvailable() error {
	log.Debug("Waiting for the OpenStack volume to be available...", map[string]string{
		"VolumeId": d.VolumeId,
	})
	if err := d.initBlockStorage(); err != nil {
		return err

	}
	if err := d.client.WaitForVolumeStatus(d, "available"); err != nil {
		return err

	}
	return nil

}

func (d *Driver) volumeAttach() error {
	log.Debug("Attaching OpenStack Volume ...", map[string]string{
		"VolumeId":         d.VolumeId,
		"VolumeDevicePath": d.VolumeDevicePath,
	})
	if err := d.initCompute(); err != nil {
		return err

	}
	VolumeDevicePath, err := d.client.VolumeAttach(d)
	if err != nil {
		return err

	}
	d.VolumeDevicePath = VolumeDevicePath
	return nil

}

func (d *Driver) assignFloatingIP() error {
	var err error

	if d.ComputeNetwork {
		err = d.initCompute()

	} else {
		err = d.initNetwork()

	}

	if err != nil {
		return err

	}

	floatingIP := &FloatingIP{}
	log.Debug("Allocating a new floating IP...", map[string]string{"MachineId": d.MachineId})

	if err := d.client.AssignFloatingIP(d, floatingIP); err != nil {
		return err

	}
	d.IPAddress = floatingIP.Ip
	return nil

}

func (d *Driver) waitForInstanceActive() error {
	log.Debug("Waiting for the OpenStack instance to be ACTIVE...", map[string]string{"MachineId": d.MachineId})
	if err := d.client.WaitForInstanceStatus(d, "ACTIVE"); err != nil {
		return err

	}
	return nil

}

func (d *Driver) lookForIPAddress() error {
	ip, err := d.GetIP()
	if err != nil {
		return err

	}
	d.IPAddress = ip
	log.Debug("IP address found", map[string]string{
		"IP":        ip,
		"MachineId": d.MachineId,
	})
	return nil

}

func (d *Driver) privateSSHKeyPath() string {
	return d.GetSSHKeyPath()

}

func (d *Driver) publicSSHKeyPath() string {
	return d.GetSSHKeyPath() + ".pub"

}

// openstack deployments may not have cinder available
// check to see if it's required before initializing
func (d *Driver) requiresBlockStorage() bool {
	return d.VolumeName != "" || d.VolumeId != "" || d.VolumeType != "" || d.BootFromVolume || d.VolumeSize > 0 || d.VolumeDevicePath != ""

}

func sanitizeKeyPairName(s *string) {
	*s = strings.Replace(*s, ".", "_", -1)

}
