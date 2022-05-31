package openforked

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/blockstorage/v1/volumes"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/bootfromvolume"
	computeips "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/schedulerhints"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/servergroups"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/volumeattach"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/images"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/floatingips"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/version"
)

type Client interface {
	Authenticate(d *Driver) error
	InitComputeClient(d *Driver) error
	InitNetworkClient(d *Driver) error
	InitBlockStorageClient(d *Driver) error

	CreateInstance(d *Driver) (string, error)
	GetInstanceState(d *Driver) (string, error)
	StartInstance(d *Driver) error
	StopInstance(d *Driver) error
	RestartInstance(d *Driver) error
	DeleteInstance(d *Driver) error
	WaitForInstanceStatus(d *Driver, status string) error
	GetInstanceIPAddresses(d *Driver) ([]IPAddress, error)
	GetPublicKey(keyPairName string) ([]byte, error)
	CreateKeyPair(d *Driver, name string, publicKey string) error
	DeleteKeyPair(d *Driver, name string) error
	GetNetworkIDs(d *Driver) ([]string, error)
	GetFlavorID(d *Driver) (string, error)
	GetImageID(d *Driver) (string, error)
	GetServerGroupID(d *Driver) (string, error)
	AssignFloatingIP(d *Driver, floatingIP *FloatingIP) error
	DeleteFloatingIP(d *Driver, floatingIP *FloatingIP) error
	GetFloatingIPs(d *Driver) ([]FloatingIP, error)
	GetFloatingIP(d *Driver, ip string) (*FloatingIP, error)
	GetFloatingIPPoolIDs(d *Driver) ([]string, error)
	GetInstancePortIDs(d *Driver) ([]string, error)
	VolumeCreate(d *Driver) (string, error)
	WaitForVolumeStatus(d *Driver, status string) error
	VolumeAttach(d *Driver) (string, error)
}

type GenericClient struct {
	Provider     *gophercloud.ProviderClient
	Compute      *gophercloud.ServiceClient
	Network      *gophercloud.ServiceClient
	BlockStorage *gophercloud.ServiceClient
}

func (c *GenericClient) CreateInstance(d *Driver) (string, error) {
	var serverOpts servers.CreateOptsBuilder

	var serverNetworks []servers.Network
	if len(d.NetworkIds) > 0 {
		serverNetworks = make([]servers.Network, 0, len(d.NetworkIds))
		for _, id := range d.NetworkIds {
			serverNetworks = append(serverNetworks, servers.Network{UUID: id})
		}
	}

	serverOpts = &keypairs.CreateOptsExt{
		CreateOptsBuilder: &servers.CreateOpts{
			Name:             d.MachineName,
			FlavorRef:        d.FlavorId,
			ImageRef:         d.ImageId,
			UserData:         d.UserData,
			Networks:         serverNetworks,
			SecurityGroups:   d.SecurityGroups,
			AvailabilityZone: d.AvailabilityZone,
			ConfigDrive:      &d.ConfigDrive,
		},
		KeyName: d.KeyPairName,
	}

	if d.ServerGroupId != "" {
		serverOpts = &schedulerhints.CreateOptsExt{
			CreateOptsBuilder: serverOpts,
			SchedulerHints: schedulerhints.SchedulerHints{
				Group: d.ServerGroupId,
			},
		}
	}

	log.Info("Creating machine...")

	var server *servers.Server
	var err error
	if d.BootFromVolume {
		blockDevices := []bootfromvolume.BlockDevice{
			{
				BootIndex:           0,
				DeleteOnTermination: true,
				DestinationType:     bootfromvolume.DestinationVolume,
				SourceType:          bootfromvolume.SourceImage,
				UUID:                d.ImageId,
				VolumeType:          d.VolumeType,
				VolumeSize:          d.VolumeSize,
			},
		}
		serverOpts = &bootfromvolume.CreateOptsExt{
			CreateOptsBuilder: serverOpts,
			BlockDevice:       blockDevices,
		}

		if d.VolumeType != "" {
			c.Compute.Microversion = "2.67"
		}

		server, err = bootfromvolume.Create(c.Compute, serverOpts).Extract()
	} else {
		server, err = servers.Create(c.Compute, serverOpts).Extract()
	}
	if err != nil {
		return "", err
	}
	return server.ID, nil
}

func (c *GenericClient) VolumeCreate(d *Driver) (string, error) {
	log.Info("Creating volume...")
	opts := volumes.CreateOpts{
		Name: d.VolumeName,
		Size: d.VolumeSize,
	}

	if d.VolumeType != "" {
		opts.VolumeType = d.VolumeType
	}

	if d.AvailabilityZone != "" {
		opts.AvailabilityZone = d.AvailabilityZone
	}

	vol, err := volumes.Create(c.BlockStorage, opts).Extract()
	if err != nil {
		return "", err
	}

	log.Infof("Volume created: VolumeId: %s VolumeName: %s VolumeType: %s VolumeSize: %d", vol.ID, vol.Name, vol.VolumeType, vol.Size)
	return vol.ID, nil
}

func (c *GenericClient) WaitForVolumeStatus(d *Driver, status string) error {
	return mcnutils.WaitForSpecificOrError(func() (bool, error) {
		vol, err := volumes.Get(c.BlockStorage, d.VolumeId).Extract()
		if err != nil {
			return true, err
		}

		return vol.Status == status, nil
	}, 50, 4*time.Second)
}

func (c *GenericClient) VolumeAttach(d *Driver) (string, error) {
	log.Info("Attaching volume...")
	attachOpts := volumeattach.CreateOpts{
		VolumeID: d.VolumeId,
	}

	if d.VolumeDevicePath != "" {
		attachOpts.Device = d.VolumeDevicePath
	}

	volAttached, err := volumeattach.Create(c.Compute, d.MachineId, attachOpts).Extract()
	if err != nil {
		return "", err
	}

	log.Infof("Volume attached: VolumeId=%v Device=%v ServerId=%v", volAttached.VolumeID, volAttached.Device, volAttached.ServerID)
	return volAttached.Device, nil
}

const (
	Floating string = "floating"
	Fixed    string = "fixed"
)

type IPAddress struct {
	Network     string
	AddressType string
	Address     string
	Version     int
	Mac         string
}

type FloatingIP struct {
	Id        string
	Ip        string
	NetworkId string
	PortId    string
	Pool      string
	MachineId string
}

func (c *GenericClient) GetInstanceState(d *Driver) (string, error) {
	server, err := c.GetServerDetail(d)
	if err != nil {
		return "", err
	}

	return server.Status, nil
}

func (c *GenericClient) StartInstance(d *Driver) error {
	result := startstop.Start(c.Compute, d.MachineId)
	return result.Err
}

func (c *GenericClient) StopInstance(d *Driver) error {
	result := startstop.Stop(c.Compute, d.MachineId)
	return result.Err
}

func (c *GenericClient) RestartInstance(d *Driver) error {
	result := servers.Reboot(c.Compute, d.MachineId, servers.RebootOpts{Type: servers.SoftReboot})
	return result.Err
}

func (c *GenericClient) DeleteInstance(d *Driver) error {
	result := servers.Delete(c.Compute, d.MachineId)
	return result.Err
}

func (c *GenericClient) WaitForInstanceStatus(d *Driver, status string) error {
	return mcnutils.WaitForSpecificOrError(func() (bool, error) {
		current, err := servers.Get(c.Compute, d.MachineId).Extract()
		if err != nil {
			return true, err
		}

		if current.Status == "ERROR" {
			return true, fmt.Errorf("Instance creation failed. Instance is in ERROR state")
		}

		if current.Status == status {
			return true, nil
		}

		return false, nil
	}, d.ActiveTimeout/4, 4*time.Second)
}

func (c *GenericClient) GetInstanceIPAddresses(d *Driver) ([]IPAddress, error) {
	server, err := c.GetServerDetail(d)
	if err != nil {
		return nil, err
	}

	var addresses []IPAddress
	for network, networkAddresses := range server.Addresses {
		for _, element := range networkAddresses.([]interface{}) {
			address := element.(map[string]interface{})
			version, ok := address["version"].(float64)
			if !ok {
				// Assume IPv4 if no version present.
				version = 4
			}

			addr := IPAddress{
				Network:     network,
				AddressType: Fixed,
				Address:     address["addr"].(string),
				Version:     int(version),
			}

			if tp, ok := address["OS-EXT-IPS:type"]; ok {
				addr.AddressType = tp.(string)
			}
			if mac, ok := address["OS-EXT-IPS-MAC:mac_addr"]; ok {
				addr.Mac = mac.(string)
			}

			addresses = append(addresses, addr)
		}
	}

	return addresses, nil
}

func (c *GenericClient) GetNetworkIDs(d *Driver) ([]string, error) {
	return c.getNetworkIDs(d.NetworkNames...)
}

func (c *GenericClient) GetFloatingIPPoolIDs(d *Driver) ([]string, error) {
	return c.getNetworkIDs(d.FloatingIpPool)
}

func (c *GenericClient) getNetworkIDs(networkNames ...string) ([]string, error) {
	if len(networkNames) == 0 {
		return nil, fmt.Errorf("no network names provided")
	}

	networkIDs := make([]string, 0, len(networkNames))
	opts := networks.ListOpts{}

	for _, networkName := range networkNames {
		opts.Name = networkName
		pager := networks.List(c.Network, opts)

		if err := pager.EachPage(func(page pagination.Page) (bool, error) {
			networkList, err := networks.ExtractNetworks(page)
			if err != nil {
				return false, err
			}

			for _, n := range networkList {
				if n.Name == networkName {
					networkIDs = append(networkIDs, n.ID)
					return false, nil
				}
			}

			return true, nil
		}); err != nil {
			return nil, err
		}
	}
	return networkIDs, nil
}

func (c *GenericClient) GetFlavorID(d *Driver) (string, error) {
	pager := flavors.ListDetail(c.Compute, nil)
	flavorID := ""

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		flavorList, err := flavors.ExtractFlavors(page)
		if err != nil {
			return false, err
		}

		for _, f := range flavorList {
			if f.Name == d.FlavorName {
				flavorID = f.ID
				return false, nil
			}
		}

		return true, nil
	})

	return flavorID, err
}

func (c *GenericClient) GetImageID(d *Driver) (string, error) {
	opts := images.ListOpts{Name: d.ImageName}
	pager := images.ListDetail(c.Compute, opts)
	var imageID string

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			return false, err
		}

		for _, i := range imageList {
			if i.Name == d.ImageName {
				imageID = i.ID
				return false, nil
			}
		}

		return true, nil
	})

	return imageID, err
}

func (c *GenericClient) GetServerGroupID(d *Driver) (string, error) {
	pager := servergroups.List(c.Compute)
	var serverGroupID string

	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		serverGroupList, err := servergroups.ExtractServerGroups(page)
		if err != nil {
			return false, err
		}

		for _, i := range serverGroupList {
			if i.Name == d.ServerGroupName {
				serverGroupID = i.ID
				return false, nil
			}
		}

		return true, nil
	})

	return serverGroupID, err
}

func (c *GenericClient) GetPublicKey(keyPairName string) ([]byte, error) {
	kp, err := keypairs.Get(c.Compute, keyPairName).Extract()
	if err != nil {
		return nil, err
	}
	return []byte(kp.PublicKey), nil
}

func (c *GenericClient) CreateKeyPair(d *Driver, name string, publicKey string) error {
	result := keypairs.Create(c.Compute, keypairs.CreateOpts{Name: name, PublicKey: publicKey})
	return result.Err
}

func (c *GenericClient) DeleteKeyPair(d *Driver, name string) error {
	result := keypairs.Delete(c.Compute, name)
	return result.Err
}

func (c *GenericClient) GetServerDetail(d *Driver) (*servers.Server, error) {
	server, err := servers.Get(c.Compute, d.MachineId).Extract()
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (c *GenericClient) AssignFloatingIP(d *Driver, floatingIP *FloatingIP) error {
	if d.ComputeNetwork {
		return c.assignNovaFloatingIP(d, floatingIP)
	}
	return c.assignNeutronFloatingIP(d, floatingIP)
}

func (c *GenericClient) assignNovaFloatingIP(d *Driver, floatingIP *FloatingIP) error {
	if floatingIP.Ip == "" {
		f, err := computeips.Create(c.Compute, computeips.CreateOpts{Pool: d.FloatingIpPool}).Extract()
		if err != nil {
			return err
		}

		floatingIP.Ip = f.IP
		floatingIP.Pool = f.Pool
	}
	return computeips.AssociateInstance(c.Compute, d.MachineId, computeips.AssociateOpts{FloatingIP: floatingIP.Ip}).Err
}

func (c *GenericClient) assignNeutronFloatingIP(d *Driver, floatingIP *FloatingIP) error {
	portID, err := c.GetInstancePortIDs(d)
	if err != nil {
		return err
	}

	if floatingIP.Id == "" {
		f, err := floatingips.Create(c.Network, floatingips.CreateOpts{
			FloatingNetworkID: d.FloatingIpPoolId,
			PortID:            portID[0],
		}).Extract()
		if err != nil {
			return err
		}
		floatingIP.Id = f.ID
		floatingIP.Ip = f.FloatingIP
		floatingIP.NetworkId = f.FloatingNetworkID
		floatingIP.PortId = f.PortID
		return nil
	}
	_, err = floatingips.Update(c.Network, floatingIP.Id, floatingips.UpdateOpts{PortID: &portID[0]}).Extract()
	return err
}

func (c *GenericClient) DeleteFloatingIP(d *Driver, floatingIP *FloatingIP) error {
	if d.ComputeNetwork {
		// Nova network is is deprecated in OpenStack
		// https://docs.openstack.org/nova/rocky/admin/networking-nova.html
		log.Warn("Detected that you use Nova network. Floating IP will not be removed, please do so manually if necessary")
		return nil
	}

	return c.deleteNeutronFloatingIP(d, floatingIP)
}

func (c *GenericClient) deleteNeutronFloatingIP(d *Driver, floatingIP *FloatingIP) error {
	return floatingips.Delete(c.Network, floatingIP.Id).ExtractErr()
}

func (c *GenericClient) GetFloatingIPs(d *Driver) ([]FloatingIP, error) {
	if d.ComputeNetwork {
		return c.getNovaNetworkFloatingIPs(d)
	}
	return c.getNeutronNetworkFloatingIPs(d, nil)
}

func (c *GenericClient) GetFloatingIP(d *Driver, ip string) (*FloatingIP, error) {
	if d.ComputeNetwork {
		return nil, fmt.Errorf("operation not supported for nova networks")
	}

	ips, err := c.getNeutronNetworkFloatingIPs(d, &floatingips.ListOpts{FloatingIP: ip})
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, nil
	}
	return &ips[0], nil
}

func (c *GenericClient) getNovaNetworkFloatingIPs(d *Driver) ([]FloatingIP, error) {
	pager := computeips.List(c.Compute)

	var ips []FloatingIP
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		ipListing, err := computeips.ExtractFloatingIPs(page)
		if err != nil {
			return false, err
		}

		for _, ip := range ipListing {
			if ip.InstanceID == "" && ip.Pool == d.FloatingIpPool {
				ips = append(ips, FloatingIP{
					Id:   ip.ID,
					Ip:   ip.IP,
					Pool: ip.Pool,
				})
			}
		}
		return true, nil
	})
	return ips, err
}

func (c *GenericClient) getNeutronNetworkFloatingIPs(d *Driver, opts *floatingips.ListOpts) ([]FloatingIP, error) {
	log.Debug("Listing floating IPs", map[string]string{
		"FloatingNetworkId": d.FloatingIpPoolId,
		"TenantID":          d.TenantId,
	})

	if opts != nil {
		opts.FloatingNetworkID = d.FloatingIpPoolId
		opts.TenantID = d.TenantId
	} else {
		opts = &floatingips.ListOpts{
			FloatingNetworkID: d.FloatingIpPoolId,
			TenantID:          d.TenantId,
		}
	}

	pager := floatingips.List(c.Network, *opts)

	var ips []FloatingIP
	if err := pager.EachPage(func(page pagination.Page) (bool, error) {
		floatingIPList, err := floatingips.ExtractFloatingIPs(page)
		if err != nil {
			return false, err
		}

		for _, f := range floatingIPList {
			ips = append(ips, FloatingIP{
				Id:        f.ID,
				Ip:        f.FloatingIP,
				NetworkId: f.FloatingNetworkID,
				PortId:    f.PortID,
			})
		}

		return true, nil
	}); err != nil {
		return nil, err
	}
	return ips, nil
}

func (c *GenericClient) GetInstancePortIDs(d *Driver) ([]string, error) {
	opts := ports.ListOpts{
		DeviceID: d.MachineId,
	}

	portIDs := make([]string, 0, len(d.NetworkIds))
	for _, networkID := range d.NetworkIds {
		opts.NetworkID = networkID
		pager := ports.List(c.Network, opts)

		if err := pager.EachPage(func(page pagination.Page) (bool, error) {
			portList, err := ports.ExtractPorts(page)
			if err != nil {
				return false, err
			}

			for _, port := range portList {
				portIDs = append(portIDs, port.ID)
			}

			return len(portList) == 0, nil
		}); err != nil {
			return nil, err
		}
	}

	return portIDs, nil
}

func (c *GenericClient) InitComputeClient(d *Driver) error {
	if c.Compute != nil {
		return nil
	}

	compute, err := openstack.NewComputeV2(c.Provider, gophercloud.EndpointOpts{
		Region:       d.Region,
		Availability: c.getEndpointType(d),
	})
	if err != nil {
		return err
	}
	c.Compute = compute
	return nil
}

func (c *GenericClient) InitNetworkClient(d *Driver) error {
	if c.Network != nil {
		return nil
	}

	network, err := openstack.NewNetworkV2(c.Provider, gophercloud.EndpointOpts{
		Region:       d.Region,
		Availability: c.getEndpointType(d),
	})
	if err != nil {
		return err
	}
	c.Network = network
	return nil
}

func (c *GenericClient) InitBlockStorageClient(d *Driver) error {
	if c.BlockStorage != nil {
		return nil
	}

	blockStorage, err := openstack.NewBlockStorageV3(c.Provider, gophercloud.EndpointOpts{
		Region:       d.Region,
		Availability: c.getEndpointType(d),
	})
	if err != nil {
		return err
	}
	c.BlockStorage = blockStorage
	return nil
}

func (c *GenericClient) getEndpointType(d *Driver) gophercloud.Availability {
	switch d.EndpointType {
	case "internalURL":
		return gophercloud.AvailabilityInternal
	case "adminURL":
		return gophercloud.AvailabilityAdmin
	}
	return gophercloud.AvailabilityPublic
}

func (c *GenericClient) Authenticate(d *Driver) error {
	if c.Provider != nil {
		return nil
	}

	log.Debug("Authenticating...", map[string]interface{}{
		"AuthUrl":                   d.AuthUrl,
		"Insecure":                  d.Insecure,
		"CaCert":                    d.CaCert,
		"DomainId":                  d.DomainId,
		"DomainName":                d.DomainName,
		"UserId":                    d.UserId,
		"Username":                  d.Username,
		"TenantName":                d.TenantName,
		"TenantID":                  d.TenantId,
		"TenantDomainName":          d.TenantDomainName,
		"TenantDomainID":            d.TenantDomainId,
		"UserDomainName":            d.UserDomainName,
		"UserDomainID":              d.UserDomainId,
		"ApplicationCredentialId":   d.ApplicationCredentialId,
		"ApplicationCredentialName": d.ApplicationCredentialName,
	})

	ao, err := d.parseAuthConfig()
	if err != nil {
		return err
	}

	// Persistent service, so we need to be able to renew tokens.
	ao.AllowReauth = true

	provider, err := openstack.NewClient(d.AuthUrl)
	if err != nil {
		return err
	}

	c.Provider = provider
	c.Provider.UserAgent.Prepend(fmt.Sprintf("docker-machine/v%d", version.APIVersion))

	err = c.SetTLSConfig(d)
	if err != nil {
		return err
	}

	return openstack.Authenticate(c.Provider, *ao)
}

func (c *GenericClient) SetTLSConfig(d *Driver) error {
	config := &tls.Config{InsecureSkipVerify: d.Insecure}

	if d.CaCert != "" {
		// Use custom CA certificate(s) for root of trust
		certPool := x509.NewCertPool()
		pem, err := ioutil.ReadFile(d.CaCert)
		if err != nil {
			log.Error("Unable to read specified CA certificate(s)")
			return err
		}

		ok := certPool.AppendCertsFromPEM(pem)
		if !ok {
			return fmt.Errorf("Ill-formed CA certificate(s) PEM file")
		}
		config.RootCAs = certPool
	}

	c.Provider.HTTPClient.Transport = &http.Transport{TLSClientConfig: config, Proxy: http.ProxyFromEnvironment}
	return nil
}
