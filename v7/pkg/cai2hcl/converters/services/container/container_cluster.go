package container

import (
	"fmt"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v7/pkg/cai2hcl/converters/utils"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v7/pkg/cai2hcl/models"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v7/pkg/caiasset"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	"google.golang.org/api/container/v1"
)

// ContainerClusterAssetType is the CAI asset type name for container cluster.
const ContainerClusterAssetType string = "container.googleapis.com/Cluster"

// ContainerClusterSchemaName is the TF resource schema name for container cluster.
const ContainerClusterSchemaName string = "google_container_cluster"

// ContainerClusterConverter for container cluster resource.
type ContainerClusterConverter struct {
	name   string
	schema map[string]*schema.Schema
}

// NewContainerClusterConverter returns an HCL converter for container cluster.
func NewContainerClusterConverter(provider *schema.Provider) models.Converter {
	schema := provider.ResourcesMap[ContainerClusterSchemaName].Schema

	return &ContainerClusterConverter{
		name:   ContainerClusterSchemaName,
		schema: schema,
	}
}

func (c *ContainerClusterConverter) Convert(asset *caiasset.Asset) ([]*models.TerraformResourceBlock, error) {
	if asset == nil || asset.Resource == nil && asset.Resource.Data == nil {
		return nil, nil
	}
	fmt.Println("LOL 2")
	var blocks []*models.TerraformResourceBlock
	block, err := c.convertResourceData(asset)
	fmt.Println("LOL 3")
	if err != nil {
		return nil, err
	}
	fmt.Println("LOL 4")
	blocks = append(blocks, block)
	return blocks, nil
}

func (c *ContainerClusterConverter) convertResourceData(asset *caiasset.Asset) (*models.TerraformResourceBlock, error) {
	if asset == nil || asset.Resource == nil || asset.Resource.Data == nil {
		return nil, fmt.Errorf("asset resource data is nil")
	}
	project := utils.ParseFieldValue(asset.Name, "projects")
	location := utils.ParseFieldValue(asset.Name, "locations")
	clusterName := utils.ParseFieldValue(asset.Name, "clusters")
	var cluster *container.Cluster
	if err := utils.DecodeJSON(asset.Resource.Data, &cluster); err != nil {
		return nil, err
	}
	hclData := make(map[string]interface{})
	// Basic fields
	hclData["name"] = clusterName
	hclData["location"] = location
	hclData["project"] = project
	// Node config and pools
	if cluster.NodeConfig != nil {
		hclData["node_config"] = flattenNodeConfig(cluster.NodeConfig)
	}
	// Networking
	if cluster.Network != "" {
		hclData["network"] = tpgresource.GetResourceNameFromSelfLink(cluster.Network)
	}
	if cluster.Subnetwork != "" {
		hclData["subnetwork"] = tpgresource.GetResourceNameFromSelfLink(cluster.Subnetwork)
	}
	// IP allocation policy
	if cluster.IpAllocationPolicy != nil {
		hclData["ip_allocation_policy"] = flattenIPAllocationPolicy(cluster.IpAllocationPolicy)
	}
	// Other important fields
	if cluster.AddonsConfig != nil {
		hclData["addons_config"] = flattenAddonsConfig(cluster.AddonsConfig)
	}
	// Add labels, resource labels, etc.
	if cluster.ResourceLabels != nil {
		hclData["resource_labels"] = cluster.ResourceLabels
	}
	// Create the block
	ctyVal, err := utils.MapToCtyValWithSchema(hclData, c.schema)
	if err != nil {
		return nil, err
	}
	return &models.TerraformResourceBlock{
		Labels: []string{c.name, cluster.Name},
		Value:  ctyVal,
	}, nil
}

func flattenNodeConfig(config *container.NodeConfig) []interface{} {
	if config == nil {
		return nil
	}

	nodeConfig := make(map[string]interface{})

	// Machine type
	if config.MachineType != "" {
		nodeConfig["machine_type"] = config.MachineType
	}

	// Disk size and type
	if config.DiskSizeGb > 0 {
		nodeConfig["disk_size_gb"] = config.DiskSizeGb
	}
	if config.DiskType != "" {
		nodeConfig["disk_type"] = config.DiskType
	}

	// OAuth scopes
	if len(config.OauthScopes) > 0 {
		nodeConfig["oauth_scopes"] = config.OauthScopes
	}

	// Service account
	if config.ServiceAccount != "" {
		nodeConfig["service_account"] = config.ServiceAccount
	}

	// Metadata
	if len(config.Metadata) > 0 {
		nodeConfig["metadata"] = config.Metadata
	}

	// Image type
	if config.ImageType != "" {
		nodeConfig["image_type"] = config.ImageType
	}

	// Labels
	if len(config.Labels) > 0 {
		nodeConfig["labels"] = config.Labels
	}

	// Local SSD disks
	if config.LocalSsdCount != 0 {
		nodeConfig["local_ssd_count"] = config.LocalSsdCount
	}

	// Tags
	if len(config.Tags) > 0 {
		nodeConfig["tags"] = config.Tags
	}

	// Preemptible nodes
	if config.Preemptible {
		nodeConfig["preemptible"] = config.Preemptible
	}

	// Spot nodes
	if config.Spot {
		nodeConfig["spot"] = config.Spot
	}

	// Min CPU platform
	if config.MinCpuPlatform != "" {
		nodeConfig["min_cpu_platform"] = config.MinCpuPlatform
	}

	// Workload metadata config
	if config.WorkloadMetadataConfig != nil {
		nodeConfig["workload_metadata_config"] =
			flattenWorkloadMetadataConfig(config.WorkloadMetadataConfig)
	}

	// Shielded instance config
	if config.ShieldedInstanceConfig != nil {
		nodeConfig["shielded_instance_config"] =
			flattenShieldedInstanceConfig(config.ShieldedInstanceConfig)
	}

	// Boot disk KMS key
	if config.BootDiskKmsKey != "" {
		nodeConfig["boot_disk_kms_key"] = config.BootDiskKmsKey
	}

	// Guest accelerators
	if len(config.Accelerators) > 0 {
		nodeConfig["guest_accelerator"] =
			flattenAccelerators(config.Accelerators)
	}

	// GCE node pool reservation affinity
	if config.ReservationAffinity != nil {
		nodeConfig["reservation_affinity"] =
			flattenReservationAffinity(config.ReservationAffinity)
	}

	// Confidential nodes
	if config.ConfidentialNodes != nil {
		nodeConfig["confidential_nodes"] =
			flattenConfidentialNodes(config.ConfidentialNodes)
	}

	// Kubelet config
	if config.KubeletConfig != nil {
		nodeConfig["kubelet_config"] =
			flattenKubeletConfig(config.KubeletConfig)
	}

	// Linux node config
	if config.LinuxNodeConfig != nil {
		nodeConfig["linux_node_config"] =
			flattenLinuxNodeConfig(config.LinuxNodeConfig)
	}

	// Return as a slice with one element (map)
	return []interface{}{nodeConfig}
}

// Helper functions for nested structures
func flattenWorkloadMetadataConfig(config *container.WorkloadMetadataConfig) []interface{} {
	if config == nil {
		return nil
	}

	workloadMetadataConfig := make(map[string]interface{})
	workloadMetadataConfig["mode"] = config.Mode

	return []interface{}{workloadMetadataConfig}
}

func flattenShieldedInstanceConfig(config *container.ShieldedInstanceConfig) []interface{} {
	if config == nil {
		return nil
	}

	shieldedInstanceConfig := make(map[string]interface{})
	shieldedInstanceConfig["enable_secure_boot"] = config.EnableSecureBoot
	shieldedInstanceConfig["enable_integrity_monitoring"] =
		config.EnableIntegrityMonitoring

	return []interface{}{shieldedInstanceConfig}
}

func flattenAccelerators(accelerators []*container.AcceleratorConfig) []interface{} {
	if len(accelerators) == 0 {
		return nil
	}

	result := make([]interface{}, len(accelerators))
	for i, accelerator := range accelerators {
		acc := make(map[string]interface{})
		acc["accelerator_type"] = accelerator.AcceleratorType
		acc["accelerator_count"] = accelerator.AcceleratorCount
		acc["gpu_partition_size"] = accelerator.GpuPartitionSize

		result[i] = acc
	}

	return result
}

func flattenReservationAffinity(config *container.ReservationAffinity) []interface{} {
	if config == nil {
		return nil
	}

	reservationAffinity := make(map[string]interface{})
	reservationAffinity["consume_reservation_type"] =
		config.ConsumeReservationType

	if len(config.Key) > 0 && len(config.Values) > 0 {
		reservationAffinity["key"] = config.Key
		reservationAffinity["values"] = config.Values
	}

	return []interface{}{reservationAffinity}
}

func flattenConfidentialNodes(config *container.ConfidentialNodes) []interface{} {
	if config == nil {
		return nil
	}

	confidentialNodes := make(map[string]interface{})
	confidentialNodes["enabled"] = config.Enabled

	return []interface{}{confidentialNodes}
}

func flattenKubeletConfig(config *container.NodeKubeletConfig) []interface{} {
	if config == nil {
		return nil
	}

	kubeletConfig := make(map[string]interface{})

	if config.CpuManagerPolicy != "" {
		kubeletConfig["cpu_manager_policy"] = config.CpuManagerPolicy
	}

	if config.CpuCfsQuota {
		kubeletConfig["cpu_cfs_quota"] = config.CpuCfsQuota
	}

	if config.CpuCfsQuotaPeriod != "" {
		kubeletConfig["cpu_cfs_quota_period"] = config.CpuCfsQuotaPeriod
	}

	if config.PodPidsLimit != 0 {
		kubeletConfig["pod_pids_limit"] = config.PodPidsLimit
	}

	return []interface{}{kubeletConfig}
}

func flattenLinuxNodeConfig(config *container.LinuxNodeConfig) []interface{} {
	if config == nil {
		return nil
	}

	linuxNodeConfig := make(map[string]interface{})

	if config.Sysctls != nil {
		linuxNodeConfig["sysctls"] = config.Sysctls
	}

	return []interface{}{linuxNodeConfig}
}

func flattenIPAllocationPolicy(policy *container.IPAllocationPolicy) []interface{} {
	if policy == nil {
		return nil
	}

	ipAllocationPolicy := make(map[string]interface{})

	// Use IP aliases
	ipAllocationPolicy["use_ip_aliases"] = policy.UseIpAliases

	// Cluster secondary range name
	if policy.ClusterSecondaryRangeName != "" {
		ipAllocationPolicy["cluster_secondary_range_name"] =
			policy.ClusterSecondaryRangeName
	}

	// Services secondary range name
	if policy.ServicesSecondaryRangeName != "" {
		ipAllocationPolicy["services_secondary_range_name"] =
			policy.ServicesSecondaryRangeName
	}

	// Cluster IPv4 CIDR block
	if policy.ClusterIpv4CidrBlock != "" {
		ipAllocationPolicy["cluster_ipv4_cidr_block"] =
			policy.ClusterIpv4CidrBlock
	}

	// Services IPv4 CIDR block
	if policy.ServicesIpv4CidrBlock != "" {
		ipAllocationPolicy["services_ipv4_cidr_block"] =
			policy.ServicesIpv4CidrBlock
	}

	// Node IPv4 CIDR block
	if policy.NodeIpv4CidrBlock != "" {
		ipAllocationPolicy["node_ipv4_cidr_block"] = policy.NodeIpv4CidrBlock
	}

	// Create subnetwork
	if policy.CreateSubnetwork {
		ipAllocationPolicy["create_subnetwork"] = policy.CreateSubnetwork
	}

	// Subnetwork name
	if policy.SubnetworkName != "" {
		ipAllocationPolicy["subnetwork_name"] = policy.SubnetworkName
	}

	// Cluster IPv4 CIDR block
	if policy.TpuIpv4CidrBlock != "" {
		ipAllocationPolicy["tpu_ipv4_cidr_block"] = policy.TpuIpv4CidrBlock
	}

	// Stack type (IPv4, IPv4_IPv6)
	if policy.StackType != "" {
		ipAllocationPolicy["stack_type"] = policy.StackType
	}

	// IPv6 access type
	if policy.Ipv6AccessType != "" {
		ipAllocationPolicy["ipv6_access_type"] = policy.Ipv6AccessType
	}

	return []interface{}{ipAllocationPolicy}
}

func flattenAddonsConfig(config *container.AddonsConfig) []interface{} {
	if config == nil {
		return nil
	}

	addonsConfig := make(map[string]interface{})

	// HTTP Load Balancing
	if config.HttpLoadBalancing != nil {
		httpLoadBalancing := make(map[string]interface{})
		httpLoadBalancing["disabled"] = config.HttpLoadBalancing.Disabled
		addonsConfig["http_load_balancing"] = []interface{}{httpLoadBalancing}
	}

	// Horizontal Pod Autoscaling
	if config.HorizontalPodAutoscaling != nil {
		horizontalPodAutoscaling := make(map[string]interface{})
		horizontalPodAutoscaling["disabled"] =
			config.HorizontalPodAutoscaling.Disabled
		addonsConfig["horizontal_pod_autoscaling"] =
			[]interface{}{horizontalPodAutoscaling}
	}

	// Network Policy
	if config.NetworkPolicyConfig != nil {
		networkPolicyConfig := make(map[string]interface{})
		networkPolicyConfig["disabled"] = config.NetworkPolicyConfig.Disabled
		addonsConfig["network_policy_config"] =
			[]interface{}{networkPolicyConfig}
	}

	// CloudRun Config
	if config.CloudRunConfig != nil {
		cloudRunConfig := make(map[string]interface{})
		cloudRunConfig["disabled"] = config.CloudRunConfig.Disabled
		if config.CloudRunConfig.LoadBalancerType != "" {
			cloudRunConfig["load_balancer_type"] =
				config.CloudRunConfig.LoadBalancerType
		}
		addonsConfig["cloudrun_config"] = []interface{}{cloudRunConfig}
	}

	// DNS Cache Config
	if config.DnsCacheConfig != nil {
		dnsCacheConfig := make(map[string]interface{})
		dnsCacheConfig["enabled"] = config.DnsCacheConfig.Enabled
		addonsConfig["dns_cache_config"] = []interface{}{dnsCacheConfig}
	}

	// GcePersistentDiskCsiDriverConfig
	if config.GcePersistentDiskCsiDriverConfig != nil {
		gcePersistentDiskCsiDriverConfig := make(map[string]interface{})
		gcePersistentDiskCsiDriverConfig["enabled"] =
			config.GcePersistentDiskCsiDriverConfig.Enabled
		addonsConfig["gce_persistent_disk_csi_driver_config"] =
			[]interface{}{gcePersistentDiskCsiDriverConfig}
	}

	// GcpFilestoreCsiDriverConfig
	if config.GcpFilestoreCsiDriverConfig != nil {
		gcpFilestoreCsiDriverConfig := make(map[string]interface{})
		gcpFilestoreCsiDriverConfig["enabled"] =
			config.GcpFilestoreCsiDriverConfig.Enabled
		addonsConfig["gcp_filestore_csi_driver_config"] =
			[]interface{}{gcpFilestoreCsiDriverConfig}
	}

	// ConfigConnectorConfig
	if config.ConfigConnectorConfig != nil {
		configConnectorConfig := make(map[string]interface{})
		configConnectorConfig["enabled"] = config.ConfigConnectorConfig.Enabled
		addonsConfig["config_connector_config"] =
			[]interface{}{configConnectorConfig}
	}

	// GkeBackupAgentConfig
	if config.GkeBackupAgentConfig != nil {
		gkeBackupAgentConfig := make(map[string]interface{})
		gkeBackupAgentConfig["enabled"] = config.GkeBackupAgentConfig.Enabled
		addonsConfig["gke_backup_agent_config"] =
			[]interface{}{gkeBackupAgentConfig}
	}

	return []interface{}{addonsConfig}
}
