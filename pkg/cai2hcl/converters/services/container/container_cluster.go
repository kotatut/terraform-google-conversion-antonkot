package container

import (
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/cai2hcl/converters/utils"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/cai2hcl/models"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/caiasset"
	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	"google.golang.org/api/container/v1"
)

const ContainerClusterAssetType string = "container.googleapis.com/Cluster"
const ContainerClusterSchemaName string = "google_container_cluster"
const ContainerNodePoolSchemaName string = "google_container_node_pool"

// REMOVED: Default values const block is removed as default handling is disabled.

type ContainerClusterConverter struct {
	clusterName    string
	clusterSchema  map[string]*schema.Schema
	nodePoolSchema map[string]*schema.Schema
}

func NewContainerClusterConverter(provider *schema.Provider) models.Converter {
	clusterSchema, clusterOk := provider.ResourcesMap[ContainerClusterSchemaName]
	nodePoolSchema, nodePoolOk := provider.ResourcesMap[ContainerNodePoolSchemaName]

	if !clusterOk {
		fmt.Printf("Warning: Schema for %s not found in provider\n", ContainerClusterSchemaName)
	}
	if !nodePoolOk {
		fmt.Printf("Warning: Schema for %s not found in provider\n", ContainerNodePoolSchemaName)
	}

	var cs map[string]*schema.Schema
	if clusterOk && clusterSchema != nil {
		cs = clusterSchema.Schema
	}

	var nps map[string]*schema.Schema
	if nodePoolOk && nodePoolSchema != nil {
		nps = nodePoolSchema.Schema
	}

	return &ContainerClusterConverter{
		clusterName:    ContainerClusterSchemaName,
		clusterSchema:  cs,
		nodePoolSchema: nps,
	}
}

func (c *ContainerClusterConverter) Convert(asset *caiasset.Asset) ([]*models.TerraformResourceBlock, error) {
	if asset == nil {
		// Handle IAM policy conversion if needed, similar to Compute Instance converter
		// if asset.IAMPolicy != nil { ... }
		return nil, fmt.Errorf("asset is nil") // Adjusted error message
	}

	// Ensure resource data exists for cluster conversion
	if asset.Resource == nil || asset.Resource.Data == nil {
		// If only IAM policy exists, handle that - otherwise return error or empty list
		// For now, assume resource data is required for this converter's primary function
		return nil, fmt.Errorf("asset resource data is nil for cluster conversion")
	}

	project := utils.ParseFieldValue(asset.Name, "projects")

	// Try to parse location from either "zones" or "locations" or "regions"
	location := utils.ParseFieldValue(asset.Name, "locations")
	if location == "" {
		location = utils.ParseFieldValue(asset.Name, "zones")
	}
	if location == "" {
		location = utils.ParseFieldValue(asset.Name, "regions")
	}

	clusterName := utils.ParseFieldValue(asset.Name, "clusters")

	var cluster *container.Cluster
	if err := utils.DecodeJSON(asset.Resource.Data, &cluster); err != nil {
		return nil, fmt.Errorf("failed to decode cluster JSON: %w", err)
	}

	clusterBlock, err := c.convertClusterData(cluster, project, location, clusterName, cluster.NodePools)
	if err != nil {
		return nil, fmt.Errorf("failed to convert cluster data: %w", err)
	}

	blocks := []*models.TerraformResourceBlock{}
	if clusterBlock != nil {
		blocks = append(blocks, clusterBlock)
	} // Removed warning about minimal block

	// --- Node Pool Conversion ---
	// Keep the heuristic to decide if separate node pool resources are needed
	hasSeparateNodePools := false
	if len(cluster.NodePools) > 1 || (len(cluster.NodePools) == 1 && cluster.NodePools[0] != nil && cluster.NodePools[0].Name != "default-pool") {
		hasSeparateNodePools = true
	}

	if len(cluster.NodePools) > 0 {
		for _, nodePool := range cluster.NodePools {
			if nodePool == nil {
				continue
			}
			// Skip conversion of the default node pool if it's managed by the cluster block
			// (i.e., not setting remove_default_node_pool = true implicitly)
			isDefaultPool := nodePool.Name == "default-pool"
			// If it's the default pool AND we are NOT managing pools separately...
			// AND clusterBlock exists AND remove_default_node_pool is not explicitly set to true...
			// then skip creating a separate resource for it.
			removeDefaultPoolSet := false
			if clusterBlock != nil {
				// Check if remove_default_node_pool is explicitly true in the generated HCL data
				removeDefaultNodePoolAttr := clusterBlock.Value.GetAttr("remove_default_node_pool")

				// Check if the attribute exists, is not null, is a boolean, and is true
				if !removeDefaultNodePoolAttr.IsNull() && removeDefaultNodePoolAttr.Type() == cty.Bool {
					if removeDefaultNodePoolAttr.True() {
						removeDefaultPoolSet = true
					}
				}
			}

			if isDefaultPool && !hasSeparateNodePools && !removeDefaultPoolSet {
				fmt.Printf("Info: Skipping separate conversion of default node pool '%s' as it's managed by cluster block attributes.\n", nodePool.Name)
				continue
			}

			nodePoolBlock, err := c.convertNodePoolData(nodePool, cluster, project, location)
			if err != nil {
				// Changed from Printf to return error to be more explicit
				return nil, fmt.Errorf("failed to convert node pool %s: %w. Halting conversion.", nodePool.Name, err)
				// Alternatively, log warning and continue:
				// fmt.Printf("Warning: Failed to convert node pool %s: %v. Skipping.\n", nodePool.Name, err)
				// continue
			}
			if nodePoolBlock != nil {
				blocks = append(blocks, nodePoolBlock)
			}
		}
	}

	// Handle IAM policy conversion if present in the asset and needed
	// Similar to compute instance converter:
	// if asset.IAMPolicy != nil {
	//	 iamBlock, err := c.convertIAM(asset) // Assuming convertIAM exists
	//	 if err != nil {
	//		 return nil, err
	//	 }
	//	 blocks = append(blocks, iamBlock)
	// }

	return blocks, nil
}

// convertClusterData maps API response directly, minimal default omission
func (c *ContainerClusterConverter) convertClusterData(cluster *container.Cluster, project, location, clusterName string, nodePools []*container.NodePool) (*models.TerraformResourceBlock, error) {
	if cluster == nil {
		return nil, fmt.Errorf("cluster data is nil")
	}
	if c.clusterSchema == nil {
		fmt.Printf("Warning: Cluster schema is nil in converter for %s. Cannot generate HCL.\n", clusterName)
		return nil, nil
	}

	hclData := make(map[string]interface{})

	// --- Required & Core Fields ---
	hclData["name"] = clusterName
	hclData["location"] = location // Location derived from asset name

	// Always include project if available
	if project != "" {
		hclData["project"] = project
	}

	// --- Direct Mappings (Include if non-zero/non-empty/non-nil from API) ---
	if cluster.Description != "" {
		hclData["description"] = cluster.Description
	}

	// --- Heuristic: Default Node Pool Handling ---
	hasSeparateNodePools := false
	if len(nodePools) > 1 || (len(nodePools) == 1 && nodePools[0] != nil && nodePools[0].Name != "default-pool") {
		hasSeparateNodePools = true
	}
	if hasSeparateNodePools {
		// Explicitly set remove_default_node_pool = true if managing node pools separately
		hclData["remove_default_node_pool"] = true
		// Do NOT set initial_node_count or cluster-level node_config
	} else {
		// Manage default pool via cluster block
		// Set remove_default_node_pool = false (or omit, relying on TF default)
		hclData["remove_default_node_pool"] = false // Explicitly set false
		if cluster.InitialNodeCount > 0 {           // Keep check for > 0 as 0 might be invalid/meaningless
			hclData["initial_node_count"] = cluster.InitialNodeCount
		}
		// Include node_config block if it exists in the API response
		if flattened := flattenNodeConfig(cluster.NodeConfig); flattened != nil {
			hclData["node_config"] = flattened
		}
	}

	// --- Network Fields ---
	if cluster.Network != "" {
		// Use resource name or self-link based on provider preference (using name here)
		hclData["network"] = tpgresource.GetResourceNameFromSelfLink(cluster.Network)
		// Note: Removed comparison with "default"
	}

	if cluster.Subnetwork != "" {
		// Attempt to construct full path, otherwise use name/self-link
		if project != "" && strings.HasPrefix(cluster.Subnetwork, "projects/") {
			hclData["subnetwork"] = cluster.Subnetwork
		} else if project != "" {
			subnetName := tpgresource.GetResourceNameFromSelfLink(cluster.Subnetwork)
			region := location // Default to cluster location (might be zone or region)
			locationParts := strings.Split(location, "-")
			if len(locationParts) >= 2 { // Basic check for region/zone format
				// Attempt to construct region for subnetwork path (e.g., us-central1-a -> us-central1)
				// This might still need refinement for all location types.
				if len(locationParts) > 2 { // Likely a zone
					region = strings.Join(locationParts[:len(locationParts)-1], "-")
				}
			}
			hclData["subnetwork"] = fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s",
				project,
				region,
				subnetName)
		} else {
			hclData["subnetwork"] = tpgresource.GetResourceNameFromSelfLink(cluster.Subnetwork)
		}
	}

	// --- Nested Blocks (Flattened, Simplified) ---
	// Call flatten functions, include the result if non-nil (meaning API object existed)
	if flattened := flattenIPAllocationPolicy(cluster.IpAllocationPolicy); flattened != nil {
		hclData["ip_allocation_policy"] = flattened
	}

	// NOTE: Do NOT set "networking_mode" here. Let the TF provider infer it
	// based on the presence/absence of "ip_allocation_policy".

	// Network Config related fields
	if cluster.NetworkConfig != nil {
		if cluster.NetworkConfig.DatapathProvider != "" { // Include even if "unspecified" or "legacy"
			hclData["datapath_provider"] = cluster.NetworkConfig.DatapathProvider
		}
		// Include boolean flags directly
		hclData["enable_fqdn_network_policy"] = cluster.NetworkConfig.EnableFqdnNetworkPolicy
		hclData["enable_l4_ilb_subsetting"] = cluster.NetworkConfig.EnableL4ilbSubsetting
		hclData["enable_multi_networking"] = cluster.NetworkConfig.EnableMultiNetworking
		// Use correct field name based on v1 API struct if different from schema
		hclData["enable_intranode_visibility"] = cluster.NetworkConfig.EnableIntraNodeVisibility

		// Nested blocks under network_config
		if flattened := flattenDnsConfig(cluster.NetworkConfig.DnsConfig); flattened != nil {
			hclData["dns_config"] = flattened
		}
		if flattened := flattenServiceExternalIPsConfig(cluster.NetworkConfig.ServiceExternalIpsConfig); flattened != nil {
			hclData["service_external_ips_config"] = flattened
		}
		if flattened := flattenGatewayApiConfig(cluster.NetworkConfig.GatewayApiConfig); flattened != nil {
			hclData["gateway_api_config"] = flattened
		}
	}

	if cluster.DefaultMaxPodsConstraint != nil { // Include even if 0? Check schema if 0 is valid config. Assume yes for direct map.
		hclData["default_max_pods_per_node"] = cluster.DefaultMaxPodsConstraint.MaxPodsPerNode
	}

	if flattened := flattenNetworkPolicy(cluster.NetworkPolicy); flattened != nil {
		hclData["network_policy"] = flattened
	}

	// Logging / Monitoring: Include both service and config if present
	if cluster.LoggingService != "" {
		hclData["logging_service"] = cluster.LoggingService
	}
	if flattened := flattenLoggingConfig(cluster.LoggingConfig); flattened != nil {
		hclData["logging_config"] = flattened
	}
	if cluster.MonitoringService != "" {
		hclData["monitoring_service"] = cluster.MonitoringService
	}
	if flattened := flattenMonitoringConfig(cluster.MonitoringConfig); flattened != nil {
		hclData["monitoring_config"] = flattened
	}

	if flattened := flattenAddonsConfig(cluster.AddonsConfig); flattened != nil {
		hclData["addons_config"] = flattened
	}

	// Always include node_locations if present in API
	if len(cluster.Locations) > 0 {
		hclData["node_locations"] = cluster.Locations
	}

	// Always include resource_labels if present in API
	if len(cluster.ResourceLabels) > 0 {
		hclData["resource_labels"] = cluster.ResourceLabels
	}

	// Release Channel / Versions
	if flattened := flattenReleaseChannel(cluster.ReleaseChannel); flattened != nil {
		hclData["release_channel"] = flattened
	}
	// Set versions directly if present, don't try to omit based on release channel
	// Schema uses 'node_version', map from appropriate API field (e.g., CurrentNodeVersion)
	if cluster.CurrentNodeVersion != "" { // Or another relevant field if schema maps differently
		hclData["node_version"] = cluster.CurrentNodeVersion
	}

	// --- Boolean Flags (Direct Mapping) ---
	// Map directly from the API struct fields. Handle nils where necessary.
	if cluster.Autopilot != nil {
		hclData["enable_autopilot"] = cluster.Autopilot.Enabled
	}
	hclData["enable_kubernetes_alpha"] = cluster.EnableKubernetesAlpha
	hclData["enable_tpu"] = cluster.EnableTpu
	if cluster.LegacyAbac != nil {
		hclData["enable_legacy_abac"] = cluster.LegacyAbac.Enabled
	}
	if cluster.ShieldedNodes != nil {
		hclData["enable_shielded_nodes"] = cluster.ShieldedNodes.Enabled
	}

	// --- Other Nested Blocks ---
	if flattened := flattenMasterAuth(cluster.MasterAuth); flattened != nil {
		hclData["master_auth"] = flattened
	}
	if flattened := flattenPrivateClusterConfigAdapted(cluster.PrivateClusterConfig, cluster.NetworkConfig); flattened != nil {
		hclData["private_cluster_config"] = flattened
	}
	if flattened := flattenClusterAutoscaling(cluster.Autoscaling); flattened != nil {
		hclData["cluster_autoscaling"] = flattened
	}
	if flattened := flattenDatabaseEncryption(cluster.DatabaseEncryption); flattened != nil {
		hclData["database_encryption"] = flattened
	}
	if flattened := flattenVerticalPodAutoscaling(cluster.VerticalPodAutoscaling); flattened != nil {
		hclData["vertical_pod_autoscaling"] = flattened
	}
	if flattened := flattenBinaryAuthorization(cluster.BinaryAuthorization); flattened != nil {
		hclData["binary_authorization"] = flattened
	}
	if flattened := flattenSecurityPostureConfig(cluster.SecurityPostureConfig); flattened != nil {
		hclData["security_posture_config"] = flattened
	}
	if flattened := flattenCostManagementConfig(cluster.CostManagementConfig); flattened != nil {
		hclData["cost_management_config"] = flattened
	}
	if flattened := flattenIdentityServiceConfig(cluster.IdentityServiceConfig); flattened != nil {
		hclData["identity_service_config"] = flattened
	}
	if flattened := flattenMeshCertificates(cluster.MeshCertificates); flattened != nil {
		hclData["mesh_certificates"] = flattened
	}
	if flattened := flattenResourceUsageExportConfig(cluster.ResourceUsageExportConfig); flattened != nil {
		hclData["resource_usage_export_config"] = flattened
	}
	if flattened := flattenSecretManagerConfig(cluster.SecretManagerConfig); flattened != nil {
		hclData["secret_manager_config"] = flattened
	}
	if flattened := flattenWorkloadIdentityConfig(cluster.WorkloadIdentityConfig); flattened != nil {
		hclData["workload_identity_config"] = flattened
	}
	// flattenFleet is already omitted correctly.
	if flattened := flattenNodePoolDefaults(cluster.NodePoolDefaults); flattened != nil {
		hclData["node_pool_defaults"] = flattened
	}

	// Final conversion to cty.Value using the schema
	ctyVal, err := utils.MapToCtyValWithSchema(hclData, c.clusterSchema)
	if err != nil {
		return nil, fmt.Errorf("error converting cluster data for %s to cty.Value: %w", clusterName, err)
	}

	return &models.TerraformResourceBlock{
		Labels: []string{c.clusterName, clusterName},
		Value:  ctyVal,
	}, nil
}

// convertNodePoolData maps API response directly, minimal default omission
func (c *ContainerClusterConverter) convertNodePoolData(nodePool *container.NodePool, cluster *container.Cluster, project, location string) (*models.TerraformResourceBlock, error) {
	if nodePool == nil {
		return nil, fmt.Errorf("node pool data is nil")
	}
	if cluster == nil {
		return nil, fmt.Errorf("cluster context is nil for node pool")
	}
	if c.nodePoolSchema == nil {
		fmt.Printf("Warning: Node pool schema is nil in converter for %s. Cannot generate HCL.\n", nodePool.Name)
		return nil, nil
	}

	hclData := make(map[string]interface{})

	// --- Required & Core Fields ---
	hclData["name"] = nodePool.Name
	hclData["cluster"] = cluster.Name // Reference cluster by name

	// Always include location and project if available
	if location != "" {
		hclData["location"] = location
	}
	if project != "" {
		hclData["project"] = project
	}

	// --- Node Count / Autoscaling ---
	autoscalingBlock := flattenNodePoolAutoscaling(nodePool.Autoscaling) // Simplified flatten function
	if autoscalingBlock != nil {
		hclData["autoscaling"] = autoscalingBlock
		// Set initial_node_count if present, even with autoscaling (TF schema allows this)
		// Note: API often returns InitialNodeCount even with autoscaling enabled.
		hclData["initial_node_count"] = nodePool.InitialNodeCount // Map directly
	} else {
		// No autoscaling block, set node_count directly from InitialNodeCount
		// Assuming InitialNodeCount reflects the desired count when autoscaling is off.
		hclData["node_count"] = nodePool.InitialNodeCount // Map directly
	}

	// --- Nested Blocks (Flattened, Simplified) ---
	if flattened := flattenNodeConfig(nodePool.Config); flattened != nil {
		hclData["node_config"] = flattened
	}
	if flattened := flattenNodeManagement(nodePool.Management); flattened != nil {
		hclData["management"] = flattened
	}

	// Max Pods Constraint
	if nodePool.MaxPodsConstraint != nil {
		hclData["max_pods_per_node"] = nodePool.MaxPodsConstraint.MaxPodsPerNode // Map directly
	}

	if flattened := flattenNodeNetworkConfig(nodePool.NetworkConfig); flattened != nil {
		hclData["network_config"] = flattened
	}
	if flattened := flattenNodePoolUpgradeSettings(nodePool.UpgradeSettings); flattened != nil {
		hclData["upgrade_settings"] = flattened
	}

	// Version - map directly if present
	if nodePool.Version != "" {
		hclData["version"] = nodePool.Version
	}

	if flattened := flattenPlacementPolicy(nodePool.PlacementPolicy); flattened != nil {
		hclData["placement_policy"] = flattened
	}

	// Node Locations - map directly if present
	if len(nodePool.Locations) > 0 {
		hclData["node_locations"] = nodePool.Locations
	}

	// Final conversion to cty.Value using the schema
	ctyVal, err := utils.MapToCtyValWithSchema(hclData, c.nodePoolSchema)
	if err != nil {
		return nil, fmt.Errorf("error converting node pool %s data to cty.Value: %w", nodePool.Name, err)
	}

	return &models.TerraformResourceBlock{
		Labels: []string{ContainerNodePoolSchemaName, nodePool.Name},
		Value:  ctyVal,
	}, nil
}

// --- FLATTEN FUNCTIONS (Simplified: Direct Mapping, No Default Omission) ---

// flattenNodeConfig maps directly, minimal default checks.
func flattenNodeConfig(config *container.NodeConfig) []interface{} {
	if config == nil {
		return nil
	}
	nodeConfig := make(map[string]interface{})

	// Map fields directly if they are non-zero/non-empty/non-nil in the API response
	if config.MachineType != "" {
		nodeConfig["machine_type"] = config.MachineType
	}
	if config.DiskSizeGb > 0 { // Keep basic check for >0, as 0 might be invalid
		nodeConfig["disk_size_gb"] = config.DiskSizeGb
	}
	if config.DiskType != "" {
		nodeConfig["disk_type"] = config.DiskType
	}
	if len(config.OauthScopes) > 0 {
		nodeConfig["oauth_scopes"] = config.OauthScopes
	}
	if config.ServiceAccount != "" {
		// Map the service account name/email directly
		nodeConfig["service_account"] = config.ServiceAccount
	}
	if len(config.Metadata) > 0 {
		nodeConfig["metadata"] = config.Metadata
	}
	if config.ImageType != "" {
		nodeConfig["image_type"] = config.ImageType
	}
	if len(config.Labels) > 0 {
		nodeConfig["labels"] = config.Labels
	}
	if config.ResourceLabels != nil && len(config.ResourceLabels) > 0 {
		nodeConfig["resource_labels"] = config.ResourceLabels
	}
	if config.LocalSsdCount > 0 { // Keep basic check for >0
		nodeConfig["local_ssd_count"] = config.LocalSsdCount
	}
	if len(config.Tags) > 0 {
		nodeConfig["tags"] = config.Tags
	}
	// Map booleans directly
	nodeConfig["preemptible"] = config.Preemptible
	nodeConfig["spot"] = config.Spot

	if config.MinCpuPlatform != "" {
		nodeConfig["min_cpu_platform"] = config.MinCpuPlatform
	}

	// --- Nested Blocks --- Call simplified flatteners
	if flattened := flattenWorkloadMetadataConfig(config.WorkloadMetadataConfig); flattened != nil {
		nodeConfig["workload_metadata_config"] = flattened
	}
	if flattened := flattenShieldedInstanceConfig(config.ShieldedInstanceConfig); flattened != nil {
		nodeConfig["shielded_instance_config"] = flattened
	}
	if flattened := flattenAccelerators(config.Accelerators); flattened != nil {
		nodeConfig["guest_accelerator"] = flattened // TF uses guest_accelerator
	}
	if flattened := flattenReservationAffinity(config.ReservationAffinity); flattened != nil {
		nodeConfig["reservation_affinity"] = flattened
	}
	if flattened := flattenConfidentialNodes(config.ConfidentialNodes); flattened != nil {
		nodeConfig["confidential_nodes"] = flattened
	}
	if flattened := flattenKubeletConfig(config.KubeletConfig); flattened != nil {
		nodeConfig["kubelet_config"] = flattened
	}
	if flattened := flattenLinuxNodeConfig(config.LinuxNodeConfig); flattened != nil {
		nodeConfig["linux_node_config"] = flattened
	}
	if flattened := flattenGvnic(config.Gvnic); flattened != nil {
		nodeConfig["gvnic"] = flattened
	}
	// TODO: Add simplified flatten calls for other nested blocks if needed
	// (EphemeralStorage, Nvme, SecondaryDisks, Gcfs, Windows, SoleTenant, HostMaintenance, FastSocket etc.)

	if config.BootDiskKmsKey != "" {
		nodeConfig["boot_disk_kms_key"] = config.BootDiskKmsKey
	}

	// Taints: Use existing flatten logic which handles empty list
	if flattened := flattenNodeTaints(config.Taints); flattened != nil {
		nodeConfig["taint"] = flattened // TF uses taint
	}

	// resource_manager_tags: Map directly if present
	if config.ResourceManagerTags != nil && len(config.ResourceManagerTags.Tags) > 0 {
		nodeConfig["resource_manager_tags"] = config.ResourceManagerTags.Tags
	}

	// Map other direct fields if they exist in the v1.NodeConfig struct
	// Ensure field names match the actual struct definition
	// nodeConfig["enable_confidential_storage"] = config.EnableConfidentialStorage
	// if config.LocalSsdEncryptionMode != "" { nodeConfig["local_ssd_encryption_mode"] = config.LocalSsdEncryptionMode }
	// if config.MaxRunDuration != "" { nodeConfig["max_run_duration"] = config.MaxRunDuration }

	// Return the block if the input config was not nil and the map is not empty
	if len(nodeConfig) == 0 {
		return nil
	}
	return []interface{}{nodeConfig}
}

// flattenWorkloadMetadataConfig: Simplified direct mapping
func flattenWorkloadMetadataConfig(config *container.WorkloadMetadataConfig) []interface{} {
	if config == nil {
		return nil
	}
	// Map directly, do not check against defaultWlcMode or "MODE_UNSPECIFIED"
	if config.Mode == "" { // Only omit if mode is genuinely empty string
		return nil
	}
	return []interface{}{map[string]interface{}{"mode": config.Mode}}
}

// flattenShieldedInstanceConfig: Simplified direct mapping
func flattenShieldedInstanceConfig(config *container.ShieldedInstanceConfig) []interface{} {
	if config == nil {
		return nil
	}
	sic := make(map[string]interface{})
	// Map booleans directly, do not check against defaults
	sic["enable_secure_boot"] = config.EnableSecureBoot
	sic["enable_integrity_monitoring"] = config.EnableIntegrityMonitoring

	// Only return block if input config was not nil
	return []interface{}{sic}
}

// flattenAccelerators: Simplified direct mapping
func flattenAccelerators(accelerators []*container.AcceleratorConfig) []interface{} {
	if len(accelerators) == 0 {
		return nil
	}
	result := make([]interface{}, 0, len(accelerators))
	for _, acc := range accelerators {
		if acc == nil {
			continue
		}
		data := make(map[string]interface{})
		// Map required fields directly
		data["accelerator_type"] = acc.AcceleratorType
		data["accelerator_count"] = acc.AcceleratorCount
		// Map optional fields directly if present
		if acc.GpuPartitionSize != "" {
			data["gpu_partition_size"] = acc.GpuPartitionSize
		}
		// Call simplified nested flatteners
		if flattened := flattenGpuSharingConfig(acc.GpuSharingConfig); flattened != nil {
			data["gpu_sharing_config"] = flattened
		}
		if flattened := flattenGpuDriverInstallationConfig(acc.GpuDriverInstallationConfig); flattened != nil {
			data["gpu_driver_installation_config"] = flattened
		}
		result = append(result, data)
	}
	if len(result) == 0 { // Possible if all acc were nil
		return nil
	}
	return result
}

// flattenGpuSharingConfig: Simplified direct mapping
func flattenGpuSharingConfig(config *container.GPUSharingConfig) []interface{} {
	if config == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map fields directly, do not check against defaults or "UNSPECIFIED"
	if config.MaxSharedClientsPerGpu > 0 { // Keep basic check > 0
		data["max_shared_clients_per_gpu"] = config.MaxSharedClientsPerGpu
	}
	if config.GpuSharingStrategy != "" {
		data["gpu_sharing_strategy"] = config.GpuSharingStrategy
	}
	if len(data) == 0 { // Return nil if neither field was set meaningfully
		return nil
	}
	return []interface{}{data}
}

// flattenGpuDriverInstallationConfig: Simplified direct mapping
func flattenGpuDriverInstallationConfig(config *container.GPUDriverInstallationConfig) []interface{} {
	if config == nil {
		return nil
	}
	// Map directly, do not check against "UNSPECIFIED"
	if config.GpuDriverVersion == "" {
		return nil // Omit only if empty string
	}
	return []interface{}{map[string]interface{}{"gpu_driver_version": config.GpuDriverVersion}}
}

// flattenReservationAffinity: Simplified direct mapping, but keep logic for SPECIFIC_RESERVATION
func flattenReservationAffinity(config *container.ReservationAffinity) []interface{} {
	if config == nil {
		return nil
	}
	// Map type directly, do not check against defaultReservationType or "UNSPECIFIED"
	if config.ConsumeReservationType == "" {
		return nil // Omit only if empty
	}

	ra := make(map[string]interface{})
	ra["consume_reservation_type"] = config.ConsumeReservationType

	// Keep logic specific to SPECIFIC_RESERVATION as it requires key/values
	if config.ConsumeReservationType == "SPECIFIC_RESERVATION" {
		if config.Key != "" {
			ra["key"] = config.Key
		} else {
			// Warning remains valid if type is SPECIFIC but key missing
			fmt.Printf("Warning: ReservationAffinity type is SPECIFIC_RESERVATION but Key is missing. Omitting block.\n")
			return nil
		}
		// Map values directly if present
		if len(config.Values) > 0 {
			ra["values"] = config.Values
		}
	}
	return []interface{}{ra}
}

// flattenConfidentialNodes: Simplified direct mapping
func flattenConfidentialNodes(config *container.ConfidentialNodes) []interface{} {
	if config == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": config.Enabled}}
}

// flattenKubeletConfig: Simplified direct mapping
func flattenKubeletConfig(config *container.NodeKubeletConfig) []interface{} {
	if config == nil {
		return nil
	}
	kc := make(map[string]interface{})
	// Map fields directly if present/non-zero/non-default-zero-value
	kc["insecure_kubelet_readonly_port_enabled"] = config.InsecureKubeletReadonlyPortEnabled

	if config.CpuManagerPolicy != "" {
		kc["cpu_manager_policy"] = config.CpuManagerPolicy // Do not check against defaultKubeletCpuPolicy
	}
	kc["cpu_cfs_quota"] = config.CpuCfsQuota
	if config.CpuCfsQuotaPeriod != "" {
		kc["cpu_cfs_quota_period"] = config.CpuCfsQuotaPeriod
	}
	if config.PodPidsLimit != 0 {
		kc["pod_pids_limit"] = config.PodPidsLimit
	}
	// TODO: Add direct mapping for container log/image GC fields if needed

	if len(kc) == 0 {
		return nil
	}
	return []interface{}{kc}
}

// flattenLinuxNodeConfig: Simplified direct mapping
func flattenLinuxNodeConfig(config *container.LinuxNodeConfig) []interface{} {
	if config == nil {
		return nil
	}
	lnc := make(map[string]interface{})
	// Map directly if present/non-empty
	if config.Sysctls != nil && len(config.Sysctls) > 0 {
		lnc["sysctls"] = config.Sysctls
	}
	if config.CgroupMode != "" { // Do not check against defaultLinuxCgroupMode or "UNSPECIFIED"
		lnc["cgroup_mode"] = config.CgroupMode
	}
	// TODO: Add direct mapping for hugepages_config if needed

	if len(lnc) == 0 {
		return nil
	}
	return []interface{}{lnc}
}

// flattenNodeTaints: Keep existing logic - already filters empty/invalid effect
func flattenNodeTaints(taints []*container.NodeTaint) []interface{} {
	if len(taints) == 0 {
		return nil
	}
	result := make([]interface{}, 0, len(taints))
	for _, taint := range taints {
		if taint == nil {
			continue
		}
		// Keep check for invalid effect
		if taint.Effect == "" || taint.Effect == "EFFECT_UNSPECIFIED" {
			continue
		}
		t := make(map[string]interface{})
		t["key"] = taint.Key
		t["value"] = taint.Value
		t["effect"] = taint.Effect
		result = append(result, t)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// flattenGvnic: Simplified direct mapping
func flattenGvnic(config *container.VirtualNIC) []interface{} {
	if config == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": config.Enabled}}
}

// flattenIPAllocationPolicy: Simplified direct mapping
func flattenIPAllocationPolicy(policy *container.IPAllocationPolicy) []interface{} {
	if policy == nil {
		return nil
	}
	ipa := make(map[string]interface{})
	// Map fields directly if non-empty / non-zero / non-default-zero-value
	if policy.ClusterSecondaryRangeName != "" {
		ipa["cluster_secondary_range_name"] = policy.ClusterSecondaryRangeName
	}
	if policy.ServicesSecondaryRangeName != "" {
		ipa["services_secondary_range_name"] = policy.ServicesSecondaryRangeName
	}
	if policy.ClusterIpv4CidrBlock != "" {
		ipa["cluster_ipv4_cidr_block"] = policy.ClusterIpv4CidrBlock
	}
	if policy.ServicesIpv4CidrBlock != "" {
		ipa["services_ipv4_cidr_block"] = policy.ServicesIpv4CidrBlock
	}
	// Map booleans directly
	ipa["create_subnetwork"] = policy.CreateSubnetwork
	if policy.SubnetworkName != "" {
		ipa["subnetwork_name"] = policy.SubnetworkName
	}
	if policy.TpuIpv4CidrBlock != "" {
		ipa["tpu_ipv4_cidr_block"] = policy.TpuIpv4CidrBlock
	}
	// Map StackType directly, do not check against default or "UNSPECIFIED"
	if policy.StackType != "" {
		ipa["stack_type"] = policy.StackType
	}
	// Map nested blocks directly if present
	if policy.AdditionalPodRangesConfig != nil && len(policy.AdditionalPodRangesConfig.PodRangeNames) > 0 {
		addlConfig := map[string]interface{}{"pod_range_names": policy.AdditionalPodRangesConfig.PodRangeNames}
		ipa["additional_pod_ranges_config"] = []interface{}{addlConfig}
	}
	if policy.PodCidrOverprovisionConfig != nil {
		overprovisionConfig := map[string]interface{}{"disable": policy.PodCidrOverprovisionConfig.Disable}
		ipa["pod_cidr_overprovision_config"] = []interface{}{overprovisionConfig}
	}

	// Return block if input policy was not nil (even if empty, presence implies VPC-native)
	return []interface{}{ipa}
}

// flattenAddonsConfig: Simplified direct mapping
func flattenAddonsConfig(config *container.AddonsConfig) []interface{} {
	if config == nil {
		return nil
	}
	addons := make(map[string]interface{})

	// For each addon, if the config object exists in API, create the HCL block and map directly
	if config.HttpLoadBalancing != nil {
		addons["http_load_balancing"] = []interface{}{map[string]interface{}{
			"disabled": config.HttpLoadBalancing.Disabled,
		}}
	}
	if config.HorizontalPodAutoscaling != nil {
		addons["horizontal_pod_autoscaling"] = []interface{}{map[string]interface{}{
			"disabled": config.HorizontalPodAutoscaling.Disabled,
		}}
	}
	if config.NetworkPolicyConfig != nil {
		addons["network_policy_config"] = []interface{}{map[string]interface{}{
			"disabled": config.NetworkPolicyConfig.Disabled,
		}}
	}
	if config.CloudRunConfig != nil {
		crc := map[string]interface{}{"disabled": config.CloudRunConfig.Disabled}
		if config.CloudRunConfig.LoadBalancerType != "" {
			crc["load_balancer_type"] = config.CloudRunConfig.LoadBalancerType
		}
		addons["cloudrun_config"] = []interface{}{crc}
	}
	if config.DnsCacheConfig != nil {
		addons["dns_cache_config"] = []interface{}{map[string]interface{}{
			"enabled": config.DnsCacheConfig.Enabled,
		}}
	}
	if config.GcePersistentDiskCsiDriverConfig != nil {
		addons["gce_persistent_disk_csi_driver_config"] = []interface{}{map[string]interface{}{
			"enabled": config.GcePersistentDiskCsiDriverConfig.Enabled,
		}}
	}
	if config.GcpFilestoreCsiDriverConfig != nil {
		addons["gcp_filestore_csi_driver_config"] = []interface{}{map[string]interface{}{
			"enabled": config.GcpFilestoreCsiDriverConfig.Enabled,
		}}
	}
	if config.ConfigConnectorConfig != nil {
		addons["config_connector_config"] = []interface{}{map[string]interface{}{
			"enabled": config.ConfigConnectorConfig.Enabled,
		}}
	}
	if config.GkeBackupAgentConfig != nil {
		addons["gke_backup_agent_config"] = []interface{}{map[string]interface{}{
			"enabled": config.GkeBackupAgentConfig.Enabled,
		}}
	}
	if config.GcsFuseCsiDriverConfig != nil {
		addons["gcs_fuse_csi_driver_config"] = []interface{}{map[string]interface{}{
			"enabled": config.GcsFuseCsiDriverConfig.Enabled,
		}}
	}
	if config.StatefulHaConfig != nil {
		addons["stateful_ha_config"] = []interface{}{map[string]interface{}{
			"enabled": config.StatefulHaConfig.Enabled,
		}}
	}
	if config.RayOperatorConfig != nil {
		rayConfig := map[string]interface{}{"enabled": config.RayOperatorConfig.Enabled}
		if config.RayOperatorConfig.RayClusterLoggingConfig != nil {
			rayConfig["ray_cluster_logging_config"] = []interface{}{map[string]interface{}{
				"enabled": config.RayOperatorConfig.RayClusterLoggingConfig.Enabled,
			}}
		}
		if config.RayOperatorConfig.RayClusterMonitoringConfig != nil {
			rayConfig["ray_cluster_monitoring_config"] = []interface{}{map[string]interface{}{
				"enabled": config.RayOperatorConfig.RayClusterMonitoringConfig.Enabled,
			}}
		}
		addons["ray_operator_config"] = []interface{}{rayConfig}
	}
	if config.ParallelstoreCsiDriverConfig != nil {
		addons["parallelstore_csi_driver_config"] = []interface{}{map[string]interface{}{
			"enabled": config.ParallelstoreCsiDriverConfig.Enabled,
		}}
	}

	if len(addons) == 0 {
		return nil
	}
	return []interface{}{addons}
}

// flattenNetworkPolicy: Simplified direct mapping
func flattenNetworkPolicy(policy *container.NetworkPolicy) []interface{} {
	if policy == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map directly, do not omit block if enabled=false
	data["enabled"] = policy.Enabled
	// Map provider directly if present, do not check against default or "UNSPECIFIED"
	if policy.Provider != "" {
		data["provider"] = policy.Provider
	}
	// Return block if input policy was not nil
	return []interface{}{data}
}

// flattenNodePoolAutoscaling: Simplified direct mapping
func flattenNodePoolAutoscaling(autoscaling *container.NodePoolAutoscaling) []interface{} {
	if autoscaling == nil {
		return nil
	}
	// If autoscaling is explicitly disabled in the API object, omit the block
	// This assumes TF provider handles node_count correctly when autoscaling block absent.
	if !autoscaling.Enabled {
		return nil
	}

	data := make(map[string]interface{})
	// Map required fields directly (assuming Enabled=true here)
	data["min_node_count"] = autoscaling.MinNodeCount
	data["max_node_count"] = autoscaling.MaxNodeCount

	// Map optional fields directly if present/non-zero
	if autoscaling.TotalMinNodeCount > 0 {
		data["total_min_node_count"] = autoscaling.TotalMinNodeCount
	}
	if autoscaling.TotalMaxNodeCount > 0 {
		data["total_max_node_count"] = autoscaling.TotalMaxNodeCount
	}
	// Map location policy directly, do not check against default
	if autoscaling.LocationPolicy != "" {
		data["location_policy"] = autoscaling.LocationPolicy
	}
	// Map Autoscaling Profile directly if exists and non-empty in API struct
	// Assuming field name is AutoscalingProfile in v1 struct
	// if autoscaling.AutoscalingProfile != "" {
	//	 data["autoscaling_profile"] = autoscaling.AutoscalingProfile
	// }

	// Always return block if Enabled=true in API
	return []interface{}{data}
}

// flattenNodeManagement: Simplified direct mapping
func flattenNodeManagement(mgmt *container.NodeManagement) []interface{} {
	if mgmt == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map directly, do not assume true defaults and omit only if false
	data["auto_repair"] = mgmt.AutoRepair
	data["auto_upgrade"] = mgmt.AutoUpgrade

	// mgmt.UpgradeOptions is output-only, skip.

	// Return block if input mgmt was not nil
	return []interface{}{data}
}

// flattenNodePoolUpgradeSettings: Simplified direct mapping
func flattenNodePoolUpgradeSettings(settings *container.UpgradeSettings) []interface{} {
	if settings == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map fields directly, do not check against defaults (1, 0, "SURGE")
	data["max_surge"] = settings.MaxSurge             // Map even if 0 or 1
	data["max_unavailable"] = settings.MaxUnavailable // Map even if 0 or 1

	if settings.Strategy != "" { // Map directly, don't check against default or "UNSPECIFIED"
		data["strategy"] = settings.Strategy
	}
	// Call simplified nested flattener
	if flattened := flattenBlueGreenSettings(settings.BlueGreenSettings); flattened != nil {
		data["blue_green_settings"] = flattened
	}

	// Return nil only if map is empty AND blueGreen was also nil
	// This avoids returning an empty block like `upgrade_settings {}` if nothing was configured.
	if len(data) == 0 && settings.BlueGreenSettings == nil {
		return nil
	}
	return []interface{}{data}
}

// flattenBlueGreenSettings: Simplified, keep required field logic
func flattenBlueGreenSettings(settings *container.BlueGreenSettings) []interface{} {
	if settings == nil {
		return nil
	}
	// Keep check for required StandardRolloutPolicy
	if settings.StandardRolloutPolicy == nil {
		fmt.Println("Warning: BlueGreenSettings present but StandardRolloutPolicy block is missing. Omitting BlueGreen block.")
		return nil
	}

	data := make(map[string]interface{})
	srp := settings.StandardRolloutPolicy
	standardRolloutPolicy := make(map[string]interface{})
	hasBatchSize := false

	// Keep ExactlyOneOf logic - map whichever is present
	if srp.BatchPercentage > 0.0 {
		standardRolloutPolicy["batch_percentage"] = srp.BatchPercentage
		hasBatchSize = true
		if srp.BatchNodeCount > 0 {
			fmt.Printf("Warning: Both BatchPercentage (%f) and BatchNodeCount (%d) are non-zero in StandardRolloutPolicy. Using Percentage.\n", srp.BatchPercentage, srp.BatchNodeCount)
		}
	} else if srp.BatchNodeCount > 0 {
		standardRolloutPolicy["batch_node_count"] = srp.BatchNodeCount
		hasBatchSize = true
	}

	// If neither batch size is valid, the block is invalid according to schema
	if !hasBatchSize {
		fmt.Println("Warning: BlueGreen StandardRolloutPolicy has no valid non-zero batch size (Percentage or NodeCount). Omitting BlueGreen block.")
		return nil
	}

	// Batch Soak Duration: Map directly, do not check against "0s" default
	if srp.BatchSoakDuration != "" {
		standardRolloutPolicy["batch_soak_duration"] = srp.BatchSoakDuration
	}

	data["standard_rollout_policy"] = []interface{}{standardRolloutPolicy}

	// Node Pool Soak Duration: Map directly, do not check against "0s" default
	if settings.NodePoolSoakDuration != "" {
		data["node_pool_soak_duration"] = settings.NodePoolSoakDuration
	}

	// Return block if input settings was not nil and valid
	return []interface{}{data}
}

// flattenMaxPodsConstraint: Simplified direct mapping
func flattenMaxPodsConstraint(constraint *container.MaxPodsConstraint) []interface{} {
	if constraint == nil {
		return nil
	}
	// Map directly. Assume schema validation handles <= 0 if necessary.
	return []interface{}{map[string]interface{}{"max_pods_per_node": constraint.MaxPodsPerNode}}
}

// flattenNodeNetworkConfig: Simplified direct mapping
func flattenNodeNetworkConfig(config *container.NodeNetworkConfig) []interface{} {
	if config == nil {
		return nil
	}
	data := make(map[string]interface{})

	// Map fields directly if non-empty / non-zero / non-default-zero-value
	if config.PodRange != "" {
		data["pod_range"] = config.PodRange
	}
	if config.PodIpv4CidrBlock != "" {
		data["pod_ipv4_cidr_block"] = config.PodIpv4CidrBlock
	}
	// Map booleans directly
	data["create_pod_range"] = config.CreatePodRange

	if config.NetworkPerformanceConfig != nil {
		// Map directly, do not check against "TIER_UNSPECIFIED"
		if config.NetworkPerformanceConfig.TotalEgressBandwidthTier != "" {
			perfConfig := map[string]interface{}{"total_egress_bandwidth_tier": config.NetworkPerformanceConfig.TotalEgressBandwidthTier}
			data["network_performance_config"] = []interface{}{perfConfig}
		}
	}
	if config.PodCidrOverprovisionConfig != nil {
		overprovisionConfig := map[string]interface{}{"disable": config.PodCidrOverprovisionConfig.Disable}
		data["pod_cidr_overprovision_config"] = []interface{}{overprovisionConfig}
	}

	// Map multi-networking configs directly if present
	if len(config.AdditionalNodeNetworkConfigs) > 0 {
		addlNodeNets := make([]interface{}, 0, len(config.AdditionalNodeNetworkConfigs))
		for _, nc := range config.AdditionalNodeNetworkConfigs {
			if nc != nil {
				m := make(map[string]interface{})
				if nc.Network != "" {
					m["network"] = nc.Network
				}
				if nc.Subnetwork != "" {
					m["subnetwork"] = nc.Subnetwork
				}
				if len(m) > 0 {
					addlNodeNets = append(addlNodeNets, m)
				}
			}
		}
		if len(addlNodeNets) > 0 {
			data["additional_node_network_config"] = addlNodeNets
		}
	}
	if len(config.AdditionalPodNetworkConfigs) > 0 {
		addlPodNets := make([]interface{}, 0, len(config.AdditionalPodNetworkConfigs))
		for _, nc := range config.AdditionalPodNetworkConfigs {
			if nc != nil {
				m := make(map[string]interface{})
				if nc.Subnetwork != "" {
					m["subnetwork"] = nc.Subnetwork
				}
				if nc.SecondaryPodRange != "" {
					m["secondary_pod_range"] = nc.SecondaryPodRange
				}
				// Map max_pods_per_node directly if pointer is non-nil
				if nc.MaxPodsPerNode != nil {
					m["max_pods_per_node"] = *nc.MaxPodsPerNode
				}
				if len(m) > 0 {
					addlPodNets = append(addlPodNets, m)
				}
			}
		}
		if len(addlPodNets) > 0 {
			data["additional_pod_network_config"] = addlPodNets
		}
	}

	if len(data) == 0 {
		return nil
	}
	return []interface{}{data}
}

// flattenPlacementPolicy: Simplified direct mapping
func flattenPlacementPolicy(policy *container.PlacementPolicy) []interface{} {
	if policy == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map directly, do not check against "TYPE_UNSPECIFIED"
	if policy.Type != "" {
		data["type"] = policy.Type
	}
	if policy.TpuTopology != "" {
		data["tpu_topology"] = policy.TpuTopology
	}
	if policy.PolicyName != "" {
		data["policy_name"] = policy.PolicyName
	}
	if len(data) == 0 {
		return nil
	}
	return []interface{}{data}
}

// flattenMasterAuth: Keep existing logic (only include block if non-default cert issuing enabled)
func flattenMasterAuth(auth *container.MasterAuth) []interface{} {
	// This block in TF primarily controls cert issuing and exposes computed certs.
	// Keep the logic to only include if issue_client_certificate=true, as false is the default
	// and the other fields are computed/sensitive.
	if auth == nil || auth.ClientCertificateConfig == nil || !auth.ClientCertificateConfig.IssueClientCertificate {
		return nil
	}
	ccc := map[string]interface{}{"issue_client_certificate": true}
	ma := map[string]interface{}{"client_certificate_config": []interface{}{ccc}}
	// Do NOT include client_certificate, client_key, cluster_ca_certificate
	return []interface{}{ma}
}

// flattenPrivateClusterConfigAdapted: Keep structural adaptation, remove internal default checks.
func flattenPrivateClusterConfigAdapted(config *container.PrivateClusterConfig, netConfig *container.NetworkConfig /* netConfig is unused in this corrected version */) []interface{} {
	// If the PrivateClusterConfig struct itself is nil in the API response,
	// then there's no private cluster configuration to flatten.
	if config == nil {
		return nil
	}

	// If the config struct exists, we create the HCL block.
	pcc := make(map[string]interface{})

	// Map enable_private_nodes directly from the PrivateClusterConfig struct.
	// The field exists here in the v1 API.
	pcc["enable_private_nodes"] = config.EnablePrivateNodes

	// Map other values directly from PrivateClusterConfig if present
	pcc["enable_private_endpoint"] = config.EnablePrivateEndpoint // Map boolean directly

	if config.MasterIpv4CidrBlock != "" {
		pcc["master_ipv4_cidr_block"] = config.MasterIpv4CidrBlock
	}

	if config.MasterGlobalAccessConfig != nil {
		// Map directly, assuming 'Enabled' exists on MasterGlobalAccessConfig
		mgac := map[string]interface{}{"enabled": config.MasterGlobalAccessConfig.Enabled}
		pcc["master_global_access_config"] = []interface{}{mgac}
	}

	if config.PrivateEndpointSubnetwork != "" {
		pcc["private_endpoint_subnetwork"] = config.PrivateEndpointSubnetwork
	}
	// Note: peering_name, private_endpoint, public_endpoint are computed, so not mapped here.

	// Return the block since config was not nil.
	return []interface{}{pcc}
}

// flattenReleaseChannel: Simplified direct mapping
func flattenReleaseChannel(rc *container.ReleaseChannel) []interface{} {
	if rc == nil {
		return nil
	}
	// Map directly, do not check against defaultReleaseChannel or "UNSPECIFIED"
	if rc.Channel == "" {
		return nil
	}
	return []interface{}{map[string]interface{}{"channel": rc.Channel}}
}

// flattenLoggingConfig: Simplified direct mapping
func flattenLoggingConfig(config *container.LoggingConfig) []interface{} {
	if config == nil || config.ComponentConfig == nil || len(config.ComponentConfig.EnableComponents) == 0 {
		// If no components specified, return nil (don't create empty block)
		return nil
	}
	// Map directly if components are present
	return []interface{}{map[string]interface{}{
		"enable_components": config.ComponentConfig.EnableComponents,
	}}
}

// flattenMonitoringConfig: Simplified direct mapping
func flattenMonitoringConfig(config *container.MonitoringConfig) []interface{} {
	if config == nil {
		return nil
	}
	mc := make(map[string]interface{})
	hasConfig := false // Track if any data is actually added

	if config.ComponentConfig != nil && len(config.ComponentConfig.EnableComponents) > 0 {
		mc["enable_components"] = config.ComponentConfig.EnableComponents
		hasConfig = true
	}

	if config.ManagedPrometheusConfig != nil {
		mpc := map[string]interface{}{"enabled": config.ManagedPrometheusConfig.Enabled} // Map directly
		// Handle AutoMonitoringConfig if API/schema supports it and field exists
		// if config.ManagedPrometheusConfig.AutoMonitoringConfig != nil { ... }
		mc["managed_prometheus"] = []interface{}{mpc}
		hasConfig = true
	}

	if config.AdvancedDatapathObservabilityConfig != nil {
		adoc := make(map[string]interface{})
		// Map fields directly
		adoc["enable_metrics"] = config.AdvancedDatapathObservabilityConfig.EnableMetrics
		if config.AdvancedDatapathObservabilityConfig.RelayMode != "" { // Don't check vs UNSPECIFIED
			adoc["relay_mode"] = config.AdvancedDatapathObservabilityConfig.RelayMode
		}
		// Only add sub-block if it contains data
		if len(adoc) > 0 {
			mc["advanced_datapath_observability_config"] = []interface{}{adoc}
			hasConfig = true
		}
	}

	if !hasConfig { // Return nil only if the input config was non-nil but resulted in no data
		return nil
	}
	return []interface{}{mc}
}

// flattenClusterAutoscaling: Simplified direct mapping, keep NAP logic structure
func flattenClusterAutoscaling(autoscaling *container.ClusterAutoscaling) []interface{} {
	if autoscaling == nil {
		return nil
	}
	ca := make(map[string]interface{})
	hasConfig := false // Track if anything gets added

	// Map autoscaling profile directly if present and non-empty
	// Assuming field name is AutoscalingProfile in v1 struct
	// if autoscaling.AutoscalingProfile != "" {
	//	 ca["autoscaling_profile"] = autoscaling.AutoscalingProfile
	//   hasConfig = true
	// }

	// Node Autoprovisioning section
	hasNapConfig := false
	if len(autoscaling.AutoprovisioningLocations) > 0 {
		ca["autoprovisioning_locations"] = autoscaling.AutoprovisioningLocations
		hasNapConfig = true
	}
	if flattened := flattenResourceLimits(autoscaling.ResourceLimits); flattened != nil {
		ca["resource_limits"] = flattened
		hasNapConfig = true
	}
	if flattened := flattenAutoprovisioningNodePoolDefaults(autoscaling.AutoprovisioningNodePoolDefaults); flattened != nil {
		ca["autoprovisioning_node_pool_defaults"] = flattened
		hasNapConfig = true
	}

	// Include 'enabled' field based on API value. Schema marks it Optional+Computed.
	// Mapping API value directly is appropriate for this style.
	ca["enabled"] = autoscaling.EnableNodeAutoprovisioning
	hasConfig = true // Assume 'enabled' always constitutes configuration intent

	// Determine if block should be returned
	if !hasConfig && !hasNapConfig {
		// If no profile, no NAP settings, and enabled=false (default?), maybe return nil.
		// However, schema suggests block is Optional+Computed. Let's return if input wasn't nil.
		if len(ca) == 0 { // More precise: return nil if map is empty
			return nil
		}
	}
	return []interface{}{ca}
}

// flattenResourceLimits: Keep existing logic (filters invalid/empty)
func flattenResourceLimits(limits []*container.ResourceLimit) []interface{} {
	if len(limits) == 0 {
		return nil
	}
	result := make([]interface{}, 0, len(limits))
	for _, limit := range limits {
		if limit == nil {
			continue
		}
		l := make(map[string]interface{})
		// Keep check for required resource_type
		if limit.ResourceType == "" {
			continue
		}
		l["resource_type"] = limit.ResourceType
		// Map min/max directly if present/non-zero (schema validates >=1 for max)
		if limit.Minimum != 0 {
			l["minimum"] = limit.Minimum
		}
		// Maximum is required by schema if block present.
		if limit.Maximum != 0 {
			l["maximum"] = limit.Maximum
		} else {
			// If max is 0 or missing, the schema considers it invalid, skip this limit
			continue
		}
		result = append(result, l)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// flattenAutoprovisioningNodePoolDefaults: Simplified direct mapping
func flattenAutoprovisioningNodePoolDefaults(defaults *container.AutoprovisioningNodePoolDefaults) []interface{} {
	if defaults == nil {
		return nil
	}
	data := make(map[string]interface{})

	// Map fields directly if present/non-empty/non-zero
	if len(defaults.OauthScopes) > 0 {
		data["oauth_scopes"] = defaults.OauthScopes
	}
	if defaults.ServiceAccount != "" { // Map directly, don't check vs "default"
		data["service_account"] = defaults.ServiceAccount
	}
	if us := flattenNodePoolUpgradeSettings(defaults.UpgradeSettings); us != nil {
		data["upgrade_settings"] = us
	}
	if mgmt := flattenNodeManagement(defaults.Management); mgmt != nil {
		data["management"] = mgmt
	}
	if defaults.MinCpuPlatform != "" {
		data["min_cpu_platform"] = defaults.MinCpuPlatform
	}
	if defaults.DiskSizeGb > 0 { // Keep check > 0
		data["disk_size_gb"] = defaults.DiskSizeGb // Don't check vs 100
	}
	if defaults.DiskType != "" { // Don't check vs pd-standard
		data["disk_type"] = defaults.DiskType
	}
	if sic := flattenShieldedInstanceConfig(defaults.ShieldedInstanceConfig); sic != nil {
		data["shielded_instance_config"] = sic
	}
	if defaults.BootDiskKmsKey != "" {
		data["boot_disk_kms_key"] = defaults.BootDiskKmsKey
	}
	if defaults.ImageType != "" { // Don't check vs COS_CONTAINERD
		data["image_type"] = defaults.ImageType
	}

	if len(data) == 0 {
		return nil
	}
	return []interface{}{data}
}

// flattenDatabaseEncryption: Keep logic checking state and requiring key_name
func flattenDatabaseEncryption(config *container.DatabaseEncryption) []interface{} {
	if config == nil {
		return nil
	}
	// Keep logic to only include block if state is non-default (ENCRYPTED)
	if config.State == "" || config.State == "DECRYPTION_STATE_UNSPECIFIED" || config.State == "DECRYPTED" {
		return nil
	}

	de := make(map[string]interface{})
	de["state"] = config.State // Must be ENCRYPTED

	// Keep check for required key_name when encrypted
	if config.KeyName != "" {
		de["key_name"] = config.KeyName
	} else {
		fmt.Println("Warning: DatabaseEncryption state is ENCRYPTED but key_name is missing. Omitting block.")
		return nil
	}
	return []interface{}{de}
}

// flattenVerticalPodAutoscaling: Simplified direct mapping
func flattenVerticalPodAutoscaling(vpa *container.VerticalPodAutoscaling) []interface{} {
	if vpa == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": vpa.Enabled}}
}

// flattenBinaryAuthorization: Simplified, keep deprecated logic handling
func flattenBinaryAuthorization(ba *container.BinaryAuthorization) []interface{} {
	if ba == nil {
		return nil
	}
	data := make(map[string]interface{})
	hasConfig := false

	// Map evaluation_mode directly if present, don't check against default or UNSPECIFIED
	if ba.EvaluationMode != "" {
		data["evaluation_mode"] = ba.EvaluationMode
		hasConfig = true
	} else if ba.Enabled {
		// Keep fallback to deprecated field only if primary is absent
		// Terraform provider should resolve the conflict based on schema.
		data["enabled"] = ba.Enabled
		hasConfig = true
	}

	if !hasConfig { // Return nil only if both fields were absent/false
		return nil
	}
	return []interface{}{data}
}

// flattenCostManagementConfig: Simplified direct mapping
func flattenCostManagementConfig(cmc *container.CostManagementConfig) []interface{} {
	if cmc == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": cmc.Enabled}}
}

// flattenDnsConfig: Simplified direct mapping
func flattenDnsConfig(dns *container.DNSConfig) []interface{} {
	if dns == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map directly, do not check against defaults or "UNSPECIFIED"
	if dns.ClusterDns != "" {
		data["cluster_dns"] = dns.ClusterDns
	}
	if dns.ClusterDnsScope != "" {
		data["cluster_dns_scope"] = dns.ClusterDnsScope
	}
	if dns.ClusterDnsDomain != "" {
		data["cluster_dns_domain"] = dns.ClusterDnsDomain
	}
	// Map additive_vpc_scope_dns_domain directly if field exists and is non-empty
	// Assuming field name is AdditiveVpcScopeDnsDomain in v1 struct
	// if dns.AdditiveVpcScopeDnsDomain != "" { data["additive_vpc_scope_dns_domain"] = dns.AdditiveVpcScopeDnsDomain }

	if len(data) == 0 {
		return nil
	}
	return []interface{}{data}
}

// flattenSecurityPostureConfig: Simplified direct mapping
func flattenSecurityPostureConfig(config *container.SecurityPostureConfig) []interface{} {
	if config == nil {
		return nil
	}
	result := map[string]interface{}{}
	// Map directly, do not check against "UNSPECIFIED"
	if config.Mode != "" {
		result["mode"] = config.Mode
	}
	if config.VulnerabilityMode != "" {
		result["vulnerability_mode"] = config.VulnerabilityMode
	}
	if len(result) == 0 {
		return nil
	}
	return []interface{}{result}
}

// flattenIdentityServiceConfig: Simplified direct mapping
func flattenIdentityServiceConfig(isc *container.IdentityServiceConfig) []interface{} {
	if isc == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": isc.Enabled}}
}

// flattenMeshCertificates: Simplified direct mapping
func flattenMeshCertificates(mc *container.MeshCertificates) []interface{} {
	if mc == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	// API field name seems to be EnableCertificates
	return []interface{}{map[string]interface{}{"enable_certificates": mc.EnableCertificates}}
}

// flattenResourceUsageExportConfig: Simplified direct mapping
func flattenResourceUsageExportConfig(ruec *container.ResourceUsageExportConfig) []interface{} {
	if ruec == nil {
		return nil
	}
	data := make(map[string]interface{})
	hasConfig := false // Track if any field is actually set

	// Map bigquery destination directly if present
	if ruec.BigqueryDestination != nil && ruec.BigqueryDestination.DatasetId != "" {
		data["bigquery_destination"] = []interface{}{map[string]interface{}{
			"dataset_id": ruec.BigqueryDestination.DatasetId,
		}}
		hasConfig = true
	}
	// Map booleans directly - presence implies configuration intent
	data["enable_network_egress_metering"] = ruec.EnableNetworkEgressMetering
	hasConfig = true // Always consider this config

	if ruec.ConsumptionMeteringConfig != nil {
		data["enable_resource_consumption_metering"] = ruec.ConsumptionMeteringConfig.Enabled
		hasConfig = true
	}
	// If consumption metering struct is nil, we don't map it. TF provider handles default (true).

	if !hasConfig { // Return nil if BQ destination was nil AND consumption metering was nil
		// We consider enable_network_egress_metering=false as still being a configuration
		return nil
	}

	// Ensure booleans are present if input struct existed
	if _, ok := data["enable_network_egress_metering"]; !ok {
		data["enable_network_egress_metering"] = ruec.EnableNetworkEgressMetering
	}
	if _, ok := data["enable_resource_consumption_metering"]; !ok && ruec.ConsumptionMeteringConfig != nil {
		data["enable_resource_consumption_metering"] = ruec.ConsumptionMeteringConfig.Enabled
	} else if _, ok := data["enable_resource_consumption_metering"]; !ok && ruec.ConsumptionMeteringConfig == nil {
		// Explicitly DON'T set it if the API struct was nil, let TF provider handle default=true
	}

	return []interface{}{data}
}

// flattenSecretManagerConfig: Simplified direct mapping
func flattenSecretManagerConfig(smc *container.SecretManagerConfig) []interface{} {
	if smc == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": smc.Enabled}}
}

// flattenServiceExternalIPsConfig: Simplified direct mapping
func flattenServiceExternalIPsConfig(seic *container.ServiceExternalIPsConfig) []interface{} {
	if seic == nil {
		return nil
	}
	// Map directly, do not omit if false (default)
	return []interface{}{map[string]interface{}{"enabled": seic.Enabled}}
}

// flattenWorkloadIdentityConfig: Simplified direct mapping
func flattenWorkloadIdentityConfig(wic *container.WorkloadIdentityConfig) []interface{} {
	if wic == nil {
		return nil
	}
	data := make(map[string]interface{})
	// Map WorkloadPool directly if non-empty, don't check against default pattern
	if wic.WorkloadPool != "" {
		data["workload_pool"] = wic.WorkloadPool
	} else {
		// If pool is empty in API, omit the block (nil map means block omitted)
		return nil
	}
	return []interface{}{data}
}

// flattenGatewayApiConfig: Simplified direct mapping
func flattenGatewayApiConfig(gac *container.GatewayAPIConfig) []interface{} {
	if gac == nil {
		return nil
	}
	// Map channel directly if non-empty, do not check against default or "UNSPECIFIED"
	if gac.Channel == "" {
		return nil
	}
	return []interface{}{map[string]interface{}{"channel": gac.Channel}}
}

// flattenFleet: Keep existing logic (omit computed block)
func flattenFleet(fleet *container.Fleet) []interface{} {
	// Fleet block is typically computed, omit from configuration HCL
	return nil
}

// --- Simplified Flatten Functions for Node Pool Defaults ---

// flattenNodePoolDefaults: Simplified direct mapping
func flattenNodePoolDefaults(defaults *container.NodePoolDefaults) []interface{} {
	if defaults == nil {
		return nil
	}
	npdData := make(map[string]interface{})
	hasConfig := false

	// Flatten nested node_config_defaults (simplified)
	if flattenedNCD := flattenNodeConfigDefaults(defaults.NodeConfigDefaults); flattenedNCD != nil {
		npdData["node_config_defaults"] = flattenedNCD
		hasConfig = true
	}

	// Add direct mapping for any other fields directly under node_pool_defaults if they exist in API/schema

	if !hasConfig {
		return nil
	}
	return []interface{}{npdData}
}

// flattenNodeConfigDefaults: Simplified direct mapping
func flattenNodeConfigDefaults(ncd *container.NodeConfigDefaults) []interface{} {
	// NOTE: The v1.NodeConfigDefaults struct might be minimal or empty.
	// Need to check the actual API definition for fields.
	// Example placeholder:
	if ncd == nil {
		return nil
	}
	ncdData := make(map[string]interface{})

	// Example: If NodeConfigDefaults had GcfsConfig field in v1 API
	// if ncd.GcfsConfig != nil {
	//     gcfsData := map[string]interface{}{"enabled": ncd.GcfsConfig.Enabled} // Map directly
	//     ncdData["gcfs_config"] = []interface{}{gcfsData}
	// }
	// Add other direct field mappings here based on the actual v1.NodeConfigDefaults struct

	if len(ncdData) == 0 {
		return nil
	}
	return []interface{}{ncdData}
}
