package container

import (
	"fmt"
	"strings"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/cai2hcl/converters/utils"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/cai2hcl/models"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/pkg/caiasset"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	"google.golang.org/api/container/v1"
	// TODO: Consider adding v1beta1 support for features like auto_monitoring_config
	// "google.golang.org/api/container/v1beta1"
)

const ContainerClusterAssetType string = "container.googleapis.com/Cluster"
const ContainerClusterSchemaName string = "google_container_cluster"
const ContainerNodePoolSchemaName string = "google_container_node_pool"

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
	if asset == nil || asset.Resource == nil || asset.Resource.Data == nil {
		return nil, fmt.Errorf("asset or asset resource data is nil")
	}

	project := utils.ParseFieldValue(asset.Name, "projects")

	// Try to parse location from either "zones" or "locations" field
	location := utils.ParseFieldValue(asset.Name, "locations")
	if location == "" {
		// If locations not found, try zones (for zonal clusters)
		location = utils.ParseFieldValue(asset.Name, "zones")
	}
	if location == "" {
		// If zones not found, try regions (for regional clusters)
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
	// Allow nil block if conversion results in only defaults (though unlikely for cluster itself)
	// if clusterBlock == nil && err == nil {
	// 	return nil, fmt.Errorf("cluster conversion returned nil block without error")
	// }

	blocks := []*models.TerraformResourceBlock{}
	if clusterBlock != nil {
		blocks = append(blocks, clusterBlock)
	} else {
		fmt.Printf("Info: Cluster %s resulted in an empty block after omitting defaults.\n", clusterName)
	}

	// Convert node pools if they exist in the asset and are not just the default pool handled by cluster block
	if len(cluster.NodePools) > 0 {
		// Determine if remove_default_node_pool should be true (implicitly or explicitly)
		// This logic might need refinement based on how initial_node_count interacts with explicit node pools in the API response.
		// Simple check: if more than one node pool exists, or if the single existing pool is NOT named "default-pool"
		hasSeparateNodePools := len(cluster.NodePools) > 1 || (len(cluster.NodePools) == 1 && cluster.NodePools[0] != nil && cluster.NodePools[0].Name != "default-pool")

		for _, nodePool := range cluster.NodePools {
			if nodePool == nil {
				continue
			}
			// Skip conversion if this looks like the default pool AND we are NOT setting remove_default_node_pool=true
			isDefaultPool := nodePool.Name == "default-pool" // GKE's default pool name
			if isDefaultPool && !hasSeparateNodePools && clusterBlock != nil && clusterBlock.Value.GetAttr("remove_default_node_pool").IsNull() {
				fmt.Printf("Info: Skipping conversion of apparent default node pool '%s' as it's likely managed by cluster block attributes.\n", nodePool.Name)
				continue
			}

			nodePoolBlock, err := c.convertNodePoolData(nodePool, cluster, project, location)
			if err != nil {
				fmt.Printf("Warning: Failed to convert node pool %s: %v. Skipping.\n", nodePool.Name, err)
				continue
			}
			if nodePoolBlock != nil {
				blocks = append(blocks, nodePoolBlock)
			}
		}
	}

	return blocks, nil
}

func (c *ContainerClusterConverter) convertClusterData(cluster *container.Cluster, project, location, clusterName string, nodePools []*container.NodePool) (*models.TerraformResourceBlock, error) {
	if cluster == nil {
		return nil, fmt.Errorf("cluster data is nil")
	}
	if c.clusterSchema == nil {
		// Cannot convert without schema, maybe return error? Or just log and return nil?
		fmt.Printf("Warning: Cluster schema is nil in converter for %s. Cannot generate HCL.\n", clusterName)
		return nil, nil // Return nil block, no error to allow potential node pool conversion
	}

	hclData := make(map[string]interface{})

	// Required fields
	hclData["name"] = clusterName

	// Add location field - required field for cluster resource
	hclData["location"] = location

	// Optional fields - only add if non-default / non-empty
	// Project: Omit if matches provider default (requires provider config access - skip for now)
	if project != "" {
		hclData["project"] = project
	}

	if cluster.Description != "" {
		hclData["description"] = cluster.Description
	}

	// Conditional logic for initial node pool / remove_default_node_pool
	// Check if separate node pool resources are expected based on API response structure
	hasSeparateNodePools := false
	if len(nodePools) > 1 || (len(nodePools) == 1 && nodePools[0] != nil && nodePools[0].Name != "default-pool") {
		hasSeparateNodePools = true
	}
	// Scenario 1: Separate node pools exist or will be created
	if hasSeparateNodePools {
		hclData["remove_default_node_pool"] = true // Default is false, so set true
		// Do NOT set initial_node_count or cluster-level node_config
	} else {
		// Scenario 2: Only the default node pool exists, manage with cluster block
		// remove_default_node_pool defaults to false, so omit it.
		// Set initial_node_count if > 0 (default seems 3, but 0 is valid API value?)
		if cluster.InitialNodeCount > 0 {
			hclData["initial_node_count"] = cluster.InitialNodeCount
		}
		// Set cluster-level node_config if non-default
		if flattened := flattenNodeConfig(cluster.NodeConfig); flattened != nil {
			hclData["node_config"] = flattened
		}
	}

	if cluster.Network != "" {
		// Use resource name or self-link based on provider preference (using name here)
		hclData["network"] = tpgresource.GetResourceNameFromSelfLink(cluster.Network)
	}

	// Subnetwork: Use full path for subnetwork
	if cluster.Subnetwork != "" {
		if project != "" && strings.HasPrefix(cluster.Subnetwork, "projects/") {
			// If it's already a full path, use it as is
			hclData["subnetwork"] = cluster.Subnetwork
		} else if project != "" {
			// Construct full path if not already present
			subnetName := tpgresource.GetResourceNameFromSelfLink(cluster.Subnetwork)

			// Extract region from location for subnetwork path
			region := "us-central1" // Default in case we can't extract from location

			// Extract region based on location format
			// If location is a zone (e.g., us-central1-a), extract the region part
			// If location is already a region (e.g., us-central1), use it directly
			locationParts := strings.Split(location, "-")
			if len(locationParts) == 3 {
				// Location is a zone, extract region (e.g., us-central1-a -> us-central1)
				lastDashIndex := strings.LastIndex(location, "-")
				if lastDashIndex > 0 {
					region = location[:lastDashIndex]
				}
			} else if len(locationParts) == 2 {
				// Location is already a region (e.g., us-central1)
				region = location
			}

			hclData["subnetwork"] = fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s",
				project,
				region,
				subnetName)
		} else {
			// Fallback to just the name if we can't construct full path
			hclData["subnetwork"] = tpgresource.GetResourceNameFromSelfLink(cluster.Subnetwork)
		}
	}

	// IP Allocation Policy
	if flattened := flattenIPAllocationPolicy(cluster.IpAllocationPolicy); flattened != nil {
		hclData["ip_allocation_policy"] = flattened
	}

	// Network Config sub-fields (Datapath Provider, boolean flags)
	if cluster.NetworkConfig != nil { // Check if NetworkConfig exists first
		// --- Cluster Blocks (Potentially under NetworkConfig) ---
		if flattened := flattenDnsConfig(cluster.NetworkConfig.DnsConfig); flattened != nil { // Access via NetworkConfig
			hclData["dns_config"] = flattened
		}
		// Corrected field name from ServiceExternalIPsConfig to ServiceExternalIpsConfig
		if flattened := flattenServiceExternalIPsConfig(cluster.NetworkConfig.ServiceExternalIpsConfig); flattened != nil {
			hclData["service_external_ips_config"] = flattened
		}
		if flattened := flattenGatewayApiConfig(cluster.NetworkConfig.GatewayApiConfig); flattened != nil { // Access via NetworkConfig
			hclData["gateway_api_config"] = flattened
		}

		// Include if "unspecified" or "legacy"
		if cluster.NetworkConfig.DatapathProvider != "" {
			hclData["datapath_provider"] = cluster.NetworkConfig.DatapathProvider
		}
		// enable_fqdn_network_policy: Omit if false (default)
		if cluster.NetworkConfig.EnableFqdnNetworkPolicy {
			hclData["enable_fqdn_network_policy"] = true
		}
		// enable_l4_ilb_subsetting: Omit if false (default)
		if cluster.NetworkConfig.EnableL4ilbSubsetting {
			hclData["enable_l4_ilb_subsetting"] = true
		}
		// enable_multi_networking: Omit if false (default)
		if cluster.NetworkConfig.EnableMultiNetworking {
			hclData["enable_multi_networking"] = true
		}
		// enable_intranode_visibility: Omit if false (default)
		if cluster.NetworkConfig.EnableIntraNodeVisibility { // Field name from schema
			hclData["enable_intranode_visibility"] = true
		}
	}

	// Default Max Pods Constraint: Omit if 0/nil (check API default)
	if cluster.DefaultMaxPodsConstraint != nil && cluster.DefaultMaxPodsConstraint.MaxPodsPerNode > 0 {
		hclData["default_max_pods_per_node"] = cluster.DefaultMaxPodsConstraint.MaxPodsPerNode
	}

	// Always include network_policy, will default to disabled with PROVIDER_UNSPECIFIED if not specified
	hclData["network_policy"] = flattenNetworkPolicy(cluster.NetworkPolicy)

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

	// Addons Config: omit if nil or only contains defaults
	if flattened := flattenAddonsConfig(cluster.AddonsConfig); flattened != nil {
		hclData["addons_config"] = flattened
	}

	// Set node_locations if present in the cluster
	if len(cluster.Locations) > 0 {
		zonesAndLocations := schema.NewSet(schema.HashString, tpgresource.ConvertStringArrToInterface(cluster.Locations))
		// we shouldn't repeat zone in locations otherwise TF fails to apply for zonal cluster
		zonesAndLocations.Remove(cluster.Zone)
		hclData["node_locations"] = zonesAndLocations
	}

	// Resource Labels: Omit if empty
	if len(cluster.ResourceLabels) > 0 {
		hclData["resource_labels"] = cluster.ResourceLabels
	}

	// Always include release_channel, will default to UNSPECIFIED if not specified
	hclData["release_channel"] = flattenReleaseChannel(cluster.ReleaseChannel)

	// Set node_version from CurrentNodeVersion (as per target schema)
	if cluster.CurrentNodeVersion != "" {
		hclData["node_version"] = cluster.CurrentNodeVersion
	}

	// master_version not included in target schema, omitting

	// Boolean flags - Omit if default (usually false, check schema)
	if cluster.Autopilot != nil && cluster.Autopilot.Enabled { // Default false
		hclData["enable_autopilot"] = true
	}
	if cluster.EnableKubernetesAlpha { // Default false
		hclData["enable_kubernetes_alpha"] = true
	}
	if cluster.EnableTpu { // Default false
		hclData["enable_tpu"] = true
	}
	if cluster.LegacyAbac != nil && cluster.LegacyAbac.Enabled { // Default false
		hclData["enable_legacy_abac"] = true
	}
	// this is true by default
	if cluster.ShieldedNodes != nil {
		hclData["enable_shielded_nodes"] = cluster.ShieldedNodes.Enabled
	}

	// --- Cluster Blocks --- Always include master_auth and control_plane_endpoints_config with default values
	// Always include master_auth block with client_certificate_config.issue_client_certificate = false
	hclData["master_auth"] = flattenMasterAuth(cluster.MasterAuth)

	// Always include control_plane_endpoints_config with defaults
	hclData["control_plane_endpoints_config"] = flattenControlPlaneEndpointsConfig(cluster.ControlPlaneEndpointsConfig)
	if flattened := flattenPrivateClusterConfigAdapted(cluster.PrivateClusterConfig, cluster.NetworkConfig); flattened != nil {
		hclData["private_cluster_config"] = flattened
	}
	if flattened := flattenClusterAutoscaling(cluster.Autoscaling); flattened != nil {
		hclData["cluster_autoscaling"] = flattened
	}
	// Always include database_encryption, will default to DECRYPTED if not specified
	hclData["database_encryption"] = flattenDatabaseEncryption(cluster.DatabaseEncryption)

	// Always include enterprise_config, will default to STANDARD tier if not specified
	hclData["enterprise_config"] = flattenEnterpriseConfig(cluster.EnterpriseConfig)
	if flattened := flattenVerticalPodAutoscaling(cluster.VerticalPodAutoscaling); flattened != nil {
		hclData["vertical_pod_autoscaling"] = flattened
	}
	if flattened := flattenBinaryAuthorization(cluster.BinaryAuthorization); flattened != nil {
		hclData["binary_authorization"] = flattened
	}
	// Add Security Posture Config
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
	if flattened := flattenFleet(cluster.Fleet); flattened != nil {
		hclData["fleet"] = flattened
	}
	// Assuming API field name NodePoolDefaults
	if flattened := flattenNodePoolDefaults(cluster.NodePoolDefaults); flattened != nil {
		hclData["node_pool_defaults"] = flattened
	}

	if flattened := flattenNodePoolAutoConfig(cluster.NodePoolAutoConfig); len(flattened) > 0 && len(flattened[0]) > 0 {
		hclData["node_pool_auto_config"] = flattened
	}

	// Check if HCL data is empty - might happen if importing a very default cluster
	if len(hclData) <= 2 { // Only name and location were set
		fmt.Printf("Warning: Cluster %s resulted in minimal HCL data after omitting defaults.\n", clusterName)
		// Decide if returning nil is appropriate. It depends on whether the cluster resource itself is truly optional.
		// For now, return the minimal block.
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

func (c *ContainerClusterConverter) convertNodePoolData(nodePool *container.NodePool, cluster *container.Cluster, project, location string) (*models.TerraformResourceBlock, error) {
	if nodePool == nil {
		return nil, fmt.Errorf("node pool data is nil")
	}
	// Cluster context is needed for referencing, but not strictly for node pool defaults
	if cluster == nil {
		return nil, fmt.Errorf("cluster context is nil for node pool")
	}
	if c.nodePoolSchema == nil {
		// Cannot convert without schema
		fmt.Printf("Warning: Node pool schema is nil in converter for %s. Cannot generate HCL.\n", nodePool.Name)
		return nil, nil
	}

	hclData := make(map[string]interface{})

	// Required fields
	hclData["name"] = nodePool.Name
	hclData["cluster"] = cluster.Name // Reference cluster by name

	// Optional fields - only add if non-default / non-empty
	if location != "" { // Location is technically required by node pool resource
		hclData["location"] = location
	}
	if project != "" { // Project is technically required by node pool resource
		hclData["project"] = project
	}

	// Node count / Autoscaling - Handle initial_node_count and node_count appropriately
	autoscalingBlock := flattenNodePoolAutoscaling(nodePool.Autoscaling)
	if autoscalingBlock != nil {
		hclData["autoscaling"] = autoscalingBlock
		// With autoscaling, always include initial_node_count
		if nodePool.InitialNodeCount > 0 {
			hclData["initial_node_count"] = nodePool.InitialNodeCount
		} else {
			// Default to 1 if not specified
			hclData["initial_node_count"] = 1
		}
	} else {
		// Autoscaling is disabled or default. Always include node_count.
		if nodePool.InitialNodeCount > 0 {
			hclData["node_count"] = nodePool.InitialNodeCount
		} else {
			// Default to 1 if not specified
			hclData["node_count"] = 1
		}
	}

	// Node Config: omit if nil or only contains defaults
	if flattened := flattenNodeConfig(nodePool.Config); flattened != nil {
		hclData["node_config"] = flattened
	}

	// Management: omit if nil or only contains defaults
	if flattened := flattenNodeManagement(nodePool.Management); flattened != nil {
		hclData["management"] = flattened
	}

	// Set max_pods_per_node directly (not as a nested block)
	if nodePool.MaxPodsConstraint != nil && nodePool.MaxPodsConstraint.MaxPodsPerNode > 0 {
		hclData["max_pods_per_node"] = nodePool.MaxPodsConstraint.MaxPodsPerNode
	}

	// Network Config: omit if nil or only contains defaults
	if flattened := flattenNodeNetworkConfig(nodePool.NetworkConfig); flattened != nil {
		hclData["network_config"] = flattened
	}

	// Upgrade Settings: omit if nil or only contains defaults
	if flattened := flattenNodePoolUpgradeSettings(nodePool.UpgradeSettings); flattened != nil {
		hclData["upgrade_settings"] = flattened
	}

	// Version: Omit if empty or matches cluster version when cluster uses release channel? Complex.
	// Simple: Omit if empty.
	if nodePool.Version != "" {
		// TODO: Add check against effective cluster node version if possible to omit redundancy?
		hclData["version"] = nodePool.Version
	}

	// Placement Policy: omit if nil or only contains defaults
	if flattened := flattenPlacementPolicy(nodePool.PlacementPolicy); flattened != nil {
		hclData["placement_policy"] = flattened
	}

	// This represents the zones where nodes in this pool will be created
	if len(nodePool.Locations) > 0 || location != "" {
		// We prefet to set the node_locations directly from cluster.Locations
		if len(nodePool.Locations) > 0 {
			hclData["node_locations"] = nodePool.Locations
		} else {
			hclData["node_locations"] = []string{location}
		}
	}

	// Always include queued_provisioning with enabled=false as the default
	hclData["queued_provisioning"] = flattenQueuedProvisioning(nodePool.QueuedProvisioning)

	// Check if HCL data is empty (beyond required fields name, cluster, location, project)
	if len(hclData) <= 4 {
		fmt.Printf("Warning: Node Pool %s resulted in minimal HCL data after omitting defaults.\n", nodePool.Name)
		// Return nil, as an empty node pool block is likely an error or redundant.
		// return nil, nil
		// Let's return minimal block for now, user might want explicit definition.
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

// --- FLATTEN FUNCTIONS (Revised for Default Omission) ---

// flattenQueuedProvisioning creates a block for queued_provisioning with enabled=false as the default
func flattenQueuedProvisioning(config *container.QueuedProvisioning) []interface{} {
	qp := make(map[string]interface{})

	// Always set enabled to false by default
	qp["enabled"] = false

	// If config exists and enabled is true, override the default
	if config != nil && config.Enabled {
		qp["enabled"] = true
	}

	return []interface{}{qp}
}

// flattenAdvancedMachineFeatures creates a block for advanced_machine_features with enable_nested_virtualization=false as the default
func flattenAdvancedMachineFeatures(config *container.AdvancedMachineFeatures) []interface{} {
	amf := make(map[string]interface{})

	// set defaults for advanced_machine_features
	amf["enable_nested_virtualization"] = false
	amf["threads_per_core"] = 0

	// If config exists and enable_nested_virtualization is true, override the default
	if config != nil {
		if config.EnableNestedVirtualization {
			amf["enable_nested_virtualization"] = true
		}
		if config.ThreadsPerCore != 0 {
			amf["threads_per_core"] = config.ThreadsPerCore
		}
	}

	return []interface{}{amf}
}

// flattenNodeConfig now checks against defaults and returns nil if only defaults are present.
func flattenNodeConfig(config *container.NodeConfig) []interface{} {
	if config == nil {
		// Create default node config with our required defaults
		nodeConfig := make(map[string]interface{})

		// Always include advanced_machine_features with default values
		nodeConfig["advanced_machine_features"] = flattenAdvancedMachineFeatures(nil)

		// Always include empty resource_manager_tags
		nodeConfig["resource_manager_tags"] = make(map[string]string)

		return []interface{}{nodeConfig}
	}

	nodeConfig := make(map[string]interface{})
	hasNonDefaultConfig := false // Track if any non-default value is set

	// Machine Type: Typically non-default if specified. Include if present.
	if config.MachineType != "" {
		// TODO: Check against implicit default like e2-medium? Hard to determine.
		nodeConfig["machine_type"] = config.MachineType
		hasNonDefaultConfig = true
	}

	if config.DiskSizeGb > 0 { // Keep basic check for >0, as 0 might be invalid
		nodeConfig["disk_size_gb"] = config.DiskSizeGb
		hasNonDefaultConfig = true
	}

	// Disk Type: Don't check on 'pd-standard' default.
	if config.DiskType != "" {
		nodeConfig["disk_type"] = config.DiskType
		hasNonDefaultConfig = true
	}

	// OAuth Scopes: Omit only if list is empty (simplification, actual defaults are complex).
	if len(config.OauthScopes) > 0 {
		// TODO: Consider comparing against expected default scopes for the SA? Very complex.
		nodeConfig["oauth_scopes"] = config.OauthScopes
		hasNonDefaultConfig = true
	}

	// Service Account: dont check on "default" SA.
	if config.ServiceAccount != "" {
		nodeConfig["service_account"] = config.ServiceAccount
		hasNonDefaultConfig = true
	}

	// Metadata: Omit if explicitly empty. GKE adds defaults, difficult to filter precisely.
	if len(config.Metadata) > 0 {
		nodeConfig["metadata"] = config.Metadata
		hasNonDefaultConfig = true
	}

	// Image Type: dont check on assumed default (COS_CONTAINERD).
	if config.ImageType != "" {
		nodeConfig["image_type"] = config.ImageType
		hasNonDefaultConfig = true
	}

	// Labels: Omit if empty map.
	if len(config.Labels) > 0 {
		nodeConfig["labels"] = config.Labels
		hasNonDefaultConfig = true
	}

	// Resource Labels: Omit if empty map. (Field name might differ in v1 struct)
	if len(config.ResourceLabels) > 0 {
		nodeConfig["resource_labels"] = config.ResourceLabels
		hasNonDefaultConfig = true
	}

	// Local SSD Count: Default 0. Omit if 0.
	if config.LocalSsdCount > 0 {
		nodeConfig["local_ssd_count"] = config.LocalSsdCount
		hasNonDefaultConfig = true
	}

	// Tags: Omit if empty list.
	if len(config.Tags) > 0 {
		nodeConfig["tags"] = config.Tags
		hasNonDefaultConfig = true
	}

	// Preemptible: Default false. Omit if false.
	if config.Preemptible {
		nodeConfig["preemptible"] = config.Preemptible
		hasNonDefaultConfig = true
	}

	// Spot: Default false. Omit if false.
	if config.Spot {
		nodeConfig["spot"] = config.Spot
		hasNonDefaultConfig = true
	}

	// Min CPU Platform: Default "". Omit if "".
	if config.MinCpuPlatform != "" {
		nodeConfig["min_cpu_platform"] = config.MinCpuPlatform
		hasNonDefaultConfig = true
	}

	// --- Nested Blocks --- Check if flatten returns non-nil
	if flattened := flattenWorkloadMetadataConfig(config.WorkloadMetadataConfig); flattened != nil {
		nodeConfig["workload_metadata_config"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenShieldedInstanceConfig(config.ShieldedInstanceConfig); flattened != nil {
		nodeConfig["shielded_instance_config"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenAccelerators(config.Accelerators); flattened != nil {
		nodeConfig["guest_accelerator"] = flattened // TF uses guest_accelerator
		hasNonDefaultConfig = true
	}
	if flattened := flattenReservationAffinity(config.ReservationAffinity); flattened != nil {
		nodeConfig["reservation_affinity"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenConfidentialNodes(config.ConfidentialNodes); flattened != nil {
		nodeConfig["confidential_nodes"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenKubeletConfig(config.KubeletConfig); flattened != nil {
		nodeConfig["kubelet_config"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenLinuxNodeConfig(config.LinuxNodeConfig); flattened != nil {
		nodeConfig["linux_node_config"] = flattened
		hasNonDefaultConfig = true
	}
	if flattened := flattenGvnic(config.Gvnic); flattened != nil { // Assuming flattenGvnic helper exists
		nodeConfig["gvnic"] = flattened
		hasNonDefaultConfig = true
	}

	// Always include advanced_machine_features with default values
	nodeConfig["advanced_machine_features"] = flattenAdvancedMachineFeatures(config.AdvancedMachineFeatures)
	hasNonDefaultConfig = true
	// Add other nested blocks (EphemeralStorage, Nvme, SecondaryDisks, Gcfs, Windows, SoleTenant, HostMaintenance, FastSocket etc.)
	// Example:
	// if flattened := flattenEphemeralStorage(config.EphemeralStorageLocalSsdConfig); flattened != nil {
	//  nodeConfig["ephemeral_storage_local_ssd_config"] = flattened
	//  hasNonDefaultConfig = true
	// }

	// --- Simple Optional Fields --- Omit if zero value / empty
	if config.BootDiskKmsKey != "" {
		nodeConfig["boot_disk_kms_key"] = config.BootDiskKmsKey
		hasNonDefaultConfig = true
	}

	// Taints: flattenNodeTaints handles empty list.
	if flattened := flattenNodeTaints(config.Taints); flattened != nil {
		nodeConfig["taint"] = flattened // TF uses taint
		hasNonDefaultConfig = true
	}

	// resource_manager_tags: Always include empty map as default
	if config.ResourceManagerTags != nil && len(config.ResourceManagerTags.Tags) > 0 {
		nodeConfig["resource_manager_tags"] = config.ResourceManagerTags.Tags // Assign the actual map
	} else {
		nodeConfig["resource_manager_tags"] = make(map[string]string) // Empty map as default
	}
	hasNonDefaultConfig = true
	// enable_confidential_storage: Omit if false (default)
	if config.EnableConfidentialStorage { // Assuming field name and bool type
		nodeConfig["enable_confidential_storage"] = true
		hasNonDefaultConfig = true
	}
	// local_ssd_encryption_mode: Omit if empty or default ("STANDARD_ENCRYPTION"?)
	localSsdEncryptDefault := "STANDARD_ENCRYPTION"                                                     // Verify
	if config.LocalSsdEncryptionMode != "" && config.LocalSsdEncryptionMode != localSsdEncryptDefault { // Assuming field name
		nodeConfig["local_ssd_encryption_mode"] = config.LocalSsdEncryptionMode
		hasNonDefaultConfig = true
	}
	// max_run_duration: Omit if empty
	if config.MaxRunDuration != "" { // Assuming field name
		nodeConfig["max_run_duration"] = config.MaxRunDuration
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig { // If NO non-default values were added
		return nil // Omit the entire node_config block
	}
	return []interface{}{nodeConfig}
}

// flattenWorkloadMetadataConfig: map directly, do not check against defaultWlcMode or "MODE_UNSPECIFIED"
func flattenWorkloadMetadataConfig(config *container.WorkloadMetadataConfig) []interface{} {
	if config == nil || config.Mode == "" {
		return nil
	}
	return []interface{}{map[string]interface{}{"mode": config.Mode}}
}

// flattenShieldedInstanceConfig: Omit fields if they match defaults, nil if block becomes empty.
func flattenShieldedInstanceConfig(config *container.ShieldedInstanceConfig) []interface{} {
	if config == nil {
		return nil
	}
	sic := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Default enable_secure_boot: false
	if config.EnableSecureBoot {
		sic["enable_secure_boot"] = true
		hasNonDefaultConfig = true
	}
	// Default enable_integrity_monitoring: true
	if !config.EnableIntegrityMonitoring { // Only include if explicitly false (non-default)
		sic["enable_integrity_monitoring"] = false
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil // Block only contained defaults
	}
	return []interface{}{sic}
}

// flattenAccelerators: Omit if list empty. Checks internal defaults.
func flattenAccelerators(accelerators []*container.AcceleratorConfig) []interface{} {
	if len(accelerators) == 0 {
		return nil
	}
	result := make([]interface{}, 0, len(accelerators))
	hasMeaningfulAccelerator := false

	for _, acc := range accelerators {
		if acc == nil {
			continue
		}

		data := make(map[string]interface{})
		accHasNonDefaultConfig := false

		// Count and Type are required by schema if block present. Always include if acc exists.
		// Assuming keys match the map structure expected by the caller (flattenNodeConfig -> guest_accelerator)
		data["accelerator_type"] = acc.AcceleratorType
		data["accelerator_count"] = acc.AcceleratorCount
		accHasNonDefaultConfig = true // Presence of type/count makes it non-default

		// Optional fields - add only if present AND potentially non-default
		if acc.GpuPartitionSize != "" {
			data["gpu_partition_size"] = acc.GpuPartitionSize
			accHasNonDefaultConfig = true
		}
		if flattened := flattenGpuSharingConfig(acc.GpuSharingConfig); flattened != nil {
			data["gpu_sharing_config"] = flattened
			accHasNonDefaultConfig = true
		}
		if flattened := flattenGpuDriverInstallationConfig(acc.GpuDriverInstallationConfig); flattened != nil {
			data["gpu_driver_installation_config"] = flattened
			accHasNonDefaultConfig = true
		}

		if accHasNonDefaultConfig { // Should always be true if acc != nil due to type/count
			result = append(result, data)
			hasMeaningfulAccelerator = true
		}
	}

	if !hasMeaningfulAccelerator { // If all acc were nil or somehow deemed default
		return nil
	}
	return result
}

// flattenGpuSharingConfig: Omit fields if default. Return nil if block empty/default.
func flattenGpuSharingConfig(config *container.GPUSharingConfig) []interface{} {
	if config == nil {
		return nil
	}
	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Max clients required by schema if block present
	if config.MaxSharedClientsPerGpu > 0 { // Assume 0 is default/invalid? Schema needs check. Let's include if > 0.
		data["max_shared_clients_per_gpu"] = config.MaxSharedClientsPerGpu
		hasNonDefaultConfig = true
	} else {
		// If max_shared_clients is required and <= 0, maybe the block is invalid?
		// For now, let's assume the block can exist without it if strategy is set.
	}

	// Strategy: Omit if default (UNSPECIFIED)
	if config.GpuSharingStrategy != "" && config.GpuSharingStrategy != "GPU_SHARING_STRATEGY_UNSPECIFIED" {
		data["gpu_sharing_strategy"] = config.GpuSharingStrategy
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil // Only contained defaults or was invalid
	}
	return []interface{}{data}
}

func flattenGpuDriverInstallationConfig(config *container.GPUDriverInstallationConfig) []interface{} {
	// Map directly, do not check against "UNSPECIFIED"
	if config == nil || config.GpuDriverVersion == "" {
		return nil
	}
	// Version is required by schema if block present, and we've established it's non-default here.
	return []interface{}{map[string]interface{}{"gpu_driver_version": config.GpuDriverVersion}}
}

func flattenReservationAffinity(config *container.ReservationAffinity) []interface{} {
	if config == nil {
		return nil
	}
	// Map type directly, do not check against "NO_RESERVATION" or "UNSPECIFIED"
	if config.ConsumeReservationType == "" {
		return nil // Omit block if type is default/unspecified
	}

	ra := make(map[string]interface{})
	ra["consume_reservation_type"] = config.ConsumeReservationType // Set non-default type

	if config.ConsumeReservationType == "SPECIFIC_RESERVATION" {
		if config.Key != "" {
			ra["key"] = config.Key
		} else {
			fmt.Printf("Warning: ReservationAffinity type is SPECIFIC_RESERVATION but Key is missing. Omitting block.\n")
			return nil
		}
		if len(config.Values) > 0 {
			ra["values"] = config.Values
		}
	}
	return []interface{}{ra}
}

// flattenConfidentialNodes: Omit if default (enabled: false).
func flattenConfidentialNodes(config *container.ConfidentialNodes) []interface{} {
	if config == nil || !config.Enabled { // Default is false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenKubeletConfig: Omit fields matching defaults, return nil if block becomes empty.
func flattenKubeletConfig(config *container.NodeKubeletConfig) []interface{} {
	if config == nil {
		return nil
	}
	kc := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Add insecure_kubelet_readonly_port_enabled if true
	if config.InsecureKubeletReadonlyPortEnabled {
		kc["insecure_kubelet_readonly_port_enabled"] = flattenInsecureKubeletReadonlyPortEnabled(config)
		hasNonDefaultConfig = true
	}

	// dont check for "none"
	if config.CpuManagerPolicy != "" {
		kc["cpu_manager_policy"] = config.CpuManagerPolicy
		hasNonDefaultConfig = true
	}

	// Assuming CpuCfsQuota field is bool in v1 API struct
	if config.CpuCfsQuota { // Default is false
		kc["cpu_cfs_quota"] = config.CpuCfsQuota
		hasNonDefaultConfig = true
	}
	if config.CpuCfsQuotaPeriod != "" { // Default is ""
		kc["cpu_cfs_quota_period"] = config.CpuCfsQuotaPeriod
		hasNonDefaultConfig = true
	}
	if config.PodPidsLimit != 0 { // Default is 0 / unset
		kc["pod_pids_limit"] = config.PodPidsLimit
		hasNonDefaultConfig = true
	}

	// TODO: Add checks for container log/image GC fields against their defaults if known

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{kc}
}

// flattenLinuxNodeConfig: Omit fields matching defaults, return nil if block becomes empty.
func flattenLinuxNodeConfig(config *container.LinuxNodeConfig) []interface{} {
	if config == nil {
		return nil
	}
	lnc := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Default sysctls: nil/empty map
	if len(config.Sysctls) > 0 {
		lnc["sysctls"] = config.Sysctls
		hasNonDefaultConfig = true
	}
	// Do not check against "GROUP_MODE_V1" or "UNSPECIFIED"
	if config.CgroupMode != "" {
		lnc["cgroup_mode"] = config.CgroupMode
		hasNonDefaultConfig = true
	}
	// TODO: Check hugepages_config against default (likely all 0)

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{lnc}
}

// flattenNodeTaints: Already handles empty list and invalid effect. No change needed.
func flattenNodeTaints(taints []*container.NodeTaint) []interface{} {
	if len(taints) == 0 {
		return nil
	}
	result := make([]interface{}, 0, len(taints))
	for _, taint := range taints {
		if taint == nil {
			continue
		}
		if taint.Effect == "" || taint.Effect == "EFFECT_UNSPECIFIED" {
			// fmt.Printf("Warning: Skipping taint with key %s due to unspecified effect.\n", taint.Key)
			continue // Skip invalid/default effect
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

// flattenGvnic: Omit if default (enabled: false).
func flattenGvnic(config *container.VirtualNIC) []interface{} {
	if config == nil || !config.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenIPAllocationPolicy: Omit fields if default, return nil if block becomes empty.
func flattenIPAllocationPolicy(policy *container.IPAllocationPolicy) []interface{} {
	if policy == nil {
		return nil
	}
	ipa := make(map[string]interface{})
	hasNonDefaultConfig := false

	// cluster_secondary_range_name conflicts with cluster_ipv4_cidr_block. we prefer to set cluster_ipv4_cidr_block
	if policy.ClusterIpv4CidrBlock != "" {
		ipa["cluster_ipv4_cidr_block"] = policy.ClusterIpv4CidrBlock
		hasNonDefaultConfig = true
	}
	if policy.ClusterIpv4CidrBlock == "" && policy.ClusterSecondaryRangeName != "" {
		ipa["cluster_secondary_range_name"] = policy.ClusterSecondaryRangeName
		hasNonDefaultConfig = true
	}
	// services_secondary_range_name conflicts with services_ipv4_cidr_block. we prefer to set services_ipv4_cidr_block
	if policy.ServicesIpv4CidrBlock != "" {
		ipa["services_ipv4_cidr_block"] = policy.ServicesIpv4CidrBlock
		hasNonDefaultConfig = true
	}
	if policy.ServicesIpv4CidrBlock == "" && policy.ServicesSecondaryRangeName != "" {
		ipa["services_secondary_range_name"] = policy.ServicesSecondaryRangeName
		hasNonDefaultConfig = true
	}
	if policy.CreateSubnetwork { // Default false
		ipa["create_subnetwork"] = policy.CreateSubnetwork
		hasNonDefaultConfig = true
	}
	if policy.SubnetworkName != "" {
		ipa["subnetwork_name"] = policy.SubnetworkName
		hasNonDefaultConfig = true
	}
	if policy.TpuIpv4CidrBlock != "" {
		ipa["tpu_ipv4_cidr_block"] = policy.TpuIpv4CidrBlock
		hasNonDefaultConfig = true
	}
	// Map StackType directly, do not check against default or "UNSPECIFIED"
	if policy.StackType != "" {
		ipa["stack_type"] = policy.StackType
		hasNonDefaultConfig = true
	}
	// Additional Pod Ranges: Omit if nil/empty
	if policy.AdditionalPodRangesConfig != nil && len(policy.AdditionalPodRangesConfig.PodRangeNames) > 0 {
		addlConfig := map[string]interface{}{"pod_range_names": policy.AdditionalPodRangesConfig.PodRangeNames}
		ipa["additional_pod_ranges_config"] = []interface{}{addlConfig}
		hasNonDefaultConfig = true
	}
	// Pod CIDR Overprovisioning: Omit if nil or disabled:false (default)
	if policy.PodCidrOverprovisionConfig != nil && policy.PodCidrOverprovisionConfig.Disable { // Only include if true (non-default)
		overprovisionConfig := map[string]interface{}{"disable": policy.PodCidrOverprovisionConfig.Disable}
		ipa["pod_cidr_overprovision_config"] = []interface{}{overprovisionConfig}
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		// If the policy object exists, IP Aliases are implicitly used.
		// The presence of the block itself enables VPC_NATIVE mode.
		// Return nil if no actual config values are set beyond defaults.
		return nil
	}
	return []interface{}{ipa}
}

// flattenAddonsConfig: Omit addons if they match their specific defaults. Nil if block empty.
func flattenAddonsConfig(config *container.AddonsConfig) []interface{} {
	if config == nil {
		return nil
	}

	addons := make(map[string]interface{})
	hasNonDefaultConfig := false

	// HTTP Load Balancing: Default enabled (disabled: false)
	if config.HttpLoadBalancing != nil && config.HttpLoadBalancing.Disabled { // Include only if explicitly disabled
		addons["http_load_balancing"] = []interface{}{map[string]interface{}{"disabled": true}}
		hasNonDefaultConfig = true
	}
	// Horizontal Pod Autoscaling: Default enabled (disabled: false)
	if config.HorizontalPodAutoscaling != nil && config.HorizontalPodAutoscaling.Disabled { // Include only if explicitly disabled
		addons["horizontal_pod_autoscaling"] = []interface{}{map[string]interface{}{"disabled": true}}
		hasNonDefaultConfig = true
	}
	// Network Policy Config: Default disabled (disabled: true)
	if config.NetworkPolicyConfig != nil && !config.NetworkPolicyConfig.Disabled { // Include only if explicitly enabled
		addons["network_policy_config"] = []interface{}{map[string]interface{}{"disabled": false}}
		hasNonDefaultConfig = true
	}
	// CloudRun Config: Default disabled (disabled: true)
	if config.CloudRunConfig != nil && !config.CloudRunConfig.Disabled { // Include only if explicitly enabled
		crc := map[string]interface{}{"disabled": false}
		// load_balancer_type default is external, only set if internal (non-default)
		if config.CloudRunConfig.LoadBalancerType == "LOAD_BALANCER_TYPE_INTERNAL" {
			crc["load_balancer_type"] = config.CloudRunConfig.LoadBalancerType
		}
		addons["cloudrun_config"] = []interface{}{crc}
		hasNonDefaultConfig = true
	}
	// DnsCache Config: Default disabled (enabled: false)
	if config.DnsCacheConfig != nil && config.DnsCacheConfig.Enabled { // Include only if explicitly enabled
		addons["dns_cache_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// GCE Persistent Disk CSI Driver: Default depends on version (often enabled). Assume TF default=enabled. Include only if explicitly disabled.
	if config.GcePersistentDiskCsiDriverConfig != nil && !config.GcePersistentDiskCsiDriverConfig.Enabled {
		addons["gce_persistent_disk_csi_driver_config"] = []interface{}{map[string]interface{}{"enabled": false}}
		hasNonDefaultConfig = true
	}
	// GCP Filestore CSI Driver: Default disabled. Include only if explicitly enabled.
	if config.GcpFilestoreCsiDriverConfig != nil && config.GcpFilestoreCsiDriverConfig.Enabled {
		addons["gcp_filestore_csi_driver_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// Config Connector Config: Default disabled. Include only if explicitly enabled.
	if config.ConfigConnectorConfig != nil && config.ConfigConnectorConfig.Enabled {
		addons["config_connector_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// GKE Backup Agent Config: Default disabled. Include only if explicitly enabled.
	if config.GkeBackupAgentConfig != nil && config.GkeBackupAgentConfig.Enabled {
		addons["gke_backup_agent_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// GCS Fuse CSI Driver Config: Default disabled. Include only if explicitly enabled.
	if config.GcsFuseCsiDriverConfig != nil && config.GcsFuseCsiDriverConfig.Enabled {
		addons["gcs_fuse_csi_driver_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// Stateful HA Config: Default disabled. Include only if explicitly enabled.
	if config.StatefulHaConfig != nil && config.StatefulHaConfig.Enabled {
		addons["stateful_ha_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}
	// Ray Operator Config: Default disabled. Include only if explicitly enabled. Check internal defaults too.
	if config.RayOperatorConfig != nil && config.RayOperatorConfig.Enabled {
		rayConfig := map[string]interface{}{"enabled": true}
		raySubConfigHasNonDefault := false
		// Ray Logging: Default disabled. Add block only if enabled.
		if config.RayOperatorConfig.RayClusterLoggingConfig != nil && config.RayOperatorConfig.RayClusterLoggingConfig.Enabled {
			rayConfig["ray_cluster_logging_config"] = []interface{}{map[string]interface{}{"enabled": true}}
			raySubConfigHasNonDefault = true
		}
		// Ray Monitoring: Default disabled. Add block only if enabled.
		if config.RayOperatorConfig.RayClusterMonitoringConfig != nil && config.RayOperatorConfig.RayClusterMonitoringConfig.Enabled {
			rayConfig["ray_cluster_monitoring_config"] = []interface{}{map[string]interface{}{"enabled": true}}
			raySubConfigHasNonDefault = true
		}
		// Only add ray_operator_config if the main addon or sub-configs are enabled
		if config.RayOperatorConfig.Enabled || raySubConfigHasNonDefault {
			addons["ray_operator_config"] = []interface{}{rayConfig}
			hasNonDefaultConfig = true
		}
	}
	// Parallelstore CSI Driver Config: Default disabled. Include only if explicitly enabled.
	if config.ParallelstoreCsiDriverConfig != nil && config.ParallelstoreCsiDriverConfig.Enabled {
		addons["parallelstore_csi_driver_config"] = []interface{}{map[string]interface{}{"enabled": true}}
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil // Omit block if only defaults were found
	}
	return []interface{}{addons}
}

// flattenNetworkPolicy: Omit if nil or disabled (default). Check provider default.
func flattenNetworkPolicy(policy *container.NetworkPolicy) []interface{} {
	// Create data map for network policy
	data := make(map[string]interface{})

	// If policy is nil or not enabled, return default values
	if policy == nil || !policy.Enabled {
		data["enabled"] = false
		data["provider"] = "PROVIDER_UNSPECIFIED"
		return []interface{}{data}
	}

	// Policy is enabled
	data["enabled"] = true

	// Set provider, default to PROVIDER_UNSPECIFIED if not set
	if policy.Provider != "" {
		data["provider"] = policy.Provider
	} else {
		data["provider"] = "PROVIDER_UNSPECIFIED"
	}

	return []interface{}{data}
}

// flattenNodePoolAutoscaling: Omit fields if default. Block required if autoscaling enabled.
func flattenNodePoolAutoscaling(autoscaling *container.NodePoolAutoscaling) []interface{} {
	// Gated by autoscaling.Enabled check in caller (convertNodePoolData)
	if autoscaling == nil || !autoscaling.Enabled {
		// This function shouldn't be called if not enabled, but double-check
		return nil
	}
	data := make(map[string]interface{})
	// REMOVED: hasNonDefaultConfig := false // Unused

	// Min/Max count are required if block present
	data["min_node_count"] = autoscaling.MinNodeCount
	data["max_node_count"] = autoscaling.MaxNodeCount
	// REMOVED: hasNonDefaultConfig = true // Unused

	// Total counts: Omit if 0 (default)
	if autoscaling.TotalMinNodeCount > 0 {
		data["total_min_node_count"] = autoscaling.TotalMinNodeCount
		// REMOVED: hasNonDefaultConfig = true // Unused
	}
	if autoscaling.TotalMaxNodeCount > 0 {
		data["total_max_node_count"] = autoscaling.TotalMaxNodeCount
		// REMOVED: hasNonDefaultConfig = true // Unused
	}
	// Location policy: Omit if default (UNSPECIFIED)
	if autoscaling.LocationPolicy != "" && autoscaling.LocationPolicy != "LOCATION_POLICY_UNSPECIFIED" {
		data["location_policy"] = autoscaling.LocationPolicy
		// REMOVED: hasNonDefaultConfig = true // Unused
	}
	// Autoscaling profile section remains commented out as before

	// Since min/max are required, the block is always returned if called.
	return []interface{}{data}
}

// flattenNodeManagement: Omit fields if default. Check defaults (TF schema likely computes true?).
func flattenNodeManagement(mgmt *container.NodeManagement) []interface{} {
	if mgmt == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Schema: Optional=true, Computed=true. What's the computed default? Often true for repair/upgrade.
	// Assume provider computes true if omitted. Only set if explicitly false.
	if !mgmt.AutoRepair {
		data["auto_repair"] = false
		hasNonDefaultConfig = true
	}
	if !mgmt.AutoUpgrade {
		data["auto_upgrade"] = false
		hasNonDefaultConfig = true
	}

	// mgmt.UpgradeOptions is output-only, skip.

	if !hasNonDefaultConfig {
		return nil
	} // Omit block if both are default (true)
	return []interface{}{data}
}

// flattenNodePoolUpgradeSettings: Omit fields if default. Check max_surge/unavailable defaults (often 1/0?).
func flattenNodePoolUpgradeSettings(settings *container.UpgradeSettings) []interface{} {
	if settings == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Check max_surge default (often 1?). Omit if matches.
	maxSurgeDefault := int64(1) // Verify this default
	if settings.MaxSurge != maxSurgeDefault {
		data["max_surge"] = settings.MaxSurge
		hasNonDefaultConfig = true
	}
	// Check max_unavailable default (often 0?). Omit if matches.
	maxUnavailableDefault := int64(0) // Verify this default
	if settings.MaxUnavailable != maxUnavailableDefault {
		data["max_unavailable"] = settings.MaxUnavailable
		hasNonDefaultConfig = true
	}

	// Strategy: Omit if default (UNSPECIFIED or SURGE?). Assume SURGE is often default if unspecified. Check provider.
	strategyDefault := "SURGE" // Verify this default
	if settings.Strategy != "" && settings.Strategy != "NODE_POOL_UPDATE_STRATEGY_UNSPECIFIED" && settings.Strategy != strategyDefault {
		data["strategy"] = settings.Strategy
		hasNonDefaultConfig = true
	}
	// BlueGreenSettings: Omit if nil or default.
	if flattened := flattenBlueGreenSettings(settings.BlueGreenSettings); flattened != nil {
		data["blue_green_settings"] = flattened
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil
	} // Omit if only defaults found
	return []interface{}{data}
}

// flattenBlueGreenSettings: Omit fields if default. Check soak duration default ("0s").
func flattenBlueGreenSettings(settings *container.BlueGreenSettings) []interface{} {
	if settings == nil {
		return nil
	}

	// StandardRolloutPolicy is required if blue_green_settings block exists in TF.
	if settings.StandardRolloutPolicy == nil {
		fmt.Println("Warning: BlueGreenSettings present but StandardRolloutPolicy block is missing. Omitting BlueGreen block.")
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false // Track non-defaults within blue-green settings

	srp := settings.StandardRolloutPolicy
	standardRolloutPolicy := make(map[string]interface{})
	hasSrpConfig := false
	hasNonDefaultSrp := false // Track non-defaults within standard rollout

	// Check if BatchPercentage is set (assuming > 0 means it's set)
	if srp.BatchPercentage > 0.0 {
		standardRolloutPolicy["batch_percentage"] = srp.BatchPercentage
		hasSrpConfig = true
		hasNonDefaultSrp = true // Explicit batch size is non-default
		// Optional: Warn if the other field is also set unexpectedly
		if srp.BatchNodeCount > 0 {
			fmt.Printf("Warning: Both BatchPercentage (%f) and BatchNodeCount (%d) are non-zero in StandardRolloutPolicy. Using Percentage.\n", srp.BatchPercentage, srp.BatchNodeCount)
		}
	} else if srp.BatchNodeCount > 0 { // Check if BatchNodeCount is set (assuming > 0 means it's set)
		standardRolloutPolicy["batch_node_count"] = srp.BatchNodeCount
		hasSrpConfig = true
		hasNonDefaultSrp = true // Explicit batch size is non-default
	} else {
		// Neither field has a positive value, the required ExactlyOneOf is missing/invalid from API.
		fmt.Println("Warning: BlueGreen StandardRolloutPolicy has no valid non-zero batch size (Percentage or NodeCount). Omitting BlueGreen block.")
		return nil // Required field missing or invalid
	}

	// Batch Soak Duration: Default is "0s". Omit if matches.
	batchSoakDurationDefault := "0s"
	if srp.BatchSoakDuration != "" && srp.BatchSoakDuration != batchSoakDurationDefault {
		standardRolloutPolicy["batch_soak_duration"] = srp.BatchSoakDuration
		hasSrpConfig = true // Should already be true
		hasNonDefaultSrp = true
	}

	if hasSrpConfig { // Should always be true if valid
		data["standard_rollout_policy"] = []interface{}{standardRolloutPolicy}
		if hasNonDefaultSrp {
			hasNonDefaultConfig = true
		} // Mark parent block non-default if SRP is non-default
	}
	// Node Pool Soak Duration: Default seems unset/"0s"? Omit if matches.
	nodePoolSoakDurationDefault := "0s" // Verify this default
	if settings.NodePoolSoakDuration != "" && settings.NodePoolSoakDuration != nodePoolSoakDurationDefault {
		data["node_pool_soak_duration"] = settings.NodePoolSoakDuration
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil
	} // Omit if only defaults found across blue-green settings
	return []interface{}{data}
}

// flattenNodeNetworkConfig: Omit fields if default. Nil if block empty.
func flattenNodeNetworkConfig(config *container.NodeNetworkConfig) []interface{} {
	if config == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Pod Range / CIDR: Include if present
	if config.PodRange != "" {
		data["pod_range"] = config.PodRange
		hasNonDefaultConfig = true
	}
	if config.PodIpv4CidrBlock != "" {
		data["pod_ipv4_cidr_block"] = config.PodIpv4CidrBlock
		hasNonDefaultConfig = true
	}
	// Create Pod Range: Default seems false? Schema doesn't specify Default. Assume include if present.
	if config.CreatePodRange {
		data["create_pod_range"] = config.CreatePodRange
		hasNonDefaultConfig = true
	}
	// Network Performance Config: Omit if nil or default tier (TIER_UNSPECIFIED)
	if config.NetworkPerformanceConfig != nil && config.NetworkPerformanceConfig.TotalEgressBandwidthTier != "" && config.NetworkPerformanceConfig.TotalEgressBandwidthTier != "TIER_UNSPECIFIED" {
		perfConfig := map[string]interface{}{"total_egress_bandwidth_tier": config.NetworkPerformanceConfig.TotalEgressBandwidthTier}
		data["network_performance_config"] = []interface{}{perfConfig}
		hasNonDefaultConfig = true
	}
	// Pod CIDR Overprovision Config: Omit if nil or disabled:false (default)
	if config.PodCidrOverprovisionConfig != nil && config.PodCidrOverprovisionConfig.Disable { // Only include if true (non-default)
		overprovisionConfig := map[string]interface{}{"disable": config.PodCidrOverprovisionConfig.Disable}
		data["pod_cidr_overprovision_config"] = []interface{}{overprovisionConfig}
		hasNonDefaultConfig = true
	}
	// Multi-networking configs: Omit if empty lists
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
			hasNonDefaultConfig = true
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
			hasNonDefaultConfig = true
		}
	}

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenPlacementPolicy: Omit fields if default. Nil if block empty.
func flattenPlacementPolicy(policy *container.PlacementPolicy) []interface{} {
	if policy == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Type: Omit if default (TYPE_UNSPECIFIED)
	if policy.Type != "" && policy.Type != "TYPE_UNSPECIFIED" {
		data["type"] = policy.Type
		hasNonDefaultConfig = true
	}
	// TpuTopology: Omit if empty
	if policy.TpuTopology != "" {
		data["tpu_topology"] = policy.TpuTopology
		hasNonDefaultConfig = true
	}
	// PolicyName: Omit if empty
	if policy.PolicyName != "" {
		data["policy_name"] = policy.PolicyName
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenMasterAuth: Always include client_certificate_config with default issue_client_certificate = false
func flattenMasterAuth(auth *container.MasterAuth) []interface{} {
	// Create default master_auth block
	ma := make(map[string]interface{})

	// Create client_certificate_config block
	ccc := make(map[string]interface{})

	// Default to issue_client_certificate = false
	ccc["issue_client_certificate"] = false

	// Override if explicitly set to true
	if auth != nil && auth.ClientCertificateConfig != nil && auth.ClientCertificateConfig.IssueClientCertificate {
		ccc["issue_client_certificate"] = true
	}

	// Add client_certificate_config to master_auth
	ma["client_certificate_config"] = []interface{}{ccc}

	// Return master_auth block
	return []interface{}{ma}
}

// flattenPrivateClusterConfigAdapted: Omit fields if default. Nil if block empty/default.
// This one is tricky as its presence implies private cluster, even if fields are default.
// Let's keep the block if isPrivate=true, but omit internal default fields.
func flattenPrivateClusterConfigAdapted(config *container.PrivateClusterConfig, netConfig *container.NetworkConfig) []interface{} {
	isPrivateClusterEnabled := false // Based on explicit config or netConfig default
	if config != nil {
		isPrivateClusterEnabled = true // Assume config presence means intent
	} else if netConfig != nil && netConfig.DefaultEnablePrivateNodes {
		isPrivateClusterEnabled = true // Enabled via default network setting
	}

	if !isPrivateClusterEnabled {
		return nil // Not a private cluster
	}

	pcc := make(map[string]interface{})
	// REMOVED: hasNonDefaultConfig := false // Unused

	// Values from PrivateClusterConfig object
	if config != nil {
		// enable_private_endpoint: Default false? Schema doesn't say. Assume false. Omit if false.
		if config.EnablePrivateEndpoint {
			pcc["enable_private_endpoint"] = config.EnablePrivateEndpoint
			// REMOVED: hasNonDefaultConfig = true // Unused
		}
		// master_ipv4_cidr_block: Omit if empty (GKE assigns default)
		if config.MasterIpv4CidrBlock != "" {
			pcc["master_ipv4_cidr_block"] = config.MasterIpv4CidrBlock
			// REMOVED: hasNonDefaultConfig = true // Unused
		}
		// master_global_access_config: Omit if nil or enabled:false (default?)
		if config.MasterGlobalAccessConfig != nil { // Check if enabled is non-default (true)
			if config.MasterGlobalAccessConfig.Enabled {
				mgac := map[string]interface{}{"enabled": true}
				pcc["master_global_access_config"] = []interface{}{mgac}
				// REMOVED: hasNonDefaultConfig = true // Unused
			}
		}
		// private_endpoint_subnetwork: Omit if empty
		if config.PrivateEndpointSubnetwork != "" {
			pcc["private_endpoint_subnetwork"] = config.PrivateEndpointSubnetwork
			// REMOVED: hasNonDefaultConfig = true // Unused
		}
	}

	// Value from NetworkConfig object
	// enable_private_nodes: Default false? Schema doesn't say. Omit if false.
	if netConfig != nil && netConfig.DefaultEnablePrivateNodes {
		pcc["enable_private_nodes"] = netConfig.DefaultEnablePrivateNodes
		// REMOVED: hasNonDefaultConfig = true // Unused
	}

	// Ensure required 'enable' flags are present if needed (as per previous logic)
	// Add enable_private_nodes back if it wasn't set above but derived from netConfig
	if _, ok := pcc["enable_private_nodes"]; !ok && netConfig != nil && netConfig.DefaultEnablePrivateNodes {
		pcc["enable_private_nodes"] = true
	}
	// Add enable_private_endpoint back if it wasn't set above but config existed? Maybe not needed. Check TF behavior.
	// if _, ok := pcc["enable_private_endpoint"]; !ok && config != nil {
	//     pcc["enable_private_endpoint"] = config.EnablePrivateEndpoint // Or false if that's the default
	// }

	// Return nil only if the block is completely empty AND represents a non-private state (which is handled at the start)
	// OR if it becomes empty after omitting all defaults and no required flags were added back.
	if len(pcc) == 0 {
		// If it's private, maybe an empty block {} is still needed?
		// For now, assume nil is ok if everything was default.
		return nil
	}

	return []interface{}{pcc}
}

// flattenReleaseChannel: Always include with default UNSPECIFIED if not specified
func flattenReleaseChannel(rc *container.ReleaseChannel) []interface{} {
	// Return "default block" if value is absent
	if rc == nil || rc.Channel == "" {
		return []interface{}{map[string]interface{}{"channel": "UNSPECIFIED"}}
	}
	// Return block with specified channel
	return []interface{}{map[string]interface{}{"channel": rc.Channel}}
}

// flattenLoggingConfig: Omit if nil or component list is empty. Check component defaults?
func flattenLoggingConfig(config *container.LoggingConfig) []interface{} {
	if config == nil || config.ComponentConfig == nil || len(config.ComponentConfig.EnableComponents) == 0 {
		return []interface{}{map[string]interface{}{}} // Return empty block instead of nil
	}
	// TODO: Compare enabled components against default set? Complex.
	// Simple: Include if any components are specified.
	return []interface{}{map[string]interface{}{
		"enable_components": config.ComponentConfig.EnableComponents,
	}}
}

// flattenMonitoringConfig: Always include default values
func flattenMonitoringConfig(config *container.MonitoringConfig) []interface{} {
	mc := make(map[string]interface{})

	// Default components to include if not specified
	defaultComponents := []string{
		"SYSTEM_COMPONENTS",
		"STORAGE",
		"POD",
		"DEPLOYMENT",
		"STATEFULSET",
		"DAEMONSET",
		"HPA",
		"CADVISOR",
		"KUBELET",
	}

	// Set components - either from config or defaults
	if config != nil && config.ComponentConfig != nil && len(config.ComponentConfig.EnableComponents) > 0 {
		mc["enable_components"] = config.ComponentConfig.EnableComponents
	} else {
		mc["enable_components"] = defaultComponents
	}

	// Managed Prometheus: Always include with default enabled=true
	mpc := make(map[string]interface{})

	// Default to enabled=true
	mpc["enabled"] = true

	// Override if explicitly set to false
	if config != nil && config.ManagedPrometheusConfig != nil && !config.ManagedPrometheusConfig.Enabled {
		mpc["enabled"] = false
	}

	// Always include auto_monitoring_config with default scope=NONE
	amc := map[string]interface{}{"scope": "NONE"}

	// AutoMonitoringConfig is not available in the v1 API - the commented code would work with v1beta1
	// Instead, just use the default scope value
	// if config != nil && config.ManagedPrometheusConfig != nil &&
	//    config.ManagedPrometheusConfig.AutoMonitoringConfig != nil &&
	//    config.ManagedPrometheusConfig.AutoMonitoringConfig.Scope != "" {
	//	amc["scope"] = config.ManagedPrometheusConfig.AutoMonitoringConfig.Scope
	// }

	// Add auto_monitoring_config to managed_prometheus
	mpc["auto_monitoring_config"] = []interface{}{amc}

	// Add managed_prometheus to monitoring_config
	mc["managed_prometheus"] = []interface{}{mpc}

	// Advanced Datapath Observability: Include if present
	if config.AdvancedDatapathObservabilityConfig != nil {
		adoc := make(map[string]interface{})

		// Include metrics setting if true
		if config.AdvancedDatapathObservabilityConfig.EnableMetrics {
			adoc["enable_metrics"] = true
		}

		// Include relay_mode if specified
		if config.AdvancedDatapathObservabilityConfig.RelayMode != "" && config.AdvancedDatapathObservabilityConfig.RelayMode != "RELAY_MODE_UNSPECIFIED" {
			adoc["relay_mode"] = config.AdvancedDatapathObservabilityConfig.RelayMode
		}

		if len(adoc) > 0 {
			mc["advanced_datapath_observability_config"] = []interface{}{adoc}
		}
	}

	return []interface{}{mc}
}

// flattenClusterAutoscaling: Omit fields if default. Nil if block empty/default.
func flattenClusterAutoscaling(autoscaling *container.ClusterAutoscaling) []interface{} {
	if autoscaling == nil {
		return nil
	}

	ca := make(map[string]interface{})
	hasNonDefaultConfig := false // Keep this flag to decide if the block itself should be returned

	// Autoscaling Profile: Default "BALANCED". Omit if matches.

	// TODO: Verify correct field name for AutoscalingProfile in v1 API or update dependency. Assume field exists.
	// The code using autoscalingProfileDefault remains commented out, so the variable is unused.
	/*
		if autoscaling.AutoscalingProfile != "" && autoscaling.AutoscalingProfile != "PROFILE_UNSPECIFIED" && autoscaling.AutoscalingProfile != "BALANCED" { // Assuming "BALANCED" is the default to compare against
		    ca["autoscaling_profile"] = autoscaling.AutoscalingProfile
		    hasNonDefaultConfig = true
		}
	*/

	// Node Autoprovisioning section
	napConfigSet := false
	if len(autoscaling.AutoprovisioningLocations) > 0 {
		napConfigSet = true
	}
	resourceLimitsBlock := flattenResourceLimits(autoscaling.ResourceLimits)
	if resourceLimitsBlock != nil {
		napConfigSet = true
	}
	autoProvDefaultsBlock := flattenAutoprovisioningNodePoolDefaults(autoscaling.AutoprovisioningNodePoolDefaults)
	if autoProvDefaultsBlock != nil {
		napConfigSet = true
	}

	if autoscaling.EnableNodeAutoprovisioning || napConfigSet { // Include if enabled OR if sub-configs exist
		ca["enabled"] = autoscaling.EnableNodeAutoprovisioning
		hasNonDefaultConfig = true // Mark non-default if NAP section is included

		if len(autoscaling.AutoprovisioningLocations) > 0 {
			ca["autoprovisioning_locations"] = autoscaling.AutoprovisioningLocations
		}
		if resourceLimitsBlock != nil {
			ca["resource_limits"] = resourceLimitsBlock
		}
		if autoProvDefaultsBlock != nil {
			ca["autoprovisioning_node_pool_defaults"] = autoProvDefaultsBlock
		}
		if !autoscaling.EnableNodeAutoprovisioning && napConfigSet {
			ca["enabled"] = false
		}
	}

	if !hasNonDefaultConfig {
		return nil
	} // Omit if profile is default AND NAP is disabled with no sub-configs
	return []interface{}{ca}
}

// flattenResourceLimits: Simple list, return nil if empty.
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
		// resource_type is required
		if limit.ResourceType == "" {
			continue
		} // Skip invalid limit
		l["resource_type"] = limit.ResourceType
		// Min/Max: Omit if 0? Schema requires max, allows optional min.
		if limit.Minimum != 0 { // Omit if default (0)
			l["minimum"] = limit.Minimum
		}
		// Maximum is required by schema if block present. Assume non-zero is non-default.
		if limit.Maximum != 0 {
			l["maximum"] = limit.Maximum
		} else {
			continue // Skip limit if max is zero (invalid?)
		}

		result = append(result, l)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// flattenAutoprovisioningNodePoolDefaults: Omit fields if default. Nil if block empty.
func flattenAutoprovisioningNodePoolDefaults(defaults *container.AutoprovisioningNodePoolDefaults) []interface{} {
	if defaults == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// OauthScopes: Omit if empty (complex default)
	if len(defaults.OauthScopes) > 0 {
		data["oauth_scopes"] = defaults.OauthScopes
		hasNonDefaultConfig = true
	}
	// ServiceAccount: dont check default ("default" or compute SA)
	if defaults.ServiceAccount != "" {
		data["service_account"] = defaults.ServiceAccount
		hasNonDefaultConfig = true
	}
	// UpgradeSettings: Omit if nil/default
	if us := flattenNodePoolUpgradeSettings(defaults.UpgradeSettings); us != nil {
		data["upgrade_settings"] = us
		hasNonDefaultConfig = true
	}
	// Management: Omit if nil/default
	if mgmt := flattenNodeManagement(defaults.Management); mgmt != nil {
		data["management"] = mgmt
		hasNonDefaultConfig = true
	}
	// MinCpuPlatform: Omit if empty (default)
	if defaults.MinCpuPlatform != "" {
		data["min_cpu_platform"] = defaults.MinCpuPlatform
		hasNonDefaultConfig = true
	}
	// DiskSizeGb: dont check on default
	if defaults.DiskSizeGb > 0 {
		data["disk_size_gb"] = defaults.DiskSizeGb
		hasNonDefaultConfig = true
	}
	// DiskType: dont check default (pd-standard)
	if defaults.DiskType != "" {
		data["disk_type"] = defaults.DiskType
		hasNonDefaultConfig = true
	}
	// ShieldedInstanceConfig: Omit if nil/default
	if sic := flattenShieldedInstanceConfig(defaults.ShieldedInstanceConfig); sic != nil {
		data["shielded_instance_config"] = sic
		hasNonDefaultConfig = true
	}
	// BootDiskKmsKey: Omit if empty
	if defaults.BootDiskKmsKey != "" {
		data["boot_disk_kms_key"] = defaults.BootDiskKmsKey
		hasNonDefaultConfig = true
	}
	// ImageType: dont check on default (COS_CONTAINERD)
	if defaults.ImageType != "" {
		data["image_type"] = defaults.ImageType
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenDatabaseEncryption: Always include database_encryption block
func flattenDatabaseEncryption(config *container.DatabaseEncryption) []interface{} {
	// If config is nil, return a default config with state "DECRYPTED"
	if config == nil {
		de := make(map[string]interface{})
		de["state"] = "DECRYPTED"
		return []interface{}{de}
	}

	de := make(map[string]interface{})

	// Always set the state, default to "DECRYPTED" if empty or unspecified
	if config.State == "" || config.State == "DECRYPTION_STATE_UNSPECIFIED" {
		de["state"] = "DECRYPTED"
	} else {
		de["state"] = config.State
	}

	// Only include key_name if state is ENCRYPTED and key_name is provided
	if config.State == "ENCRYPTED" {
		if config.KeyName != "" {
			de["key_name"] = config.KeyName
		} else {
			fmt.Println("Warning: DatabaseEncryption state is ENCRYPTED but key_name is missing. Setting state to DECRYPTED.")
			de["state"] = "DECRYPTED"
		}
	}

	return []interface{}{de}
}

// flattenEnterpriseConfig: Always include enterprise_config block with desired_tier
func flattenEnterpriseConfig(config *container.EnterpriseConfig) []interface{} {
	// If config is nil, return a default config with desired_tier = "STANDARD"
	if config == nil {
		ec := make(map[string]interface{})
		ec["desired_tier"] = "STANDARD"
		return []interface{}{ec}
	}

	ec := make(map[string]interface{})

	// Always set the desired_tier, default to "STANDARD" if empty or unspecified
	if config.DesiredTier == "" || config.DesiredTier == "CLUSTER_TIER_UNSPECIFIED" {
		ec["desired_tier"] = "STANDARD"
	} else {
		ec["desired_tier"] = config.DesiredTier
	}

	return []interface{}{ec}
}

// flattenVerticalPodAutoscaling: Omit if default (enabled: false).
func flattenVerticalPodAutoscaling(vpa *container.VerticalPodAutoscaling) []interface{} {
	if vpa == nil || !vpa.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenBinaryAuthorization: Omit fields if default. Nil if block empty/default.
func flattenBinaryAuthorization(ba *container.BinaryAuthorization) []interface{} {
	if ba == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Map evaluation_mode directly if present, don't check against PROJECT_SINGLETON_POLICY_ENFORCE or UNSPECIFIED
	if ba.EvaluationMode != "" {
		data["evaluation_mode"] = ba.EvaluationMode
		hasNonDefaultConfig = true
	} else if ba.Enabled {
		// Don't set deprecated field if possible
		data["enabled"] = ba.Enabled
		hasNonDefaultConfig = true
	}

	// If only default settings were present (e.g., mode=ENFORCE), omit the block?
	// Requires knowing if ENFORCE is truly default state if block is omitted. Assume yes.
	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenCostManagementConfig: Omit if default (enabled: false).
func flattenCostManagementConfig(cmc *container.CostManagementConfig) []interface{} {
	if cmc == nil || !cmc.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenDnsConfig: Omit fields if default. Nil if block empty.
func flattenDnsConfig(dns *container.DNSConfig) []interface{} {
	if dns == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// cluster_dns: map directly, do not check against defaults or "UNSPECIFIED"
	if dns.ClusterDns != "" {
		data["cluster_dns"] = dns.ClusterDns
		hasNonDefaultConfig = true
	}
	// cluster_dns_scope: dont check "DNS_SCOPE_UNSPECIFIED"
	if dns.ClusterDnsScope != "" {
		data["cluster_dns_scope"] = dns.ClusterDnsScope
		hasNonDefaultConfig = true
	}
	// cluster_dns_domain: Omit if empty (default)
	if dns.ClusterDnsDomain != "" {
		data["cluster_dns_domain"] = dns.ClusterDnsDomain
		hasNonDefaultConfig = true
	}
	// TODO: Verify AdditiveVpcScopeDnsDomain in API/TF Schema. Omit if empty.
	// if dns.AdditiveVpcScopeDnsDomain != "" { data["additive_vpc_scope_dns_domain"] = dns.AdditiveVpcScopeDnsDomain; hasNonDefaultConfig = true }

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenSecurityPostureConfig: Convert security posture config
func flattenSecurityPostureConfig(config *container.SecurityPostureConfig) []interface{} {
	if config == nil {
		return nil
	}

	result := map[string]interface{}{}

	if config.Mode != "" && config.Mode != "MODE_UNSPECIFIED" {
		result["mode"] = config.Mode
	}

	if config.VulnerabilityMode != "" && config.VulnerabilityMode != "VULNERABILITY_MODE_UNSPECIFIED" {
		result["vulnerability_mode"] = config.VulnerabilityMode
	}

	if len(result) == 0 {
		return nil
	}

	return []interface{}{result}
}

// flattenIdentityServiceConfig: Omit if default (enabled: false).
func flattenIdentityServiceConfig(isc *container.IdentityServiceConfig) []interface{} {
	if isc == nil || !isc.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenMeshCertificates: Omit if default (enabled: false).
func flattenMeshCertificates(mc *container.MeshCertificates) []interface{} {
	if mc == nil || !mc.EnableCertificates { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enable_certificates": true}}
}

// flattenResourceUsageExportConfig: Omit fields if default. Nil if block empty.
func flattenResourceUsageExportConfig(ruec *container.ResourceUsageExportConfig) []interface{} {
	if ruec == nil {
		return nil
	}

	data := make(map[string]interface{})
	hasNonDefaultConfig := false

	// bigquery_destination: Omit if nil or dataset empty
	if ruec.BigqueryDestination != nil && ruec.BigqueryDestination.DatasetId != "" {
		data["bigquery_destination"] = []interface{}{map[string]interface{}{"dataset_id": ruec.BigqueryDestination.DatasetId}}
		hasNonDefaultConfig = true // Requires explicit config
	}
	// enable_network_egress_metering: Default false. Omit if false.
	if ruec.EnableNetworkEgressMetering {
		data["enable_network_egress_metering"] = ruec.EnableNetworkEgressMetering
		hasNonDefaultConfig = true
	}
	// If consumption metering struct is nil, we don't map it. TF provider handles default (true)
	if ruec.ConsumptionMeteringConfig != nil {
		data["enable_resource_consumption_metering"] = ruec.ConsumptionMeteringConfig.Enabled
		hasNonDefaultConfig = true
	}

	if !hasNonDefaultConfig {
		return nil
	}
	return []interface{}{data}
}

// flattenSecretManagerConfig: Omit if default (enabled: false).
func flattenSecretManagerConfig(smc *container.SecretManagerConfig) []interface{} {
	if smc == nil || !smc.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenServiceExternalIPsConfig: Omit if default (enabled: false).
func flattenServiceExternalIPsConfig(seic *container.ServiceExternalIPsConfig) []interface{} {
	if seic == nil || !seic.Enabled { // Default enabled: false
		return nil
	}
	return []interface{}{map[string]interface{}{"enabled": true}}
}

// flattenWorkloadIdentityConfig: Omit if nil or pool is default.
func flattenWorkloadIdentityConfig(wic *container.WorkloadIdentityConfig) []interface{} {
	if wic == nil {
		return nil
	}

	data := make(map[string]interface{})
	pool := ""

	// Use WorkloadPool field name based on current TF schema & v1 API struct.
	// The field IdentityNamespace does not exist in v1.WorkloadIdentityConfig.
	if wic.WorkloadPool != "" {
		pool = wic.WorkloadPool
	}

	// Omit if pool is empty or matches the default pattern (project-id.svc.id.goog)
	// TODO: Need project ID to check default pool name accurately.
	// Simple check: omit if empty. Provider might compute default if omitted.
	if pool != "" /* && !isDefaultWorkloadPool(pool, projectID) */ {
		data["workload_pool"] = pool
	} else {
		// If pool is empty (either from API or after default check), omit the block
		return nil
	}

	// If pool was non-empty and added to data, return the block
	return []interface{}{data}
}

// flattenGatewayApiConfig: dont check (DISABLED or UNSPECIFIED).
func flattenGatewayApiConfig(gac *container.GatewayAPIConfig) []interface{} {
	if gac == nil || gac.Channel == "" {
		return nil
	}
	return []interface{}{map[string]interface{}{"channel": gac.Channel}}
}

// flattenFleet: Fleet configuration for the cluster
func flattenFleet(c *container.Fleet) []map[string]interface{} {
	if c == nil {
		return nil
	}

	// all this attributes are computed
	// "membership":          c.Membership,
	// "membership_id":       membership_id,
	// "membership_location": membership_location,
	// "pre_registered":      c.PreRegistered,
	return []map[string]interface{}{
		{
			"project": c.Project,
		},
	}
}

// --- New Flatten Functions for Node Pool Defaults ---

// Flattens the top-level node_pool_defaults block
func flattenNodePoolDefaults(defaults *container.NodePoolDefaults) []interface{} { // Assuming API struct name
	if defaults == nil {
		return nil
	}

	npdData := make(map[string]interface{})
	hasNonDefaultConfig := false

	// Flatten the nested node_config_defaults block
	// Assuming API field name is NodeConfigDefaults
	if flattenedNCD := flattenNodeConfigDefaults(defaults.NodeConfigDefaults); flattenedNCD != nil {
		npdData["node_config_defaults"] = flattenedNCD
		hasNonDefaultConfig = true
	}

	// Add checks for any other fields directly under node_pool_defaults if they exist in API/schema

	if !hasNonDefaultConfig {
		return nil
	} // Nothing non-default in the entire block
	return []interface{}{npdData}
}

// Flattens the nested node_config_defaults block, checking internal defaults
func flattenNodeConfigDefaults(ncd *container.NodeConfigDefaults) []interface{} { // Assuming API struct name
	if ncd == nil {
		return nil
	}

	ncdData := make(map[string]interface{})
	hasNonDefaultConfig := false // Track if this nested block has anything non-default

	if !hasNonDefaultConfig {
		return nil
	} // Nothing non-default found in node_config_defaults
	return []interface{}{ncdData}
}

// flattenControlPlaneEndpointsConfig: Always include with default values
func flattenControlPlaneEndpointsConfig(config *container.ControlPlaneEndpointsConfig) []interface{} {
	result := make(map[string]interface{})

	// DNS Endpoint Config - default to allow_external_traffic = false
	dnsConfig := make(map[string]interface{})
	dnsConfig["allow_external_traffic"] = false

	// Override if explicitly set to true
	if config != nil && config.DnsEndpointConfig != nil && config.DnsEndpointConfig.AllowExternalTraffic {
		dnsConfig["allow_external_traffic"] = true
	}

	// Add endpoint if present
	if config != nil && config.DnsEndpointConfig != nil && config.DnsEndpointConfig.Endpoint != "" {
		dnsConfig["endpoint"] = config.DnsEndpointConfig.Endpoint
	}

	result["dns_endpoint_config"] = []interface{}{dnsConfig}

	// IP Endpoints Config - default to enabled = true
	ipConfig := make(map[string]interface{})
	ipConfig["enabled"] = true

	// Override if explicitly set to false
	if config != nil && config.IpEndpointsConfig != nil && !config.IpEndpointsConfig.Enabled {
		ipConfig["enabled"] = false
	}

	// Add other fields if present
	if config != nil && config.IpEndpointsConfig != nil {
		if config.IpEndpointsConfig.EnablePublicEndpoint {
			ipConfig["enable_public_endpoint"] = true
		}

		if config.IpEndpointsConfig.PublicEndpoint != "" {
			ipConfig["public_endpoint"] = config.IpEndpointsConfig.PublicEndpoint
		}

		if config.IpEndpointsConfig.PrivateEndpoint != "" {
			ipConfig["private_endpoint"] = config.IpEndpointsConfig.PrivateEndpoint
		}

		// Add authorized_networks_config if present
		if config.IpEndpointsConfig.AuthorizedNetworksConfig != nil {
			if config.IpEndpointsConfig.AuthorizedNetworksConfig.GcpPublicCidrsAccessEnabled {
				authConfig := make(map[string]interface{})
				authConfig["gcp_public_cidrs_access_enabled"] = true
				ipConfig["authorized_networks_config"] = []interface{}{authConfig}
			}
		}
	}

	result["ip_endpoints_config"] = []interface{}{ipConfig}

	return []interface{}{result}
}

func flattenNodePoolAutoConfig(c *container.NodePoolAutoConfig) []map[string]interface{} {
	if c == nil {
		return nil
	}

	result := make(map[string]interface{})
	if c.NodeKubeletConfig != nil {
		result["node_kubelet_config"] = flattenNodePoolAutoConfigNodeKubeletConfig(c.NodeKubeletConfig)
	}
	if c.NetworkTags != nil {
		result["network_tags"] = flattenNodePoolAutoConfigNetworkTags(c.NetworkTags)
	}
	if c.ResourceManagerTags != nil {
		result["resource_manager_tags"] = flattenResourceManagerTags(c.ResourceManagerTags)
	}
	if c.LinuxNodeConfig != nil {
		result["linux_node_config"] = []map[string]interface{}{
			{"cgroup_mode": c.LinuxNodeConfig.CgroupMode},
		}
	}

	return []map[string]interface{}{result}
}

func flattenNodePoolAutoConfigNetworkTags(c *container.NetworkTags) []map[string]interface{} {
	if c == nil {
		return nil
	}

	result := make(map[string]interface{})
	if c.Tags != nil {
		result["tags"] = c.Tags
	}
	return []map[string]interface{}{result}
}

func flattenNodePoolAutoConfigNodeKubeletConfig(c *container.NodeKubeletConfig) []map[string]interface{} {
	result := []map[string]interface{}{}
	if c != nil {
		result = append(result, map[string]interface{}{
			"insecure_kubelet_readonly_port_enabled": flattenInsecureKubeletReadonlyPortEnabled(c),
		})
	}
	return result
}

func flattenResourceManagerTags(c *container.ResourceManagerTags) map[string]interface{} {
	if c == nil {
		return nil
	}

	rmt := make(map[string]interface{})

	for k, v := range c.Tags {
		rmt[k] = v
	}

	return rmt
}

func flattenInsecureKubeletReadonlyPortEnabled(c *container.NodeKubeletConfig) string {
	// Convert bool from the API to the enum values used internally
	if c != nil && c.InsecureKubeletReadonlyPortEnabled {
		return "TRUE"
	}
	return "FALSE"
}
