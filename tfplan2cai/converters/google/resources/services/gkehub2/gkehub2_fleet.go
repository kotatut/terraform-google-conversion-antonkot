// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/gkehub2/Fleet.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package gkehub2

import (
	"reflect"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

const GKEHub2FleetAssetType string = "gkehub.googleapis.com/Fleet"

func ResourceConverterGKEHub2Fleet() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: GKEHub2FleetAssetType,
		Convert:   GetGKEHub2FleetCaiObject,
	}
}

func GetGKEHub2FleetCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//gkehub.googleapis.com/projects/{{project}}/locations/global/fleets/default")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetGKEHub2FleetApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: GKEHub2FleetAssetType,
			Resource: &cai.AssetResource{
				Version:              "v1beta",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/gkehub/v1beta/rest",
				DiscoveryName:        "Fleet",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetGKEHub2FleetApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	displayNameProp, err := expandGKEHub2FleetDisplayName(d.Get("display_name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("display_name"); !tpgresource.IsEmptyValue(reflect.ValueOf(displayNameProp)) && (ok || !reflect.DeepEqual(v, displayNameProp)) {
		obj["displayName"] = displayNameProp
	}
	defaultClusterConfigProp, err := expandGKEHub2FleetDefaultClusterConfig(d.Get("default_cluster_config"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("default_cluster_config"); !tpgresource.IsEmptyValue(reflect.ValueOf(defaultClusterConfigProp)) && (ok || !reflect.DeepEqual(v, defaultClusterConfigProp)) {
		obj["defaultClusterConfig"] = defaultClusterConfigProp
	}

	return obj, nil
}

func expandGKEHub2FleetDisplayName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandGKEHub2FleetDefaultClusterConfig(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedBinaryAuthorizationConfig, err := expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfig(original["binary_authorization_config"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedBinaryAuthorizationConfig); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["binaryAuthorizationConfig"] = transformedBinaryAuthorizationConfig
	}

	transformedSecurityPostureConfig, err := expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfig(original["security_posture_config"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedSecurityPostureConfig); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["securityPostureConfig"] = transformedSecurityPostureConfig
	}

	return transformed, nil
}

func expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfig(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedEvaluationMode, err := expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigEvaluationMode(original["evaluation_mode"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedEvaluationMode); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["evaluationMode"] = transformedEvaluationMode
	}

	transformedPolicyBindings, err := expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigPolicyBindings(original["policy_bindings"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedPolicyBindings); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["policyBindings"] = transformedPolicyBindings
	}

	return transformed, nil
}

func expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigEvaluationMode(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigPolicyBindings(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedName, err := expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigPolicyBindingsName(original["name"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedName); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["name"] = transformedName
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandGKEHub2FleetDefaultClusterConfigBinaryAuthorizationConfigPolicyBindingsName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfig(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedMode, err := expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfigMode(original["mode"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedMode); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["mode"] = transformedMode
	}

	transformedVulnerabilityMode, err := expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfigVulnerabilityMode(original["vulnerability_mode"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedVulnerabilityMode); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["vulnerabilityMode"] = transformedVulnerabilityMode
	}

	return transformed, nil
}

func expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfigMode(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandGKEHub2FleetDefaultClusterConfigSecurityPostureConfigVulnerabilityMode(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}
