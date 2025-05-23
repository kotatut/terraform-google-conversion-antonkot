// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/compute/NetworkFirewallPolicyPacketMirroringRule.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package compute

import (
	"reflect"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

const ComputeNetworkFirewallPolicyPacketMirroringRuleAssetType string = "compute.googleapis.com/NetworkFirewallPolicyPacketMirroringRule"

func ResourceConverterComputeNetworkFirewallPolicyPacketMirroringRule() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: ComputeNetworkFirewallPolicyPacketMirroringRuleAssetType,
		Convert:   GetComputeNetworkFirewallPolicyPacketMirroringRuleCaiObject,
	}
}

func GetComputeNetworkFirewallPolicyPacketMirroringRuleCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//compute.googleapis.com/projects/{{project}}/global/firewallPolicies/{{firewall_policy}}/getPacketMirroringRule?priority={{priority}}")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetComputeNetworkFirewallPolicyPacketMirroringRuleApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: ComputeNetworkFirewallPolicyPacketMirroringRuleAssetType,
			Resource: &cai.AssetResource{
				Version:              "beta",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/compute/beta/rest",
				DiscoveryName:        "NetworkFirewallPolicyPacketMirroringRule",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetComputeNetworkFirewallPolicyPacketMirroringRuleApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	ruleNameProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleRuleName(d.Get("rule_name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("rule_name"); !tpgresource.IsEmptyValue(reflect.ValueOf(ruleNameProp)) && (ok || !reflect.DeepEqual(v, ruleNameProp)) {
		obj["ruleName"] = ruleNameProp
	}
	descriptionProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleDescription(d.Get("description"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("description"); !tpgresource.IsEmptyValue(reflect.ValueOf(descriptionProp)) && (ok || !reflect.DeepEqual(v, descriptionProp)) {
		obj["description"] = descriptionProp
	}
	priorityProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRulePriority(d.Get("priority"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("priority"); !tpgresource.IsEmptyValue(reflect.ValueOf(priorityProp)) && (ok || !reflect.DeepEqual(v, priorityProp)) {
		obj["priority"] = priorityProp
	}
	matchProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatch(d.Get("match"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("match"); !tpgresource.IsEmptyValue(reflect.ValueOf(matchProp)) && (ok || !reflect.DeepEqual(v, matchProp)) {
		obj["match"] = matchProp
	}
	actionProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleAction(d.Get("action"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("action"); !tpgresource.IsEmptyValue(reflect.ValueOf(actionProp)) && (ok || !reflect.DeepEqual(v, actionProp)) {
		obj["action"] = actionProp
	}
	securityProfileGroupProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleSecurityProfileGroup(d.Get("security_profile_group"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("security_profile_group"); !tpgresource.IsEmptyValue(reflect.ValueOf(securityProfileGroupProp)) && (ok || !reflect.DeepEqual(v, securityProfileGroupProp)) {
		obj["securityProfileGroup"] = securityProfileGroupProp
	}
	targetSecureTagsProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTags(d.Get("target_secure_tags"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("target_secure_tags"); ok || !reflect.DeepEqual(v, targetSecureTagsProp) {
		obj["targetSecureTags"] = targetSecureTagsProp
	}
	tlsInspectProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleTlsInspect(d.Get("tls_inspect"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("tls_inspect"); !tpgresource.IsEmptyValue(reflect.ValueOf(tlsInspectProp)) && (ok || !reflect.DeepEqual(v, tlsInspectProp)) {
		obj["tlsInspect"] = tlsInspectProp
	}
	directionProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleDirection(d.Get("direction"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("direction"); !tpgresource.IsEmptyValue(reflect.ValueOf(directionProp)) && (ok || !reflect.DeepEqual(v, directionProp)) {
		obj["direction"] = directionProp
	}
	disabledProp, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleDisabled(d.Get("disabled"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("disabled"); !tpgresource.IsEmptyValue(reflect.ValueOf(disabledProp)) && (ok || !reflect.DeepEqual(v, disabledProp)) {
		obj["disabled"] = disabledProp
	}

	return obj, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleRuleName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleDescription(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRulePriority(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatch(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedSrcIpRanges, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchSrcIpRanges(original["src_ip_ranges"], d, config)
	if err != nil {
		return nil, err
	} else {
		transformed["srcIpRanges"] = transformedSrcIpRanges
	}

	transformedDestIpRanges, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchDestIpRanges(original["dest_ip_ranges"], d, config)
	if err != nil {
		return nil, err
	} else {
		transformed["destIpRanges"] = transformedDestIpRanges
	}

	transformedLayer4Configs, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4Configs(original["layer4_configs"], d, config)
	if err != nil {
		return nil, err
	} else {
		transformed["layer4Configs"] = transformedLayer4Configs
	}

	return transformed, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchSrcIpRanges(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchDestIpRanges(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4Configs(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedIpProtocol, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4ConfigsIpProtocol(original["ip_protocol"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedIpProtocol); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["ipProtocol"] = transformedIpProtocol
		}

		transformedPorts, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4ConfigsPorts(original["ports"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedPorts); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["ports"] = transformedPorts
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4ConfigsIpProtocol(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleMatchLayer4ConfigsPorts(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleAction(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleSecurityProfileGroup(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTags(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedName, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTagsName(original["name"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedName); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["name"] = transformedName
		}

		transformedState, err := expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTagsState(original["state"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedState); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["state"] = transformedState
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTagsName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleTargetSecureTagsState(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleTlsInspect(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleDirection(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeNetworkFirewallPolicyPacketMirroringRuleDisabled(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}
