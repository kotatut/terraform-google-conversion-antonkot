// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This file is automatically generated by Magic Modules and manual
//     changes will be clobbered when the file is regenerated.
//
//     Please read more about how to change this file in
//     .github/CONTRIBUTING.md.
//
// ----------------------------------------------------------------------------

package google

import "reflect"

func GetGKEHubMembershipCaiObject(d TerraformResourceData, config *Config) ([]Asset, error) {
	name, err := assetName(d, config, "//gkehub.googleapis.com/{{name}}")
	if err != nil {
		return []Asset{}, err
	}
	if obj, err := GetGKEHubMembershipApiObject(d, config); err == nil {
		return []Asset{{
			Name: name,
			Type: "gkehub.googleapis.com/Membership",
			Resource: &AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/gkehub/v1/rest",
				DiscoveryName:        "Membership",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []Asset{}, err
	}
}

func GetGKEHubMembershipApiObject(d TerraformResourceData, config *Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	labelsProp, err := expandGKEHubMembershipLabels(d.Get("labels"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("labels"); !isEmptyValue(reflect.ValueOf(labelsProp)) && (ok || !reflect.DeepEqual(v, labelsProp)) {
		obj["labels"] = labelsProp
	}
	endpointProp, err := expandGKEHubMembershipEndpoint(d.Get("endpoint"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("endpoint"); !isEmptyValue(reflect.ValueOf(endpointProp)) && (ok || !reflect.DeepEqual(v, endpointProp)) {
		obj["endpoint"] = endpointProp
	}
	authorityProp, err := expandGKEHubMembershipAuthority(d.Get("authority"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("authority"); !isEmptyValue(reflect.ValueOf(authorityProp)) && (ok || !reflect.DeepEqual(v, authorityProp)) {
		obj["authority"] = authorityProp
	}

	return obj, nil
}

func expandGKEHubMembershipLabels(v interface{}, d TerraformResourceData, config *Config) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	m := make(map[string]string)
	for k, val := range v.(map[string]interface{}) {
		m[k] = val.(string)
	}
	return m, nil
}

func expandGKEHubMembershipEndpoint(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedGkeCluster, err := expandGKEHubMembershipEndpointGkeCluster(original["gke_cluster"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedGkeCluster); val.IsValid() && !isEmptyValue(val) {
		transformed["gkeCluster"] = transformedGkeCluster
	}

	return transformed, nil
}

func expandGKEHubMembershipEndpointGkeCluster(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedResourceLink, err := expandGKEHubMembershipEndpointGkeClusterResourceLink(original["resource_link"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedResourceLink); val.IsValid() && !isEmptyValue(val) {
		transformed["resourceLink"] = transformedResourceLink
	}

	return transformed, nil
}

func expandGKEHubMembershipEndpointGkeClusterResourceLink(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandGKEHubMembershipAuthority(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedIssuer, err := expandGKEHubMembershipAuthorityIssuer(original["issuer"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedIssuer); val.IsValid() && !isEmptyValue(val) {
		transformed["issuer"] = transformedIssuer
	}

	return transformed, nil
}

func expandGKEHubMembershipAuthorityIssuer(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}
