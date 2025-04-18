// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/compute/SslPolicy.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package compute

import (
	"context"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

func sslPolicyCustomizeDiff(_ context.Context, diff *schema.ResourceDiff, v interface{}) error {
	profile := diff.Get("profile")
	customFeaturesCount := diff.Get("custom_features.#")

	// Validate that policy configs aren't incompatible during all phases
	// CUSTOM profile demands non-zero custom_features, and other profiles (i.e., not CUSTOM) demand zero custom_features
	if diff.HasChange("profile") || diff.HasChange("custom_features") {
		if profile.(string) == "CUSTOM" {
			if customFeaturesCount.(int) == 0 {
				return fmt.Errorf("Error in SSL Policy %s: the profile is set to %s but no custom_features are set.", diff.Get("name"), profile.(string))
			}
		} else {
			if customFeaturesCount != 0 {
				return fmt.Errorf("Error in SSL Policy %s: the profile is set to %s but using custom_features requires the profile to be CUSTOM.", diff.Get("name"), profile.(string))
			}
		}
		return nil
	}
	return nil
}

const ComputeSslPolicyAssetType string = "compute.googleapis.com/SslPolicy"

func ResourceConverterComputeSslPolicy() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: ComputeSslPolicyAssetType,
		Convert:   GetComputeSslPolicyCaiObject,
	}
}

func GetComputeSslPolicyCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//compute.googleapis.com/projects/{{project}}/global/sslPolicies/{{name}}")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetComputeSslPolicyApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: ComputeSslPolicyAssetType,
			Resource: &cai.AssetResource{
				Version:              "beta",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/compute/beta/rest",
				DiscoveryName:        "SslPolicy",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetComputeSslPolicyApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	descriptionProp, err := expandComputeSslPolicyDescription(d.Get("description"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("description"); !tpgresource.IsEmptyValue(reflect.ValueOf(descriptionProp)) && (ok || !reflect.DeepEqual(v, descriptionProp)) {
		obj["description"] = descriptionProp
	}
	nameProp, err := expandComputeSslPolicyName(d.Get("name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("name"); !tpgresource.IsEmptyValue(reflect.ValueOf(nameProp)) && (ok || !reflect.DeepEqual(v, nameProp)) {
		obj["name"] = nameProp
	}
	profileProp, err := expandComputeSslPolicyProfile(d.Get("profile"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("profile"); !tpgresource.IsEmptyValue(reflect.ValueOf(profileProp)) && (ok || !reflect.DeepEqual(v, profileProp)) {
		obj["profile"] = profileProp
	}
	minTlsVersionProp, err := expandComputeSslPolicyMinTlsVersion(d.Get("min_tls_version"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("min_tls_version"); !tpgresource.IsEmptyValue(reflect.ValueOf(minTlsVersionProp)) && (ok || !reflect.DeepEqual(v, minTlsVersionProp)) {
		obj["minTlsVersion"] = minTlsVersionProp
	}
	customFeaturesProp, err := expandComputeSslPolicyCustomFeatures(d.Get("custom_features"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("custom_features"); !tpgresource.IsEmptyValue(reflect.ValueOf(customFeaturesProp)) && (ok || !reflect.DeepEqual(v, customFeaturesProp)) {
		obj["customFeatures"] = customFeaturesProp
	}

	return obj, nil
}

func expandComputeSslPolicyDescription(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSslPolicyName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSslPolicyProfile(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSslPolicyMinTlsVersion(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSslPolicyCustomFeatures(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	v = v.(*schema.Set).List()
	return v, nil
}
