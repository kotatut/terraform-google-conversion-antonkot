// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/biglake/Database.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package biglake

import (
	"reflect"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

const BiglakeDatabaseAssetType string = "biglake.googleapis.com/Database"

func ResourceConverterBiglakeDatabase() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: BiglakeDatabaseAssetType,
		Convert:   GetBiglakeDatabaseCaiObject,
	}
}

func GetBiglakeDatabaseCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//biglake.googleapis.com/{{catalog}}/databases/{{name}}")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetBiglakeDatabaseApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: BiglakeDatabaseAssetType,
			Resource: &cai.AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/biglake/v1/rest",
				DiscoveryName:        "Database",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetBiglakeDatabaseApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	typeProp, err := expandBiglakeDatabaseType(d.Get("type"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("type"); !tpgresource.IsEmptyValue(reflect.ValueOf(typeProp)) && (ok || !reflect.DeepEqual(v, typeProp)) {
		obj["type"] = typeProp
	}
	hiveOptionsProp, err := expandBiglakeDatabaseHiveOptions(d.Get("hive_options"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("hive_options"); !tpgresource.IsEmptyValue(reflect.ValueOf(hiveOptionsProp)) && (ok || !reflect.DeepEqual(v, hiveOptionsProp)) {
		obj["hiveOptions"] = hiveOptionsProp
	}

	return obj, nil
}

func expandBiglakeDatabaseType(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandBiglakeDatabaseHiveOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedLocationUri, err := expandBiglakeDatabaseHiveOptionsLocationUri(original["location_uri"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedLocationUri); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["locationUri"] = transformedLocationUri
	}

	transformedParameters, err := expandBiglakeDatabaseHiveOptionsParameters(original["parameters"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedParameters); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["parameters"] = transformedParameters
	}

	return transformed, nil
}

func expandBiglakeDatabaseHiveOptionsLocationUri(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandBiglakeDatabaseHiveOptionsParameters(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	m := make(map[string]string)
	for k, val := range v.(map[string]interface{}) {
		m[k] = val.(string)
	}
	return m, nil
}
