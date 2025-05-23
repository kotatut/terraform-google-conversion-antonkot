// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/backupdr/BackupPlanAssociation.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package backupdr

import (
	"reflect"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

const BackupDRBackupPlanAssociationAssetType string = "backupdr.googleapis.com/BackupPlanAssociation"

func ResourceConverterBackupDRBackupPlanAssociation() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: BackupDRBackupPlanAssociationAssetType,
		Convert:   GetBackupDRBackupPlanAssociationCaiObject,
	}
}

func GetBackupDRBackupPlanAssociationCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//backupdr.googleapis.com/projects/{{project}}/locations/{{location}}/backupPlanAssociations/{{backup_plan_association_id}}")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetBackupDRBackupPlanAssociationApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: BackupDRBackupPlanAssociationAssetType,
			Resource: &cai.AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/backupdr/v1/rest",
				DiscoveryName:        "BackupPlanAssociation",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetBackupDRBackupPlanAssociationApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	resourceProp, err := expandBackupDRBackupPlanAssociationResource(d.Get("resource"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("resource"); !tpgresource.IsEmptyValue(reflect.ValueOf(resourceProp)) && (ok || !reflect.DeepEqual(v, resourceProp)) {
		obj["resource"] = resourceProp
	}
	backupPlanProp, err := expandBackupDRBackupPlanAssociationBackupPlan(d.Get("backup_plan"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("backup_plan"); !tpgresource.IsEmptyValue(reflect.ValueOf(backupPlanProp)) && (ok || !reflect.DeepEqual(v, backupPlanProp)) {
		obj["backupPlan"] = backupPlanProp
	}
	resourceTypeProp, err := expandBackupDRBackupPlanAssociationResourceType(d.Get("resource_type"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("resource_type"); !tpgresource.IsEmptyValue(reflect.ValueOf(resourceTypeProp)) && (ok || !reflect.DeepEqual(v, resourceTypeProp)) {
		obj["resourceType"] = resourceTypeProp
	}

	return obj, nil
}

func expandBackupDRBackupPlanAssociationResource(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandBackupDRBackupPlanAssociationBackupPlan(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandBackupDRBackupPlanAssociationResourceType(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}
