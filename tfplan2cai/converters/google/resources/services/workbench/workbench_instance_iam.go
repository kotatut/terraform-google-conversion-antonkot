// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/workbench/Instance.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter_iam.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package workbench

import (
	"fmt"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

// Provide a separate asset type constant so we don't have to worry about name conflicts between IAM and non-IAM converter files
const WorkbenchInstanceIAMAssetType string = "notebooks.googleapis.com/Instance"

func ResourceConverterWorkbenchInstanceIamPolicy() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         WorkbenchInstanceIAMAssetType,
		Convert:           GetWorkbenchInstanceIamPolicyCaiObject,
		MergeCreateUpdate: MergeWorkbenchInstanceIamPolicy,
	}
}

func ResourceConverterWorkbenchInstanceIamBinding() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         WorkbenchInstanceIAMAssetType,
		Convert:           GetWorkbenchInstanceIamBindingCaiObject,
		FetchFullResource: FetchWorkbenchInstanceIamPolicy,
		MergeCreateUpdate: MergeWorkbenchInstanceIamBinding,
		MergeDelete:       MergeWorkbenchInstanceIamBindingDelete,
	}
}

func ResourceConverterWorkbenchInstanceIamMember() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         WorkbenchInstanceIAMAssetType,
		Convert:           GetWorkbenchInstanceIamMemberCaiObject,
		FetchFullResource: FetchWorkbenchInstanceIamPolicy,
		MergeCreateUpdate: MergeWorkbenchInstanceIamMember,
		MergeDelete:       MergeWorkbenchInstanceIamMemberDelete,
	}
}

func GetWorkbenchInstanceIamPolicyCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newWorkbenchInstanceIamAsset(d, config, cai.ExpandIamPolicyBindings)
}

func GetWorkbenchInstanceIamBindingCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newWorkbenchInstanceIamAsset(d, config, cai.ExpandIamRoleBindings)
}

func GetWorkbenchInstanceIamMemberCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newWorkbenchInstanceIamAsset(d, config, cai.ExpandIamMemberBindings)
}

func MergeWorkbenchInstanceIamPolicy(existing, incoming cai.Asset) cai.Asset {
	existing.IAMPolicy = incoming.IAMPolicy
	return existing
}

func MergeWorkbenchInstanceIamBinding(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAuthoritativeBindings)
}

func MergeWorkbenchInstanceIamBindingDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAuthoritativeBindings)
}

func MergeWorkbenchInstanceIamMember(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAdditiveBindings)
}

func MergeWorkbenchInstanceIamMemberDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAdditiveBindings)
}

func newWorkbenchInstanceIamAsset(
	d tpgresource.TerraformResourceData,
	config *transport_tpg.Config,
	expandBindings func(d tpgresource.TerraformResourceData) ([]cai.IAMBinding, error),
) ([]cai.Asset, error) {
	bindings, err := expandBindings(d)
	if err != nil {
		return []cai.Asset{}, fmt.Errorf("expanding bindings: %v", err)
	}

	name, err := cai.AssetName(d, config, "//notebooks.googleapis.com/projects/{{project}}/locations/{{location}}/instances/{{name}}")
	if err != nil {
		return []cai.Asset{}, err
	}

	return []cai.Asset{{
		Name: name,
		Type: WorkbenchInstanceIAMAssetType,
		IAMPolicy: &cai.IAMPolicy{
			Bindings: bindings,
		},
	}}, nil
}

func FetchWorkbenchInstanceIamPolicy(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (cai.Asset, error) {
	// Check if the identity field returns a value
	if _, ok := d.GetOk("location"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}
	if _, ok := d.GetOk("name"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}

	return cai.FetchIamPolicy(
		WorkbenchInstanceIamUpdaterProducer,
		d,
		config,
		"//notebooks.googleapis.com/projects/{{project}}/locations/{{location}}/instances/{{name}}",
		WorkbenchInstanceIAMAssetType,
	)
}
