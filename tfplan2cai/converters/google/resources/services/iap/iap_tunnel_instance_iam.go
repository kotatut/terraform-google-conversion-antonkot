// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/iap/TunnelInstance.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter_iam.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package iap

import (
	"fmt"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

// Provide a separate asset type constant so we don't have to worry about name conflicts between IAM and non-IAM converter files
const IapTunnelInstanceIAMAssetType string = "iap.googleapis.com/TunnelInstance"

func ResourceConverterIapTunnelInstanceIamPolicy() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         IapTunnelInstanceIAMAssetType,
		Convert:           GetIapTunnelInstanceIamPolicyCaiObject,
		MergeCreateUpdate: MergeIapTunnelInstanceIamPolicy,
	}
}

func ResourceConverterIapTunnelInstanceIamBinding() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         IapTunnelInstanceIAMAssetType,
		Convert:           GetIapTunnelInstanceIamBindingCaiObject,
		FetchFullResource: FetchIapTunnelInstanceIamPolicy,
		MergeCreateUpdate: MergeIapTunnelInstanceIamBinding,
		MergeDelete:       MergeIapTunnelInstanceIamBindingDelete,
	}
}

func ResourceConverterIapTunnelInstanceIamMember() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         IapTunnelInstanceIAMAssetType,
		Convert:           GetIapTunnelInstanceIamMemberCaiObject,
		FetchFullResource: FetchIapTunnelInstanceIamPolicy,
		MergeCreateUpdate: MergeIapTunnelInstanceIamMember,
		MergeDelete:       MergeIapTunnelInstanceIamMemberDelete,
	}
}

func GetIapTunnelInstanceIamPolicyCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newIapTunnelInstanceIamAsset(d, config, cai.ExpandIamPolicyBindings)
}

func GetIapTunnelInstanceIamBindingCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newIapTunnelInstanceIamAsset(d, config, cai.ExpandIamRoleBindings)
}

func GetIapTunnelInstanceIamMemberCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newIapTunnelInstanceIamAsset(d, config, cai.ExpandIamMemberBindings)
}

func MergeIapTunnelInstanceIamPolicy(existing, incoming cai.Asset) cai.Asset {
	existing.IAMPolicy = incoming.IAMPolicy
	return existing
}

func MergeIapTunnelInstanceIamBinding(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAuthoritativeBindings)
}

func MergeIapTunnelInstanceIamBindingDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAuthoritativeBindings)
}

func MergeIapTunnelInstanceIamMember(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAdditiveBindings)
}

func MergeIapTunnelInstanceIamMemberDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAdditiveBindings)
}

func newIapTunnelInstanceIamAsset(
	d tpgresource.TerraformResourceData,
	config *transport_tpg.Config,
	expandBindings func(d tpgresource.TerraformResourceData) ([]cai.IAMBinding, error),
) ([]cai.Asset, error) {
	bindings, err := expandBindings(d)
	if err != nil {
		return []cai.Asset{}, fmt.Errorf("expanding bindings: %v", err)
	}

	name, err := cai.AssetName(d, config, "//iap.googleapis.com/projects/{{project}}/iap_tunnel/zones/{{zone}}/instances/{{instance}}")
	if err != nil {
		return []cai.Asset{}, err
	}

	return []cai.Asset{{
		Name: name,
		Type: IapTunnelInstanceIAMAssetType,
		IAMPolicy: &cai.IAMPolicy{
			Bindings: bindings,
		},
	}}, nil
}

func FetchIapTunnelInstanceIamPolicy(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (cai.Asset, error) {
	// Check if the identity field returns a value
	if _, ok := d.GetOk("zone"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}
	if _, ok := d.GetOk("instance"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}

	return cai.FetchIamPolicy(
		IapTunnelInstanceIamUpdaterProducer,
		d,
		config,
		"//iap.googleapis.com/projects/{{project}}/iap_tunnel/zones/{{zone}}/instances/{{instance}}",
		IapTunnelInstanceIAMAssetType,
	)
}
