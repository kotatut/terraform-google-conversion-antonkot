// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/vertexai/FeatureGroup.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/tgc/resource_converter_iam.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package vertexai

import (
	"fmt"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/tfplan2cai/converters/google/resources/cai"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

// Provide a separate asset type constant so we don't have to worry about name conflicts between IAM and non-IAM converter files
const VertexAIFeatureGroupIAMAssetType string = "aiplatform.googleapis.com/FeatureGroup"

func ResourceConverterVertexAIFeatureGroupIamPolicy() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         VertexAIFeatureGroupIAMAssetType,
		Convert:           GetVertexAIFeatureGroupIamPolicyCaiObject,
		MergeCreateUpdate: MergeVertexAIFeatureGroupIamPolicy,
	}
}

func ResourceConverterVertexAIFeatureGroupIamBinding() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         VertexAIFeatureGroupIAMAssetType,
		Convert:           GetVertexAIFeatureGroupIamBindingCaiObject,
		FetchFullResource: FetchVertexAIFeatureGroupIamPolicy,
		MergeCreateUpdate: MergeVertexAIFeatureGroupIamBinding,
		MergeDelete:       MergeVertexAIFeatureGroupIamBindingDelete,
	}
}

func ResourceConverterVertexAIFeatureGroupIamMember() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType:         VertexAIFeatureGroupIAMAssetType,
		Convert:           GetVertexAIFeatureGroupIamMemberCaiObject,
		FetchFullResource: FetchVertexAIFeatureGroupIamPolicy,
		MergeCreateUpdate: MergeVertexAIFeatureGroupIamMember,
		MergeDelete:       MergeVertexAIFeatureGroupIamMemberDelete,
	}
}

func GetVertexAIFeatureGroupIamPolicyCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newVertexAIFeatureGroupIamAsset(d, config, cai.ExpandIamPolicyBindings)
}

func GetVertexAIFeatureGroupIamBindingCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newVertexAIFeatureGroupIamAsset(d, config, cai.ExpandIamRoleBindings)
}

func GetVertexAIFeatureGroupIamMemberCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	return newVertexAIFeatureGroupIamAsset(d, config, cai.ExpandIamMemberBindings)
}

func MergeVertexAIFeatureGroupIamPolicy(existing, incoming cai.Asset) cai.Asset {
	existing.IAMPolicy = incoming.IAMPolicy
	return existing
}

func MergeVertexAIFeatureGroupIamBinding(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAuthoritativeBindings)
}

func MergeVertexAIFeatureGroupIamBindingDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAuthoritativeBindings)
}

func MergeVertexAIFeatureGroupIamMember(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeIamAssets(existing, incoming, cai.MergeAdditiveBindings)
}

func MergeVertexAIFeatureGroupIamMemberDelete(existing, incoming cai.Asset) cai.Asset {
	return cai.MergeDeleteIamAssets(existing, incoming, cai.MergeDeleteAdditiveBindings)
}

func newVertexAIFeatureGroupIamAsset(
	d tpgresource.TerraformResourceData,
	config *transport_tpg.Config,
	expandBindings func(d tpgresource.TerraformResourceData) ([]cai.IAMBinding, error),
) ([]cai.Asset, error) {
	bindings, err := expandBindings(d)
	if err != nil {
		return []cai.Asset{}, fmt.Errorf("expanding bindings: %v", err)
	}

	name, err := cai.AssetName(d, config, "//aiplatform.googleapis.com/projects/{{project}}/locations/{{region}}/featureGroups/{{feature_group}}")
	if err != nil {
		return []cai.Asset{}, err
	}

	return []cai.Asset{{
		Name: name,
		Type: VertexAIFeatureGroupIAMAssetType,
		IAMPolicy: &cai.IAMPolicy{
			Bindings: bindings,
		},
	}}, nil
}

func FetchVertexAIFeatureGroupIamPolicy(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (cai.Asset, error) {
	// Check if the identity field returns a value
	if _, ok := d.GetOk("region"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}
	if _, ok := d.GetOk("feature_group"); !ok {
		return cai.Asset{}, cai.ErrEmptyIdentityField
	}

	return cai.FetchIamPolicy(
		VertexAIFeatureGroupIamUpdaterProducer,
		d,
		config,
		"//aiplatform.googleapis.com/projects/{{project}}/locations/{{region}}/featureGroups/{{feature_group}}",
		VertexAIFeatureGroupIAMAssetType,
	)
}
