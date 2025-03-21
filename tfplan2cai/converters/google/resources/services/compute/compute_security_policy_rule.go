// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/compute/SecurityPolicyRule.yaml
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

const ComputeSecurityPolicyRuleAssetType string = "compute.googleapis.com/SecurityPolicyRule"

func ResourceConverterComputeSecurityPolicyRule() cai.ResourceConverter {
	return cai.ResourceConverter{
		AssetType: ComputeSecurityPolicyRuleAssetType,
		Convert:   GetComputeSecurityPolicyRuleCaiObject,
	}
}

func GetComputeSecurityPolicyRuleCaiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) ([]cai.Asset, error) {
	name, err := cai.AssetName(d, config, "//compute.googleapis.com/projects/{{project}}/global/securityPolicies/{{security_policy}}/getRule?priority={{priority}}")
	if err != nil {
		return []cai.Asset{}, err
	}
	if obj, err := GetComputeSecurityPolicyRuleApiObject(d, config); err == nil {
		return []cai.Asset{{
			Name: name,
			Type: ComputeSecurityPolicyRuleAssetType,
			Resource: &cai.AssetResource{
				Version:              "beta",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/compute/beta/rest",
				DiscoveryName:        "SecurityPolicyRule",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []cai.Asset{}, err
	}
}

func GetComputeSecurityPolicyRuleApiObject(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	descriptionProp, err := expandComputeSecurityPolicyRuleDescription(d.Get("description"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("description"); !tpgresource.IsEmptyValue(reflect.ValueOf(descriptionProp)) && (ok || !reflect.DeepEqual(v, descriptionProp)) {
		obj["description"] = descriptionProp
	}
	priorityProp, err := expandComputeSecurityPolicyRulePriority(d.Get("priority"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("priority"); !tpgresource.IsEmptyValue(reflect.ValueOf(priorityProp)) && (ok || !reflect.DeepEqual(v, priorityProp)) {
		obj["priority"] = priorityProp
	}
	matchProp, err := expandComputeSecurityPolicyRuleMatch(d.Get("match"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("match"); !tpgresource.IsEmptyValue(reflect.ValueOf(matchProp)) && (ok || !reflect.DeepEqual(v, matchProp)) {
		obj["match"] = matchProp
	}
	preconfiguredWafConfigProp, err := expandComputeSecurityPolicyRulePreconfiguredWafConfig(d.Get("preconfigured_waf_config"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("preconfigured_waf_config"); !tpgresource.IsEmptyValue(reflect.ValueOf(preconfiguredWafConfigProp)) && (ok || !reflect.DeepEqual(v, preconfiguredWafConfigProp)) {
		obj["preconfiguredWafConfig"] = preconfiguredWafConfigProp
	}
	actionProp, err := expandComputeSecurityPolicyRuleAction(d.Get("action"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("action"); !tpgresource.IsEmptyValue(reflect.ValueOf(actionProp)) && (ok || !reflect.DeepEqual(v, actionProp)) {
		obj["action"] = actionProp
	}
	rateLimitOptionsProp, err := expandComputeSecurityPolicyRuleRateLimitOptions(d.Get("rate_limit_options"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("rate_limit_options"); !tpgresource.IsEmptyValue(reflect.ValueOf(rateLimitOptionsProp)) && (ok || !reflect.DeepEqual(v, rateLimitOptionsProp)) {
		obj["rateLimitOptions"] = rateLimitOptionsProp
	}
	redirectOptionsProp, err := expandComputeSecurityPolicyRuleRedirectOptions(d.Get("redirect_options"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("redirect_options"); !tpgresource.IsEmptyValue(reflect.ValueOf(redirectOptionsProp)) && (ok || !reflect.DeepEqual(v, redirectOptionsProp)) {
		obj["redirectOptions"] = redirectOptionsProp
	}
	headerActionProp, err := expandComputeSecurityPolicyRuleHeaderAction(d.Get("header_action"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("header_action"); !tpgresource.IsEmptyValue(reflect.ValueOf(headerActionProp)) && (ok || !reflect.DeepEqual(v, headerActionProp)) {
		obj["headerAction"] = headerActionProp
	}
	previewProp, err := expandComputeSecurityPolicyRulePreview(d.Get("preview"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("preview"); ok || !reflect.DeepEqual(v, previewProp) {
		obj["preview"] = previewProp
	}

	return obj, nil
}

func expandComputeSecurityPolicyRuleDescription(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePriority(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleMatch(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedVersionedExpr, err := expandComputeSecurityPolicyRuleMatchVersionedExpr(original["versioned_expr"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedVersionedExpr); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["versionedExpr"] = transformedVersionedExpr
	}

	transformedExpr, err := expandComputeSecurityPolicyRuleMatchExpr(original["expr"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExpr); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["expr"] = transformedExpr
	}

	transformedExprOptions, err := expandComputeSecurityPolicyRuleMatchExprOptions(original["expr_options"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExprOptions); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["exprOptions"] = transformedExprOptions
	}

	transformedConfig, err := expandComputeSecurityPolicyRuleMatchConfig(original["config"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedConfig); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["config"] = transformedConfig
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleMatchVersionedExpr(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleMatchExpr(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedExpression, err := expandComputeSecurityPolicyRuleMatchExprExpression(original["expression"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExpression); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["expression"] = transformedExpression
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleMatchExprExpression(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleMatchExprOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedRecaptchaOptions, err := expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptions(original["recaptcha_options"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedRecaptchaOptions); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["recaptchaOptions"] = transformedRecaptchaOptions
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedActionTokenSiteKeys, err := expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptionsActionTokenSiteKeys(original["action_token_site_keys"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedActionTokenSiteKeys); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["actionTokenSiteKeys"] = transformedActionTokenSiteKeys
	}

	transformedSessionTokenSiteKeys, err := expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptionsSessionTokenSiteKeys(original["session_token_site_keys"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedSessionTokenSiteKeys); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["sessionTokenSiteKeys"] = transformedSessionTokenSiteKeys
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptionsActionTokenSiteKeys(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleMatchExprOptionsRecaptchaOptionsSessionTokenSiteKeys(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleMatchConfig(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedSrcIpRanges, err := expandComputeSecurityPolicyRuleMatchConfigSrcIpRanges(original["src_ip_ranges"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedSrcIpRanges); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["srcIpRanges"] = transformedSrcIpRanges
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleMatchConfigSrcIpRanges(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfig(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedExclusion, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusion(original["exclusion"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExclusion); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["exclusions"] = transformedExclusion
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusion(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedRequestHeader, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeader(original["request_header"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedRequestHeader); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["requestHeadersToExclude"] = transformedRequestHeader
		}

		transformedRequestCookie, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookie(original["request_cookie"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedRequestCookie); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["requestCookiesToExclude"] = transformedRequestCookie
		}

		transformedRequestUri, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUri(original["request_uri"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedRequestUri); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["requestUrisToExclude"] = transformedRequestUri
		}

		transformedRequestQueryParam, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParam(original["request_query_param"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedRequestQueryParam); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["requestQueryParamsToExclude"] = transformedRequestQueryParam
		}

		transformedTargetRuleSet, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionTargetRuleSet(original["target_rule_set"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedTargetRuleSet); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["targetRuleSet"] = transformedTargetRuleSet
		}

		transformedTargetRuleIds, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionTargetRuleIds(original["target_rule_ids"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedTargetRuleIds); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["targetRuleIds"] = transformedTargetRuleIds
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeader(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedOperator, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeaderOperator(original["operator"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedOperator); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["op"] = transformedOperator
		}

		transformedValue, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeaderValue(original["value"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedValue); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["val"] = transformedValue
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeaderOperator(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestHeaderValue(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookie(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedOperator, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookieOperator(original["operator"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedOperator); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["op"] = transformedOperator
		}

		transformedValue, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookieValue(original["value"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedValue); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["val"] = transformedValue
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookieOperator(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestCookieValue(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUri(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedOperator, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUriOperator(original["operator"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedOperator); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["op"] = transformedOperator
		}

		transformedValue, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUriValue(original["value"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedValue); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["val"] = transformedValue
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUriOperator(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestUriValue(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParam(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedOperator, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParamOperator(original["operator"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedOperator); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["op"] = transformedOperator
		}

		transformedValue, err := expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParamValue(original["value"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedValue); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["val"] = transformedValue
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParamOperator(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionRequestQueryParamValue(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionTargetRuleSet(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreconfiguredWafConfigExclusionTargetRuleIds(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleAction(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedRateLimitThreshold, err := expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThreshold(original["rate_limit_threshold"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedRateLimitThreshold); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["rateLimitThreshold"] = transformedRateLimitThreshold
	}

	transformedConformAction, err := expandComputeSecurityPolicyRuleRateLimitOptionsConformAction(original["conform_action"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedConformAction); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["conformAction"] = transformedConformAction
	}

	transformedExceedRedirectOptions, err := expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptions(original["exceed_redirect_options"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExceedRedirectOptions); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["exceedRedirectOptions"] = transformedExceedRedirectOptions
	}

	transformedExceedAction, err := expandComputeSecurityPolicyRuleRateLimitOptionsExceedAction(original["exceed_action"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedExceedAction); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["exceedAction"] = transformedExceedAction
	}

	transformedEnforceOnKey, err := expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKey(original["enforce_on_key"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedEnforceOnKey); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["enforceOnKey"] = transformedEnforceOnKey
	}

	transformedEnforceOnKeyName, err := expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyName(original["enforce_on_key_name"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedEnforceOnKeyName); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["enforceOnKeyName"] = transformedEnforceOnKeyName
	}

	transformedEnforceOnKeyConfigs, err := expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigs(original["enforce_on_key_configs"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedEnforceOnKeyConfigs); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["enforceOnKeyConfigs"] = transformedEnforceOnKeyConfigs
	}

	transformedBanThreshold, err := expandComputeSecurityPolicyRuleRateLimitOptionsBanThreshold(original["ban_threshold"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedBanThreshold); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["banThreshold"] = transformedBanThreshold
	}

	transformedBanDurationSec, err := expandComputeSecurityPolicyRuleRateLimitOptionsBanDurationSec(original["ban_duration_sec"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedBanDurationSec); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["banDurationSec"] = transformedBanDurationSec
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThreshold(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedCount, err := expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThresholdCount(original["count"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedCount); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["count"] = transformedCount
	}

	transformedIntervalSec, err := expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThresholdIntervalSec(original["interval_sec"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedIntervalSec); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["intervalSec"] = transformedIntervalSec
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThresholdCount(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsRateLimitThresholdIntervalSec(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsConformAction(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedType, err := expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptionsType(original["type"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedType); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["type"] = transformedType
	}

	transformedTarget, err := expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptionsTarget(original["target"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedTarget); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["target"] = transformedTarget
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptionsType(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsExceedRedirectOptionsTarget(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsExceedAction(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKey(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigs(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedEnforceOnKeyType, err := expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigsEnforceOnKeyType(original["enforce_on_key_type"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedEnforceOnKeyType); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["enforceOnKeyType"] = transformedEnforceOnKeyType
		}

		transformedEnforceOnKeyName, err := expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigsEnforceOnKeyName(original["enforce_on_key_name"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedEnforceOnKeyName); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["enforceOnKeyName"] = transformedEnforceOnKeyName
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigsEnforceOnKeyType(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsEnforceOnKeyConfigsEnforceOnKeyName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsBanThreshold(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedCount, err := expandComputeSecurityPolicyRuleRateLimitOptionsBanThresholdCount(original["count"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedCount); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["count"] = transformedCount
	}

	transformedIntervalSec, err := expandComputeSecurityPolicyRuleRateLimitOptionsBanThresholdIntervalSec(original["interval_sec"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedIntervalSec); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["intervalSec"] = transformedIntervalSec
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsBanThresholdCount(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsBanThresholdIntervalSec(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRateLimitOptionsBanDurationSec(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRedirectOptions(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedType, err := expandComputeSecurityPolicyRuleRedirectOptionsType(original["type"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedType); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["type"] = transformedType
	}

	transformedTarget, err := expandComputeSecurityPolicyRuleRedirectOptionsTarget(original["target"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedTarget); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["target"] = transformedTarget
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleRedirectOptionsType(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleRedirectOptionsTarget(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleHeaderAction(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedRequestHeadersToAdds, err := expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAdds(original["request_headers_to_adds"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedRequestHeadersToAdds); val.IsValid() && !tpgresource.IsEmptyValue(val) {
		transformed["requestHeadersToAdds"] = transformedRequestHeadersToAdds
	}

	return transformed, nil
}

func expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAdds(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedHeaderName, err := expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAddsHeaderName(original["header_name"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedHeaderName); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["headerName"] = transformedHeaderName
		}

		transformedHeaderValue, err := expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAddsHeaderValue(original["header_value"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedHeaderValue); val.IsValid() && !tpgresource.IsEmptyValue(val) {
			transformed["headerValue"] = transformedHeaderValue
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAddsHeaderName(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRuleHeaderActionRequestHeadersToAddsHeaderValue(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}

func expandComputeSecurityPolicyRulePreview(v interface{}, d tpgresource.TerraformResourceData, config *transport_tpg.Config) (interface{}, error) {
	return v, nil
}
