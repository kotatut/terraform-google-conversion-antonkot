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

import (
	"encoding/json"
	"reflect"
)

func GetHealthcareHl7V2StoreCaiObject(d TerraformResourceData, config *Config) ([]Asset, error) {
	name, err := assetName(d, config, "//healthcare.googleapis.com/{{dataset}}/hl7V2Stores/{{name}}")
	if err != nil {
		return []Asset{}, err
	}
	if obj, err := GetHealthcareHl7V2StoreApiObject(d, config); err == nil {
		return []Asset{{
			Name: name,
			Type: "healthcare.googleapis.com/Hl7V2Store",
			Resource: &AssetResource{
				Version:              "v1",
				DiscoveryDocumentURI: "https://www.googleapis.com/discovery/v1/apis/healthcare/v1/rest",
				DiscoveryName:        "Hl7V2Store",
				Data:                 obj,
			},
		}}, nil
	} else {
		return []Asset{}, err
	}
}

func GetHealthcareHl7V2StoreApiObject(d TerraformResourceData, config *Config) (map[string]interface{}, error) {
	obj := make(map[string]interface{})
	nameProp, err := expandHealthcareHl7V2StoreName(d.Get("name"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("name"); !isEmptyValue(reflect.ValueOf(nameProp)) && (ok || !reflect.DeepEqual(v, nameProp)) {
		obj["name"] = nameProp
	}
	parserConfigProp, err := expandHealthcareHl7V2StoreParserConfig(d.Get("parser_config"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("parser_config"); !isEmptyValue(reflect.ValueOf(parserConfigProp)) && (ok || !reflect.DeepEqual(v, parserConfigProp)) {
		obj["parserConfig"] = parserConfigProp
	}
	labelsProp, err := expandHealthcareHl7V2StoreLabels(d.Get("labels"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("labels"); !isEmptyValue(reflect.ValueOf(labelsProp)) && (ok || !reflect.DeepEqual(v, labelsProp)) {
		obj["labels"] = labelsProp
	}
	notificationConfigsProp, err := expandHealthcareHl7V2StoreNotificationConfigs(d.Get("notification_configs"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("notification_configs"); !isEmptyValue(reflect.ValueOf(notificationConfigsProp)) && (ok || !reflect.DeepEqual(v, notificationConfigsProp)) {
		obj["notificationConfigs"] = notificationConfigsProp
	}
	notificationConfigProp, err := expandHealthcareHl7V2StoreNotificationConfig(d.Get("notification_config"), d, config)
	if err != nil {
		return nil, err
	} else if v, ok := d.GetOkExists("notification_config"); !isEmptyValue(reflect.ValueOf(notificationConfigProp)) && (ok || !reflect.DeepEqual(v, notificationConfigProp)) {
		obj["notificationConfig"] = notificationConfigProp
	}

	return obj, nil
}

func expandHealthcareHl7V2StoreName(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandHealthcareHl7V2StoreParserConfig(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedAllowNullHeader, err := expandHealthcareHl7V2StoreParserConfigAllowNullHeader(original["allow_null_header"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedAllowNullHeader); val.IsValid() && !isEmptyValue(val) {
		transformed["allowNullHeader"] = transformedAllowNullHeader
	}

	transformedSegmentTerminator, err := expandHealthcareHl7V2StoreParserConfigSegmentTerminator(original["segment_terminator"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedSegmentTerminator); val.IsValid() && !isEmptyValue(val) {
		transformed["segmentTerminator"] = transformedSegmentTerminator
	}

	transformedSchema, err := expandHealthcareHl7V2StoreParserConfigSchema(original["schema"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedSchema); val.IsValid() && !isEmptyValue(val) {
		transformed["schema"] = transformedSchema
	}

	return transformed, nil
}

func expandHealthcareHl7V2StoreParserConfigAllowNullHeader(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandHealthcareHl7V2StoreParserConfigSegmentTerminator(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandHealthcareHl7V2StoreParserConfigSchema(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	b := []byte(v.(string))
	if len(b) == 0 {
		return nil, nil
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func expandHealthcareHl7V2StoreLabels(v interface{}, d TerraformResourceData, config *Config) (map[string]string, error) {
	if v == nil {
		return map[string]string{}, nil
	}
	m := make(map[string]string)
	for k, val := range v.(map[string]interface{}) {
		m[k] = val.(string)
	}
	return m, nil
}

func expandHealthcareHl7V2StoreNotificationConfigs(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	req := make([]interface{}, 0, len(l))
	for _, raw := range l {
		if raw == nil {
			continue
		}
		original := raw.(map[string]interface{})
		transformed := make(map[string]interface{})

		transformedPubsubTopic, err := expandHealthcareHl7V2StoreNotificationConfigsPubsubTopic(original["pubsub_topic"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedPubsubTopic); val.IsValid() && !isEmptyValue(val) {
			transformed["pubsubTopic"] = transformedPubsubTopic
		}

		transformedFilter, err := expandHealthcareHl7V2StoreNotificationConfigsFilter(original["filter"], d, config)
		if err != nil {
			return nil, err
		} else if val := reflect.ValueOf(transformedFilter); val.IsValid() && !isEmptyValue(val) {
			transformed["filter"] = transformedFilter
		}

		req = append(req, transformed)
	}
	return req, nil
}

func expandHealthcareHl7V2StoreNotificationConfigsPubsubTopic(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandHealthcareHl7V2StoreNotificationConfigsFilter(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}

func expandHealthcareHl7V2StoreNotificationConfig(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	l := v.([]interface{})
	if len(l) == 0 || l[0] == nil {
		return nil, nil
	}
	raw := l[0]
	original := raw.(map[string]interface{})
	transformed := make(map[string]interface{})

	transformedPubsubTopic, err := expandHealthcareHl7V2StoreNotificationConfigPubsubTopic(original["pubsub_topic"], d, config)
	if err != nil {
		return nil, err
	} else if val := reflect.ValueOf(transformedPubsubTopic); val.IsValid() && !isEmptyValue(val) {
		transformed["pubsubTopic"] = transformedPubsubTopic
	}

	return transformed, nil
}

func expandHealthcareHl7V2StoreNotificationConfigPubsubTopic(v interface{}, d TerraformResourceData, config *Config) (interface{}, error) {
	return v, nil
}
