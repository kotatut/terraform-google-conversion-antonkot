// ----------------------------------------------------------------------------
//
//     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
//
// ----------------------------------------------------------------------------
//
//     This code is generated by Magic Modules using the following:
//
//     Configuration: https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/products/compute/StoragePool.yaml
//     Template:      https://github.com/GoogleCloudPlatform/magic-modules/tree/main/mmv1/templates/terraform/iam_policy.go.tmpl
//
//     DO NOT EDIT this file directly. Any changes made to this file will be
//     overwritten during the next generation cycle.
//
// ----------------------------------------------------------------------------

package compute

import (
	"fmt"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"google.golang.org/api/cloudresourcemanager/v1"

	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgiamresource"
	"github.com/hashicorp/terraform-provider-google-beta/google-beta/tpgresource"
	transport_tpg "github.com/hashicorp/terraform-provider-google-beta/google-beta/transport"
)

var ComputeStoragePoolIamSchema = map[string]*schema.Schema{
	"project": {
		Type:     schema.TypeString,
		Computed: true,
		Optional: true,
		ForceNew: true,
	},
	"zone": {
		Type:     schema.TypeString,
		Computed: true,
		Optional: true,
		ForceNew: true,
	},
	"name": {
		Type:             schema.TypeString,
		Required:         true,
		ForceNew:         true,
		DiffSuppressFunc: tpgresource.CompareSelfLinkOrResourceName,
	},
}

type ComputeStoragePoolIamUpdater struct {
	project string
	zone    string
	name    string
	d       tpgresource.TerraformResourceData
	Config  *transport_tpg.Config
}

func ComputeStoragePoolIamUpdaterProducer(d tpgresource.TerraformResourceData, config *transport_tpg.Config) (tpgiamresource.ResourceIamUpdater, error) {
	values := make(map[string]string)

	project, _ := tpgresource.GetProject(d, config)
	if project != "" {
		if err := d.Set("project", project); err != nil {
			return nil, fmt.Errorf("Error setting project: %s", err)
		}
	}
	values["project"] = project
	zone, _ := tpgresource.GetZone(d, config)
	if zone != "" {
		if err := d.Set("zone", zone); err != nil {
			return nil, fmt.Errorf("Error setting zone: %s", err)
		}
	}
	values["zone"] = zone
	if v, ok := d.GetOk("name"); ok {
		values["name"] = v.(string)
	}

	// We may have gotten either a long or short name, so attempt to parse long name if possible
	m, err := tpgresource.GetImportIdQualifiers([]string{"projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/storagePools/(?P<name>[^/]+)", "(?P<project>[^/]+)/(?P<zone>[^/]+)/(?P<name>[^/]+)", "(?P<zone>[^/]+)/(?P<name>[^/]+)", "(?P<name>[^/]+)"}, d, config, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	for k, v := range m {
		values[k] = v
	}

	u := &ComputeStoragePoolIamUpdater{
		project: values["project"],
		zone:    values["zone"],
		name:    values["name"],
		d:       d,
		Config:  config,
	}

	if err := d.Set("project", u.project); err != nil {
		return nil, fmt.Errorf("Error setting project: %s", err)
	}
	if err := d.Set("zone", u.zone); err != nil {
		return nil, fmt.Errorf("Error setting zone: %s", err)
	}
	if err := d.Set("name", u.GetResourceId()); err != nil {
		return nil, fmt.Errorf("Error setting name: %s", err)
	}

	return u, nil
}

func ComputeStoragePoolIdParseFunc(d *schema.ResourceData, config *transport_tpg.Config) error {
	values := make(map[string]string)

	project, _ := tpgresource.GetProject(d, config)
	if project != "" {
		values["project"] = project
	}

	zone, _ := tpgresource.GetZone(d, config)
	if zone != "" {
		values["zone"] = zone
	}

	m, err := tpgresource.GetImportIdQualifiers([]string{"projects/(?P<project>[^/]+)/zones/(?P<zone>[^/]+)/storagePools/(?P<name>[^/]+)", "(?P<project>[^/]+)/(?P<zone>[^/]+)/(?P<name>[^/]+)", "(?P<zone>[^/]+)/(?P<name>[^/]+)", "(?P<name>[^/]+)"}, d, config, d.Id())
	if err != nil {
		return err
	}

	for k, v := range m {
		values[k] = v
	}

	u := &ComputeStoragePoolIamUpdater{
		project: values["project"],
		zone:    values["zone"],
		name:    values["name"],
		d:       d,
		Config:  config,
	}
	if err := d.Set("name", u.GetResourceId()); err != nil {
		return fmt.Errorf("Error setting name: %s", err)
	}
	d.SetId(u.GetResourceId())
	return nil
}

func (u *ComputeStoragePoolIamUpdater) GetResourceIamPolicy() (*cloudresourcemanager.Policy, error) {
	url, err := u.qualifyStoragePoolUrl("getIamPolicy")
	if err != nil {
		return nil, err
	}

	project, err := tpgresource.GetProject(u.d, u.Config)
	if err != nil {
		return nil, err
	}
	var obj map[string]interface{}
	url, err = transport_tpg.AddQueryParams(url, map[string]string{"optionsRequestedPolicyVersion": fmt.Sprintf("%d", tpgiamresource.IamPolicyVersion)})
	if err != nil {
		return nil, err
	}

	userAgent, err := tpgresource.GenerateUserAgentString(u.d, u.Config.UserAgent)
	if err != nil {
		return nil, err
	}

	policy, err := transport_tpg.SendRequest(transport_tpg.SendRequestOptions{
		Config:    u.Config,
		Method:    "GET",
		Project:   project,
		RawURL:    url,
		UserAgent: userAgent,
		Body:      obj,
	})
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("Error retrieving IAM policy for %s: {{err}}", u.DescribeResource()), err)
	}

	out := &cloudresourcemanager.Policy{}
	err = tpgresource.Convert(policy, out)
	if err != nil {
		return nil, errwrap.Wrapf("Cannot convert a policy to a resource manager policy: {{err}}", err)
	}

	return out, nil
}

func (u *ComputeStoragePoolIamUpdater) SetResourceIamPolicy(policy *cloudresourcemanager.Policy) error {
	json, err := tpgresource.ConvertToMap(policy)
	if err != nil {
		return err
	}

	obj := make(map[string]interface{})
	obj["policy"] = json

	url, err := u.qualifyStoragePoolUrl("setIamPolicy")
	if err != nil {
		return err
	}
	project, err := tpgresource.GetProject(u.d, u.Config)
	if err != nil {
		return err
	}

	userAgent, err := tpgresource.GenerateUserAgentString(u.d, u.Config.UserAgent)
	if err != nil {
		return err
	}

	_, err = transport_tpg.SendRequest(transport_tpg.SendRequestOptions{
		Config:    u.Config,
		Method:    "POST",
		Project:   project,
		RawURL:    url,
		UserAgent: userAgent,
		Body:      obj,
		Timeout:   u.d.Timeout(schema.TimeoutCreate),
	})
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("Error setting IAM policy for %s: {{err}}", u.DescribeResource()), err)
	}

	return nil
}

func (u *ComputeStoragePoolIamUpdater) qualifyStoragePoolUrl(methodIdentifier string) (string, error) {
	urlTemplate := fmt.Sprintf("{{ComputeBasePath}}%s/%s", fmt.Sprintf("projects/%s/zones/%s/storagePools/%s", u.project, u.zone, u.name), methodIdentifier)
	url, err := tpgresource.ReplaceVars(u.d, u.Config, urlTemplate)
	if err != nil {
		return "", err
	}
	return url, nil
}

func (u *ComputeStoragePoolIamUpdater) GetResourceId() string {
	return fmt.Sprintf("projects/%s/zones/%s/storagePools/%s", u.project, u.zone, u.name)
}

func (u *ComputeStoragePoolIamUpdater) GetMutexKey() string {
	return fmt.Sprintf("iam-compute-storagepool-%s", u.GetResourceId())
}

func (u *ComputeStoragePoolIamUpdater) DescribeResource() string {
	return fmt.Sprintf("compute storagepool %q", u.GetResourceId())
}
