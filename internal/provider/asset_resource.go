// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/rsclarke/xbow"
)

var _ resource.Resource = &AssetResource{}
var _ resource.ResourceWithImportState = &AssetResource{}

func NewAssetResource() resource.Resource {
	return &AssetResource{}
}

type AssetResource struct {
	client *xbow.Client
}

type AssetResourceModel struct {
	ID                   types.String `tfsdk:"id"`
	Name                 types.String `tfsdk:"name"`
	OrganizationID       types.String `tfsdk:"organization_id"`
	LifecycleState       types.String `tfsdk:"lifecycle_state"`
	Sku                  types.String `tfsdk:"sku"`
	StartURL             types.String `tfsdk:"start_url"`
	MaxRequestsPerSecond types.Int64  `tfsdk:"max_requests_per_second"`
	ApprovedTimeWindows  types.Object `tfsdk:"approved_time_windows"`
	Credentials          types.List   `tfsdk:"credentials"`
	DNSBoundaryRules     types.List   `tfsdk:"dns_boundary_rules"`
	Headers              types.Map    `tfsdk:"headers"`
	HTTPBoundaryRules    types.List   `tfsdk:"http_boundary_rules"`
	Checks               types.Object `tfsdk:"checks"`
	ArchiveAt            types.String `tfsdk:"archive_at"`
	CreatedAt            types.String `tfsdk:"created_at"`
	UpdatedAt            types.String `tfsdk:"updated_at"`
}

type ApprovedTimeWindowsModel struct {
	Tz      types.String `tfsdk:"tz"`
	Entries types.List   `tfsdk:"entries"`
}

type TimeWindowEntryModel struct {
	StartWeekday types.Int64  `tfsdk:"start_weekday"`
	StartTime    types.String `tfsdk:"start_time"`
	EndWeekday   types.Int64  `tfsdk:"end_weekday"`
	EndTime      types.String `tfsdk:"end_time"`
}

type CredentialModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Type             types.String `tfsdk:"type"`
	Username         types.String `tfsdk:"username"`
	Password         types.String `tfsdk:"password"`
	EmailAddress     types.String `tfsdk:"email_address"`
	AuthenticatorURI types.String `tfsdk:"authenticator_uri"`
}

type DNSBoundaryRuleModel struct {
	ID                types.String `tfsdk:"id"`
	Action            types.String `tfsdk:"action"`
	Type              types.String `tfsdk:"type"`
	Filter            types.String `tfsdk:"filter"`
	IncludeSubdomains types.Bool   `tfsdk:"include_subdomains"`
}

type HTTPBoundaryRuleModel struct {
	ID                types.String `tfsdk:"id"`
	Action            types.String `tfsdk:"action"`
	Type              types.String `tfsdk:"type"`
	Filter            types.String `tfsdk:"filter"`
	IncludeSubdomains types.Bool   `tfsdk:"include_subdomains"`
}

type AssetChecksModel struct {
	AssetReachable   types.Object `tfsdk:"asset_reachable"`
	Credentials      types.Object `tfsdk:"credentials"`
	DNSBoundaryRules types.Object `tfsdk:"dns_boundary_rules"`
	UpdatedAt        types.String `tfsdk:"updated_at"`
}

type AssetCheckModel struct {
	State   types.String `tfsdk:"state"`
	Message types.String `tfsdk:"message"`
}

func timeWindowEntryAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"start_weekday": types.Int64Type,
		"start_time":    types.StringType,
		"end_weekday":   types.Int64Type,
		"end_time":      types.StringType,
	}
}

func approvedTimeWindowsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"tz":      types.StringType,
		"entries": types.ListType{ElemType: types.ObjectType{AttrTypes: timeWindowEntryAttrTypes()}},
	}
}

func credentialAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                types.StringType,
		"name":              types.StringType,
		"type":              types.StringType,
		"username":          types.StringType,
		"password":          types.StringType,
		"email_address":     types.StringType,
		"authenticator_uri": types.StringType,
	}
}

func dnsBoundaryRuleAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"action":             types.StringType,
		"type":               types.StringType,
		"filter":             types.StringType,
		"include_subdomains": types.BoolType,
	}
}

func httpBoundaryRuleAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"id":                 types.StringType,
		"action":             types.StringType,
		"type":               types.StringType,
		"filter":             types.StringType,
		"include_subdomains": types.BoolType,
	}
}

func assetCheckAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"state":   types.StringType,
		"message": types.StringType,
	}
}

func assetChecksAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"asset_reachable":    types.ObjectType{AttrTypes: assetCheckAttrTypes()},
		"credentials":        types.ObjectType{AttrTypes: assetCheckAttrTypes()},
		"dns_boundary_rules": types.ObjectType{AttrTypes: assetCheckAttrTypes()},
		"updated_at":         types.StringType,
	}
}

func (r *AssetResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_asset"
}

func (r *AssetResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an XBOW Asset resource.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The unique identifier of the asset.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The name of the asset.",
			},
			"organization_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The organization ID that owns the asset.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"lifecycle_state": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The lifecycle state of the asset (active or archived).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sku": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The SKU identifier for the asset.",
			},
			"start_url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The starting URL for assessment.",
			},
			"max_requests_per_second": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Maximum requests per second for rate limiting.",
			},
			"approved_time_windows": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Time windows when assessments are allowed to run.",
				Attributes: map[string]schema.Attribute{
					"tz": schema.StringAttribute{
						Required:            true,
						MarkdownDescription: "The timezone for the time windows (e.g., 'America/New_York').",
					},
					"entries": schema.ListNestedAttribute{
						Required:            true,
						MarkdownDescription: "List of time window entries.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"start_weekday": schema.Int64Attribute{
									Required:            true,
									MarkdownDescription: "Start day of the week (0=Sunday, 6=Saturday).",
								},
								"start_time": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "Start time in HH:MM format.",
								},
								"end_weekday": schema.Int64Attribute{
									Required:            true,
									MarkdownDescription: "End day of the week (0=Sunday, 6=Saturday).",
								},
								"end_time": schema.StringAttribute{
									Required:            true,
									MarkdownDescription: "End time in HH:MM format.",
								},
							},
						},
					},
				},
			},
			"credentials": schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Authentication credentials for the asset.",
				Default:             listdefault.StaticValue(types.ListValueMust(types.ObjectType{AttrTypes: credentialAttrTypes()}, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier of the credential.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"name": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The name of the credential.",
						},
						"type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The type of credential (e.g., 'basic', 'oauth').",
						},
						"username": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The username for authentication.",
						},
						"password": schema.StringAttribute{
							Required:            true,
							Sensitive:           true,
							MarkdownDescription: "The password for authentication.",
						},
						"email_address": schema.StringAttribute{
							Optional:            true,
							MarkdownDescription: "The email address associated with the credential.",
						},
						"authenticator_uri": schema.StringAttribute{
							Optional:            true,
							Sensitive:           true,
							MarkdownDescription: "The TOTP authenticator URI for MFA.",
						},
					},
				},
			},
			"dns_boundary_rules": schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "DNS boundary rules for the asset.",
				Default:             listdefault.StaticValue(types.ListValueMust(types.ObjectType{AttrTypes: dnsBoundaryRuleAttrTypes()}, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier of the DNS boundary rule.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"action": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The action to take (allow-attack, deny-attack).",
						},
						"type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The type of rule (e.g., 'domain').",
						},
						"filter": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The filter pattern for the rule.",
						},
						"include_subdomains": schema.BoolAttribute{
							Optional:            true,
							MarkdownDescription: "Whether to include subdomains in the rule.",
						},
					},
				},
			},
			"headers": schema.MapAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Custom HTTP headers to include in requests. Each header can have multiple values.",
				ElementType:         types.ListType{ElemType: types.StringType},
				Default:             mapdefault.StaticValue(types.MapValueMust(types.ListType{ElemType: types.StringType}, map[string]attr.Value{})),
			},
			"http_boundary_rules": schema.ListNestedAttribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "HTTP boundary rules for the asset.",
				Default:             listdefault.StaticValue(types.ListValueMust(types.ObjectType{AttrTypes: httpBoundaryRuleAttrTypes()}, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "The unique identifier of the HTTP boundary rule.",
							PlanModifiers: []planmodifier.String{
								stringplanmodifier.UseStateForUnknown(),
							},
						},
						"action": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The action to take (allow-attack, allow-auth, deny-attack).",
						},
						"type": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The type of rule (e.g., 'domain', 'path').",
						},
						"filter": schema.StringAttribute{
							Required:            true,
							MarkdownDescription: "The filter pattern for the rule.",
						},
						"include_subdomains": schema.BoolAttribute{
							Optional:            true,
							MarkdownDescription: "Whether to include subdomains in the rule.",
						},
					},
				},
			},
			"checks": schema.SingleNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Validation checks for the asset.",
				Attributes: map[string]schema.Attribute{
					"asset_reachable": schema.SingleNestedAttribute{
						Computed:            true,
						MarkdownDescription: "Check if the asset is reachable.",
						Attributes: map[string]schema.Attribute{
							"state": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The state of the check.",
							},
							"message": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The message from the check.",
							},
						},
					},
					"credentials": schema.SingleNestedAttribute{
						Computed:            true,
						MarkdownDescription: "Check if the credentials are valid.",
						Attributes: map[string]schema.Attribute{
							"state": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The state of the check.",
							},
							"message": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The message from the check.",
							},
						},
					},
					"dns_boundary_rules": schema.SingleNestedAttribute{
						Computed:            true,
						MarkdownDescription: "Check if DNS boundary rules are configured correctly.",
						Attributes: map[string]schema.Attribute{
							"state": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The state of the check.",
							},
							"message": schema.StringAttribute{
								Computed:            true,
								MarkdownDescription: "The message from the check.",
							},
						},
					},
					"updated_at": schema.StringAttribute{
						Computed:            true,
						MarkdownDescription: "When the checks were last updated.",
					},
				},
			},
			"archive_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the asset is scheduled to be archived (RFC3339 format).",
			},
			"created_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the asset was created (RFC3339 format).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"updated_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "When the asset was last updated (RFC3339 format).",
			},
		},
	}
}

func (r *AssetResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*xbow.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *xbow.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *AssetResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AssetResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createReq := &xbow.CreateAssetRequest{
		Name: data.Name.ValueString(),
		Sku:  data.Sku.ValueString(),
	}

	asset, err := r.client.Assets.Create(ctx, data.OrganizationID.ValueString(), createReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create asset", err.Error())
		return
	}

	data.ID = types.StringValue(asset.ID)

	updateReq := r.buildUpdateRequest(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if updateReq != nil {
		asset, err = r.client.Assets.Update(ctx, asset.ID, updateReq)
		if err != nil {
			resp.Diagnostics.AddError("Failed to update asset after creation", err.Error())
			return
		}
	}

	r.populateModelFromAsset(ctx, &data, asset, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "created asset", map[string]interface{}{"id": asset.ID})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AssetResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data AssetResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	asset, err := r.client.Assets.Get(ctx, data.ID.ValueString())
	if err != nil {
		if errors.Is(err, xbow.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Failed to read asset", err.Error())
		return
	}

	r.populateModelFromAsset(ctx, &data, asset, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AssetResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data AssetResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateReq := r.buildUpdateRequest(ctx, &data, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if updateReq == nil {
		updateReq = &xbow.UpdateAssetRequest{
			Name: data.Name.ValueString(),
		}
	}

	sku := data.Sku.ValueString()
	updateReq.Sku = &sku

	asset, err := r.client.Assets.Update(ctx, data.ID.ValueString(), updateReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to update asset", err.Error())
		return
	}

	r.populateModelFromAsset(ctx, &data, asset, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "updated asset", map[string]interface{}{"id": asset.ID})

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *AssetResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AssetResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "delete is a no-op for asset (API does not support deletion)", map[string]interface{}{"id": data.ID.ValueString()})
}

func (r *AssetResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *AssetResource) buildUpdateRequest(ctx context.Context, data *AssetResourceModel, diags *diag.Diagnostics) *xbow.UpdateAssetRequest {
	hasUpdates := false
	updateReq := &xbow.UpdateAssetRequest{
		Name: data.Name.ValueString(),
	}

	if !data.StartURL.IsNull() {
		updateReq.StartURL = data.StartURL.ValueString()
		hasUpdates = true
	}

	if !data.MaxRequestsPerSecond.IsNull() {
		updateReq.MaxRequestsPerSecond = int(data.MaxRequestsPerSecond.ValueInt64())
		hasUpdates = true
	}

	if !data.ApprovedTimeWindows.IsNull() {
		var atw ApprovedTimeWindowsModel
		diags.Append(data.ApprovedTimeWindows.As(ctx, &atw, basetypes.ObjectAsOptions{})...)
		if diags.HasError() {
			return nil
		}

		var entries []TimeWindowEntryModel
		diags.Append(atw.Entries.ElementsAs(ctx, &entries, false)...)
		if diags.HasError() {
			return nil
		}

		xbowEntries := make([]xbow.TimeWindowEntry, len(entries))
		for i, e := range entries {
			xbowEntries[i] = xbow.TimeWindowEntry{
				StartWeekday: int(e.StartWeekday.ValueInt64()),
				StartTime:    e.StartTime.ValueString(),
				EndWeekday:   int(e.EndWeekday.ValueInt64()),
				EndTime:      e.EndTime.ValueString(),
			}
		}

		updateReq.ApprovedTimeWindows = &xbow.ApprovedTimeWindows{
			Tz:      atw.Tz.ValueString(),
			Entries: xbowEntries,
		}
		hasUpdates = true
	}

	if !data.Credentials.IsNull() && len(data.Credentials.Elements()) > 0 {
		var creds []CredentialModel
		diags.Append(data.Credentials.ElementsAs(ctx, &creds, false)...)
		if diags.HasError() {
			return nil
		}

		xbowCreds := make([]xbow.Credential, len(creds))
		for i, c := range creds {
			xbowCreds[i] = xbow.Credential{
				ID:       c.ID.ValueString(),
				Name:     c.Name.ValueString(),
				Type:     c.Type.ValueString(),
				Username: c.Username.ValueString(),
				Password: c.Password.ValueString(),
			}
			if !c.EmailAddress.IsNull() {
				email := c.EmailAddress.ValueString()
				xbowCreds[i].EmailAddress = &email
			}
			if !c.AuthenticatorURI.IsNull() {
				uri := c.AuthenticatorURI.ValueString()
				xbowCreds[i].AuthenticatorURI = &uri
			}
		}
		updateReq.Credentials = xbowCreds
		hasUpdates = true
	}

	if !data.DNSBoundaryRules.IsNull() && len(data.DNSBoundaryRules.Elements()) > 0 {
		var rules []DNSBoundaryRuleModel
		diags.Append(data.DNSBoundaryRules.ElementsAs(ctx, &rules, false)...)
		if diags.HasError() {
			return nil
		}

		xbowRules := make([]xbow.DNSBoundaryRule, len(rules))
		for i, r := range rules {
			xbowRules[i] = xbow.DNSBoundaryRule{
				ID:     r.ID.ValueString(),
				Action: xbow.DNSBoundaryRuleAction(r.Action.ValueString()),
				Type:   r.Type.ValueString(),
				Filter: r.Filter.ValueString(),
			}
			if !r.IncludeSubdomains.IsNull() {
				inc := r.IncludeSubdomains.ValueBool()
				xbowRules[i].IncludeSubdomains = &inc
			}
		}
		updateReq.DNSBoundaryRules = xbowRules
		hasUpdates = true
	}

	if !data.Headers.IsNull() && len(data.Headers.Elements()) > 0 {
		var headersMap map[string]types.List
		diags.Append(data.Headers.ElementsAs(ctx, &headersMap, false)...)
		if diags.HasError() {
			return nil
		}

		xbowHeaders := make(map[string][]string)
		for k, v := range headersMap {
			var values []string
			diags.Append(v.ElementsAs(ctx, &values, false)...)
			if diags.HasError() {
				return nil
			}
			xbowHeaders[k] = values
		}
		updateReq.Headers = xbowHeaders
		hasUpdates = true
	}

	if !data.HTTPBoundaryRules.IsNull() && len(data.HTTPBoundaryRules.Elements()) > 0 {
		var rules []HTTPBoundaryRuleModel
		diags.Append(data.HTTPBoundaryRules.ElementsAs(ctx, &rules, false)...)
		if diags.HasError() {
			return nil
		}

		xbowRules := make([]xbow.HTTPBoundaryRule, len(rules))
		for i, r := range rules {
			xbowRules[i] = xbow.HTTPBoundaryRule{
				ID:     r.ID.ValueString(),
				Action: xbow.HTTPBoundaryRuleAction(r.Action.ValueString()),
				Type:   r.Type.ValueString(),
				Filter: r.Filter.ValueString(),
			}
			if !r.IncludeSubdomains.IsNull() {
				inc := r.IncludeSubdomains.ValueBool()
				xbowRules[i].IncludeSubdomains = &inc
			}
		}
		updateReq.HTTPBoundaryRules = xbowRules
		hasUpdates = true
	}

	if !hasUpdates {
		return nil
	}

	return updateReq
}

func (r *AssetResource) populateModelFromAsset(_ context.Context, data *AssetResourceModel, asset *xbow.Asset, diags *diag.Diagnostics) {
	data.ID = types.StringValue(asset.ID)
	data.Name = types.StringValue(asset.Name)
	data.OrganizationID = types.StringValue(asset.OrganizationID)
	data.LifecycleState = types.StringValue(string(asset.Lifecycle))
	data.Sku = types.StringValue(asset.Sku)

	if asset.StartURL != nil {
		data.StartURL = types.StringValue(*asset.StartURL)
	} else {
		data.StartURL = types.StringNull()
	}

	if asset.MaxRequestsPerSecond != nil {
		data.MaxRequestsPerSecond = types.Int64Value(int64(*asset.MaxRequestsPerSecond))
	} else {
		data.MaxRequestsPerSecond = types.Int64Null()
	}

	if asset.ApprovedTimeWindows != nil {
		entries := make([]attr.Value, len(asset.ApprovedTimeWindows.Entries))
		for i, e := range asset.ApprovedTimeWindows.Entries {
			entryObj, d := types.ObjectValue(timeWindowEntryAttrTypes(), map[string]attr.Value{
				"start_weekday": types.Int64Value(int64(e.StartWeekday)),
				"start_time":    types.StringValue(e.StartTime),
				"end_weekday":   types.Int64Value(int64(e.EndWeekday)),
				"end_time":      types.StringValue(e.EndTime),
			})
			diags.Append(d...)
			if diags.HasError() {
				return
			}
			entries[i] = entryObj
		}

		entriesList, d := types.ListValue(types.ObjectType{AttrTypes: timeWindowEntryAttrTypes()}, entries)
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		atwObj, d := types.ObjectValue(approvedTimeWindowsAttrTypes(), map[string]attr.Value{
			"tz":      types.StringValue(asset.ApprovedTimeWindows.Tz),
			"entries": entriesList,
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.ApprovedTimeWindows = atwObj
	} else {
		data.ApprovedTimeWindows = types.ObjectNull(approvedTimeWindowsAttrTypes())
	}

	if len(asset.Credentials) > 0 {
		creds := make([]attr.Value, len(asset.Credentials))
		for i, c := range asset.Credentials {
			emailAddr := types.StringNull()
			if c.EmailAddress != nil {
				emailAddr = types.StringValue(*c.EmailAddress)
			}
			authURI := types.StringNull()
			if c.AuthenticatorURI != nil {
				authURI = types.StringValue(*c.AuthenticatorURI)
			}

			credObj, d := types.ObjectValue(credentialAttrTypes(), map[string]attr.Value{
				"id":                types.StringValue(c.ID),
				"name":              types.StringValue(c.Name),
				"type":              types.StringValue(c.Type),
				"username":          types.StringValue(c.Username),
				"password":          types.StringValue(c.Password),
				"email_address":     emailAddr,
				"authenticator_uri": authURI,
			})
			diags.Append(d...)
			if diags.HasError() {
				return
			}
			creds[i] = credObj
		}

		credsList, d := types.ListValue(types.ObjectType{AttrTypes: credentialAttrTypes()}, creds)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.Credentials = credsList
	} else {
		data.Credentials = types.ListValueMust(types.ObjectType{AttrTypes: credentialAttrTypes()}, []attr.Value{})
	}

	if len(asset.DNSBoundaryRules) > 0 {
		rules := make([]attr.Value, len(asset.DNSBoundaryRules))
		for i, r := range asset.DNSBoundaryRules {
			incSubdomains := types.BoolNull()
			if r.IncludeSubdomains != nil {
				incSubdomains = types.BoolValue(*r.IncludeSubdomains)
			}

			ruleObj, d := types.ObjectValue(dnsBoundaryRuleAttrTypes(), map[string]attr.Value{
				"id":                 types.StringValue(r.ID),
				"action":             types.StringValue(string(r.Action)),
				"type":               types.StringValue(r.Type),
				"filter":             types.StringValue(r.Filter),
				"include_subdomains": incSubdomains,
			})
			diags.Append(d...)
			if diags.HasError() {
				return
			}
			rules[i] = ruleObj
		}

		rulesList, d := types.ListValue(types.ObjectType{AttrTypes: dnsBoundaryRuleAttrTypes()}, rules)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.DNSBoundaryRules = rulesList
	} else {
		data.DNSBoundaryRules = types.ListValueMust(types.ObjectType{AttrTypes: dnsBoundaryRuleAttrTypes()}, []attr.Value{})
	}

	if len(asset.Headers) > 0 {
		headersMap := make(map[string]attr.Value)
		for k, v := range asset.Headers {
			values := make([]attr.Value, len(v))
			for i, val := range v {
				values[i] = types.StringValue(val)
			}
			headerList, d := types.ListValue(types.StringType, values)
			diags.Append(d...)
			if diags.HasError() {
				return
			}
			headersMap[k] = headerList
		}

		headers, d := types.MapValue(types.ListType{ElemType: types.StringType}, headersMap)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.Headers = headers
	} else {
		data.Headers = types.MapValueMust(types.ListType{ElemType: types.StringType}, map[string]attr.Value{})
	}

	if len(asset.HTTPBoundaryRules) > 0 {
		rules := make([]attr.Value, len(asset.HTTPBoundaryRules))
		for i, r := range asset.HTTPBoundaryRules {
			incSubdomains := types.BoolNull()
			if r.IncludeSubdomains != nil {
				incSubdomains = types.BoolValue(*r.IncludeSubdomains)
			}

			ruleObj, d := types.ObjectValue(httpBoundaryRuleAttrTypes(), map[string]attr.Value{
				"id":                 types.StringValue(r.ID),
				"action":             types.StringValue(string(r.Action)),
				"type":               types.StringValue(r.Type),
				"filter":             types.StringValue(r.Filter),
				"include_subdomains": incSubdomains,
			})
			diags.Append(d...)
			if diags.HasError() {
				return
			}
			rules[i] = ruleObj
		}

		rulesList, d := types.ListValue(types.ObjectType{AttrTypes: httpBoundaryRuleAttrTypes()}, rules)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.HTTPBoundaryRules = rulesList
	} else {
		data.HTTPBoundaryRules = types.ListValueMust(types.ObjectType{AttrTypes: httpBoundaryRuleAttrTypes()}, []attr.Value{})
	}

	if asset.Checks != nil {
		assetReachable, d := types.ObjectValue(assetCheckAttrTypes(), map[string]attr.Value{
			"state":   types.StringValue(string(asset.Checks.AssetReachable.State)),
			"message": types.StringValue(asset.Checks.AssetReachable.Message),
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		credentials, d := types.ObjectValue(assetCheckAttrTypes(), map[string]attr.Value{
			"state":   types.StringValue(string(asset.Checks.Credentials.State)),
			"message": types.StringValue(asset.Checks.Credentials.Message),
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		dnsRules, d := types.ObjectValue(assetCheckAttrTypes(), map[string]attr.Value{
			"state":   types.StringValue(string(asset.Checks.DNSBoundaryRules.State)),
			"message": types.StringValue(asset.Checks.DNSBoundaryRules.Message),
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}

		checksUpdatedAt := types.StringNull()
		if asset.Checks.UpdatedAt != nil {
			checksUpdatedAt = types.StringValue(asset.Checks.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
		}

		checksObj, d := types.ObjectValue(assetChecksAttrTypes(), map[string]attr.Value{
			"asset_reachable":    assetReachable,
			"credentials":        credentials,
			"dns_boundary_rules": dnsRules,
			"updated_at":         checksUpdatedAt,
		})
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		data.Checks = checksObj
	} else {
		data.Checks = types.ObjectNull(assetChecksAttrTypes())
	}

	if asset.ArchiveAt != nil {
		data.ArchiveAt = types.StringValue(asset.ArchiveAt.Format("2006-01-02T15:04:05Z07:00"))
	} else {
		data.ArchiveAt = types.StringNull()
	}

	data.CreatedAt = types.StringValue(asset.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	data.UpdatedAt = types.StringValue(asset.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
}
