#
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package templates.gcp.TFGCPIAMAllowedBindingsConstraintV3

# import data.validator.gcp.lib as lib

violation[{
	"msg": message,
	"details": metadata,
}] {
	# NOTE: For Terraform review object, the following schema is followed:
	# review: {
	# 	change: {
	# 		actions: ["create"],
	# 		after: {
	#			condition: []
	#			members: []
	#			project:
	# 			role: 
	# 		}
	# 	},
	# 	mode:
	# 	name: 
	# 	provider_name:
	# 	type:
	# }

	# Outdated Gatekeeper format, updating to v1beta1
	params := input.parameters

	# Use input.review for TF changes (see schema above)
	resource := input.review[_]

	resource.type == "google_project_iam_binding"
	not resource.change.actions[0] == "delete"

	# Unused, for reference only.
	# check_asset_type(review, params)

	# # Check if resource is part of asset names to scan
	# include_list := lib.get_default(params, "assetNames", [])
	# is_included(include_list, resource.name)

	# Gather role and member for TF
	role := resource.change.after.role
	member := resource.change.after.members[_]

	# Match roles between resource changes and params, we'll see what members
	glob.match(params.role, ["/"], role)

	# params.role == role

	# Get mode from params
	mode := object.get(params, "mode", "allowlist")

	# Grab matches found using set arithmetic
	matches_found = [m | m = config_pattern(params.members[_]); glob.match(m, [], member)]
	target_match_count(mode, desired_count)
	count(matches_found) != desired_count

	message := sprintf("IAM policy for %v grants %v to %v", [resource.name, role, member])

	metadata := {
		"resource": resource.name,
		"member": member,
		"role": role,
	}
}

###########################
# Rule Utilities
###########################

# Determine the overlap between matches under test and constraint
target_match_count(mode) = 0 {
	mode == "denylist"
}

target_match_count(mode) = 1 {
	mode == "allowlist"
}

# Unused, for reference only.
# check_asset_type(resource, params) {
# 	lib.has_field(params, "assetType")
# 	params.assetType == resource.type
# }

# check_asset_type(resource, params) {
# 	lib.has_field(params, "assetType") == false
# }

# Unused, for reference only.
# is_included(include_list, asset_name) {
# 	include_list != []
# 	glob.match(include_list[_], ["/"], asset_name)
# }

# is_included(include_list, asset_name) {
# 	include_list == []
# }

# If the member in constraint is written as a single "*", turn it into super
# glob "**". Otherwise, we won't be able to match everything.
config_pattern(old_pattern) = "**" {
	old_pattern == "*"
}

config_pattern(old_pattern) = old_pattern {
	old_pattern != "*"
}
