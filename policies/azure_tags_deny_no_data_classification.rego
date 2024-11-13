# Ensure that the 'dataclassification' tag is defined on the resource
#
# METADATA
# title: Verify Azure VM has data classification tags
# description: Verifies that password authentication is not enabled for ssh on a machine. This helps prevent unauthorised brute force attacks.
# custom:
#   controls:
#     - AC-1
#   schedule: "* * * * * *"
package compliance_framework.azure_tags.deny_no_data_classification

import rego.v1

allow if {
    input.Name == "dataclassification"
    input.Value in ["Public", "General", "Confidential", "Highly Confidential", "Secret", "Top Secret", "Sensitive"]
}
