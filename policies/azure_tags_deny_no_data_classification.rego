# METADATA
# title: Verify Azure VM has data classification tags
# description: Verifies that a VM machine has data classification tags.
# custom:
#   controls:
#     - AC-1
#   schedule: "* * * * * *"
package compliance_framework.azure_tags.deny_no_data_classification

import future.keywords.in

valid_values := ["Public", "General", "Confidential", "Highly Confidential", "Secret", "Top Secret", "Sensitive"]

violation[{
    "title": "Azure Virtual Machine does not have a data classification tag.",
    "description": "Virtual Machine should have a data classification tag.",
    "remarks": "Add a tag under 'dataclassification' that is one of the following: 'Public', 'General', 'Confidential', 'Highly Confidential', 'Secret', 'Top Secret', or 'Sensitive'."
}] {
    count({key: v | v = input[key]; key == "dataclassification"}, count_key1)
    count_key1 == 0
}

violation[{
    "title": "Azure Virtual Machine does not have a valid data classification tag.",
    "description": "Virtual Machine should have a valid data classification tag.",
    "remarks": "Add a tag under 'dataclassification' that is one of the following: 'Public', 'General', 'Confidential', 'Highly Confidential', 'Secret', 'Top Secret', or 'Sensitive'."
}] {
    some k, v in input
    k == "dataclassification"
    not v in valid_values
}
