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

activities := [
    {
        "title": "Verify Azure VM Tags",
        "description": "Verify That all VMs in Azure have the correct data classification tags applied to them.",
        "type": "evaluation",
        "steps": [
            "Parse Azure VM's.",
            "Check if the tag dataclassification is set and the value is valid.",
            "Flag violation if the tags are either not set or have an invalid value."
        ],
        "tools": ["rego", "OPA"]
    }
]

risks := [
    {
        "title": "Regulatory Non-Compliance",
        "description": "TODO",
        "statement": "TODO",
        "links": [],
    },
]

violation[{
    "title": "Azure Virtual Machine does not have a data classification tag.",
    "description": "Virtual Machine should have a data classification tag.",
    "remarks": sprintf("Add a tag under 'dataclassification' that is one of the following: %s", [concat(", ", valid_values)]),
    "control-implementations": [
        "TODO"
    ]
}] if {
    count({key: v | v = input[key]; key == "dataclassification"}, count_key1)
    count_key1 == 0
}

violation[{
    "title": "Azure Virtual Machine does not have a valid data classification tag.",
    "description": "Virtual Machine should have a valid data classification tag.",
    "remarks": sprintf("Add a tag under 'dataclassification' that is one of the following: %s", [concat(", ", valid_values)]),
    "control-implementations": [
        "TODO"
    ]
}] if {
    some k, v in input
    k == "dataclassification"
    not v in valid_values
}
