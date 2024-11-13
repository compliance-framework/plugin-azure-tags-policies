package compliance_framework.azure_tags.deny_no_data_classification

import rego.v1

test_valid if {
    result := data.compliance_framework.azure_tags.deny_no_data_classification.allow with input as {"Name": "dataclassification", "Value": "Public"}
    result == true
}

test_invalid_value if {
    not data.compliance_framework.azure_tags.deny_no_data_classification.allow with input as {"Name": "dataclassification", "Value": "error"}
}

test_invalid_name if {
    not data.compliance_framework.azure_tags.deny_no_data_classification.allow with input as {"Name": "error", "Value": "Confidential"}
}

test_invalid_name_key if {
    not data.compliance_framework.azure_tags.deny_no_data_classification.allow with input as {"Error": "dataclassification", "Value": "Confidential"}
}

test_invalid_value_key if {
    not data.compliance_framework.azure_tags.deny_no_data_classification.allow with input as {"Name": "dataclassification", "Error": "Confidential"}
}