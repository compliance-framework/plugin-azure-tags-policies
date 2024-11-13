package compliance_framework.azure_tags.deny_no_data_classification

test_valid {
    count(violation) == 0 with input as {"dataclassification": "Public"}
}

test_valid_2 {
    count(violation) == 0 with input as {"dataclassification": "Top Secret"}
}

test_invalid_value {
    count(violation) == 1 with input as {"tags": {"dataclassification": "error"}}
}

test_invalid_name {
    count(violation) == 1 with input as {"tags": {"error": "Confidential"}}
}

test_non_existent {
    count(violation) == 1 with input as {"tags": {"something": "else"}}
}
