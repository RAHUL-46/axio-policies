package gaia.run

default allow := false

allow if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
}

allow if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
}

allow if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"
}
