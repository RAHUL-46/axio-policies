package gaia.run

default allow := true

allow if {
    not deny
}

deny if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket"
    resource.change.after.acl == "public-read"
}

deny if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    resource.change.after.instance_type == "t2.micro"
}

deny if {
    some resource in input.resource_changes
    resource.type == "aws_security_group"

    some ingress in resource.change.after.ingress
    ingress.from_port == 22
    ingress.to_port == 22

    some cidr in ingress.cidr_blocks
    cidr == "0.0.0.0/0"
}
