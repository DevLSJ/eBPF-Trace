output "ec2_public_ip" { value = aws_instance.backend.public_ip }
output "instance_id" { value = aws_instance.backend.id }
output "security_group_id" { value = aws_security_group.backend.id }
