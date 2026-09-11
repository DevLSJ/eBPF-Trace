# Local validation: terraform init -backend=false.
# CI requires a pre-existing private, versioned S3 bucket (TF_STATE_BUCKET).
terraform {
  backend "s3" {}
}
