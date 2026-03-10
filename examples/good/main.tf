# examples/good/main.tf — security-conscious configs

# Scoped IAM policy
resource "aws_iam_role_policy" "scoped" {
  name = "scoped-s3-policy"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["${aws_s3_bucket.secure.arn}/*"]
    }]
  })
}

# S3 with encryption and blocked public access
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket-${var.account_id}"
}
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# Restricted security group
resource "aws_security_group" "app" {
  name   = "app-sg"
  vpc_id = var.vpc_id
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
  }
}

# Encrypted private RDS
resource "aws_db_instance" "secure" {
  identifier          = "my-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  deletion_protection = true
}

# Encrypted S3 with versioning
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration { status = "Enabled" }
}
