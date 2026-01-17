# examples/bad/main.tf — intentionally insecure configs for testing

# IAM wildcard
resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = aws_iam_role.main.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["*"], Resource = ["*"] }]
  })
}

# Open security group
resource "aws_security_group" "wide_open" {
  name   = "wide-open"
  vpc_id = var.vpc_id
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Unencrypted public RDS with hardcoded password
resource "aws_db_instance" "insecure" {
  identifier          = "my-db"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "hardcoded-password-123"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

# Lambda with admin access
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
