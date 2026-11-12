terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.70" }
    archive = { source = "hashicorp/archive", version = "~> 2.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = { project = "tripwire" } }
}

data "aws_caller_identity" "me" {}
data "aws_partition" "p" {}

locals {
  n       = var.name_prefix
  account = data.aws_caller_identity.me.account_id
}

# ---------------- storage ----------------

resource "aws_s3_bucket" "models" {
  bucket_prefix = "${local.n}-models-"
  force_destroy = true
}
resource "aws_s3_bucket_versioning" "models" {
  bucket = aws_s3_bucket.models.id
  versioning_configuration { status = "Enabled" } # roll back a bad model in one step
}
resource "aws_s3_bucket_public_access_block" "models" {
  bucket                  = aws_s3_bucket.models.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "baselines" {
  name         = "${local.n}-baselines"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"
  attribute {
    name = "identity"
    type = "S"
  }
}

resource "aws_dynamodb_table" "recent" {
  name         = "${local.n}-recent"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "identity"
  range_key    = "t"
  attribute {
    name = "identity"
    type = "S"
  }
  attribute {
    name = "t"
    type = "N"
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

resource "aws_dynamodb_table" "incidents" {
  name         = "${local.n}-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "key"
  attribute {
    name = "key"
    type = "S"
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
}

resource "aws_secretsmanager_secret" "slack" {
  name_prefix = "${local.n}-slack-bot-token-"
  description = "Slack bot token (xoxb-...) with chat:write. Set the value by hand, never in Terraform."
}

# ---------------- lambda ----------------

# zip keeps the tripwire/ package folder so the relative imports work
data "archive_file" "pkg" {
  type        = "zip"
  output_path = "${path.module}/build/tripwire.zip"
  dynamic "source" {
    for_each = fileset("${path.module}/../tripwire", "*.py")
    content {
      content  = file("${path.module}/../tripwire/${source.value}")
      filename = "tripwire/${source.value}"
    }
  }
}

resource "aws_lambda_function" "detector" {
  function_name    = "${local.n}-detector"
  role             = aws_iam_role.fn.arn
  runtime          = "python3.12"
  handler          = "tripwire.handler.handler"
  filename         = data.archive_file.pkg.output_path
  source_code_hash = data.archive_file.pkg.output_base64sha256
  memory_size      = 512
  timeout          = 15

  environment {
    variables = {
      MODEL_BUCKET     = aws_s3_bucket.models.id
      MODEL_KEY        = "models/latest.json"
      BASELINE_TABLE   = aws_dynamodb_table.baselines.name
      RECENT_TABLE     = aws_dynamodb_table.recent.name
      INCIDENT_TABLE   = aws_dynamodb_table.incidents.name
      SLACK_SECRET_ARN = var.enable_slack ? aws_secretsmanager_secret.slack.arn : ""
      SLACK_CHANNEL    = var.slack_channel
      BEDROCK_MODEL_ID = var.bedrock_model_id
    }
  }
  depends_on = [aws_cloudwatch_log_group.fn]
}

resource "aws_cloudwatch_log_group" "fn" {
  name              = "/aws/lambda/${local.n}-detector"
  retention_in_days = 14
}

resource "aws_iam_role" "fn" {
  name_prefix = "${local.n}-fn-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# least privilege: read the model, read baselines, read/write only its own two working tables
resource "aws_iam_role_policy" "fn" {
  role = aws_iam_role.fn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.models.arn}/models/*" },
      { Effect = "Allow", Action = ["dynamodb:GetItem"], Resource = aws_dynamodb_table.baselines.arn },
      { Effect = "Allow", Action = ["dynamodb:PutItem", "dynamodb:Query"], Resource = aws_dynamodb_table.recent.arn },
      { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:PutItem"], Resource = aws_dynamodb_table.incidents.arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.fn.arn}:*" },
      ],
      var.enable_slack ? [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.slack.arn }] : [],
      var.bedrock_model_id != "" ? [{ Effect = "Allow", Action = ["bedrock:InvokeModel"], Resource = "*" }] : []
    )
  })
}

# ---------------- events ----------------

resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "${local.n}-cloudtrail-calls"
  description = "Every CloudTrail management event in this region goes to the detector"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    # don't score our own Lambda's DynamoDB/S3 calls, that would loop
    detail = { userIdentity = { arn = [{ "anything-but" = { prefix = "arn:${data.aws_partition.p.partition}:sts::${local.account}:assumed-role/${aws_iam_role.fn.name}" } }] } }
  })
}

resource "aws_cloudwatch_event_target" "fn" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = aws_lambda_function.detector.arn
  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 600
  }
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail.arn
}

# ---------------- trail (optional, if the account has none) ----------------

resource "aws_s3_bucket" "trail" {
  count         = var.create_trail ? 1 : 0
  bucket_prefix = "${local.n}-trail-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count                   = var.create_trail ? 1 : 0
  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.create_trail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "AclCheck", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:GetBucketAcl", Resource = aws_s3_bucket.trail[0].arn },
      { Sid      = "Write", Effect = "Allow", Principal = { Service = "cloudtrail.amazonaws.com" }, Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account}/*",
      Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
    ]
  })
}

resource "aws_cloudtrail" "main" {
  count                         = var.create_trail ? 1 : 0
  name                          = "${local.n}-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  is_multi_region_trail         = true
  include_global_service_events = true
  event_selector {
    read_write_type           = "All" # read only calls (List*, Describe*, Get*) are most of an attacker's recon
    include_management_events = true
  }
  depends_on = [aws_s3_bucket_policy.trail]
}
