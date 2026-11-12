output "model_bucket" { value = aws_s3_bucket.models.id }
output "baseline_table" { value = aws_dynamodb_table.baselines.name }
output "incident_table" { value = aws_dynamodb_table.incidents.name }
output "slack_secret_arn" { value = aws_secretsmanager_secret.slack.arn }
output "function_name" { value = aws_lambda_function.detector.function_name }
