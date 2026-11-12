variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "tripwire"
}

variable "create_trail" {
  description = "Create a multi region trail with read and write management events. Turn off if the account already has one."
  type        = bool
  default     = true
}

variable "enable_slack" {
  description = "Post to Slack. Put the bot token in the created secret first."
  type        = bool
  default     = false
}

variable "slack_channel" {
  type    = string
  default = "#sec-alerts"
}

variable "bedrock_model_id" {
  description = "Bedrock model or inference profile id for incident summaries. Empty = facts only, no LLM."
  type        = string
  default     = ""
}
