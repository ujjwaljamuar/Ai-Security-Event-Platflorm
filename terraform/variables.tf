variable "aws_region" {
  description = "AWS region for the security event platform."
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Project identifier used for resource naming and tags."
  type        = string
  default     = "ai-security-event-platform"
}

variable "environment" {
  description = "Deployment environment."
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "Environment must be dev, test, or prod."
  }
}

variable "stream_name" {
  description = "Kinesis Data Stream name."
  type        = string
  default     = "security-events-dev"
}

variable "retention_hours" {
  description = "Number of hours Kinesis retains records."
  type        = number
  default     = 24

  validation {
    condition     = var.retention_hours >= 24 && var.retention_hours <= 8760
    error_message = "Retention must be between 24 and 8760 hours."
  }
}

variable "shard_count" {
  description = "Initial shard count if using provisioned capacity."
  type        = number
  default     = 1

  validation {
    condition     = var.shard_count >= 1
    error_message = "Shard count must be at least one."
  }
}