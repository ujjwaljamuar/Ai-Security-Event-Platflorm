output "stream_name" {
  description = "Name of the Kinesis Data Stream."
  value       = aws_kinesis_stream.security_events.name
}

output "stream_arn" {
  description = "ARN of the Kinesis Data Stream."
  value       = aws_kinesis_stream.security_events.arn
}

output "producer_policy_arn" {
  description = "IAM policy ARN for event producers."
  value       = aws_iam_policy.producer.arn
}

output "consumer_policy_arn" {
  description = "IAM policy ARN for event consumers."
  value       = aws_iam_policy.consumer.arn
}