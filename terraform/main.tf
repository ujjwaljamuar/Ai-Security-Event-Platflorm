
resource "aws_kinesis_stream" "security_events" {
  name             = var.stream_name
  retention_period = var.retention_hours
  encryption_type  = "KMS"
  kms_key_id       = "alias/aws/kinesis"
  stream_mode_details {
    stream_mode = "ON_DEMAND"
  }

  lifecycle {
    prevent_destroy = false
  }
}

data "aws_iam_policy_document" "producer" {
  statement {
    sid    = "PublishSecurityEvents"
    effect = "Allow"

    actions = [
      "kinesis:PutRecord",
      "kinesis:PutRecords",
    ]

    resources = [aws_kinesis_stream.security_events.arn]
  }
}

resource "aws_iam_policy" "producer" {
  name        = "${var.project_name}-${var.environment}-producer"
  description = "Allows publishing events to the security event stream."
  policy      = data.aws_iam_policy_document.producer.json
}

data "aws_iam_policy_document" "consumer" {
  statement {
    sid    = "ReadSecurityEvents"
    effect = "Allow"

    actions = [
      "kinesis:DescribeStream",
      "kinesis:DescribeStreamSummary",
      "kinesis:ListShards",
      "kinesis:GetShardIterator",
      "kinesis:GetRecords",
    ]

    resources = [aws_kinesis_stream.security_events.arn]
  }
}

resource "aws_iam_policy" "consumer" {
  name        = "${var.project_name}-${var.environment}-consumer"
  description = "Allows reading events from the security event stream."
  policy      = data.aws_iam_policy_document.consumer.json
}
