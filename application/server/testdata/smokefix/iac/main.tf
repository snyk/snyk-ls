resource "aws_s3_bucket" "bad" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
