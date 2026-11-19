group "default" {
  targets = ["collector", "analyzer", "llm-gateway", "api"]
}

variable "tags" {
  default = ["latest", "0.1.0", "dev"]
  type = list(string)
}

target "collector" {
  dockerfile = "apps/collector/Dockerfile"
  context    = "."
  tags       = [for tag in tags : "agpenton/pihole-dns-collector:${tag}"]
  platforms  = ["linux/arm64"]
}

target "analyzer" {
  dockerfile = "apps/analyzer/Dockerfile"
  context    = "."
  tags       = [for tag in tags : "agpenton/pihole-security-analyzer:${tag}"]
  platforms  = ["linux/arm64"]
}

target "llm-gateway" {
  dockerfile = "apps/llm-gateway/Dockerfile"
  context    = "."
  tags       = [for tag in tags : "agpenton/pihole-llm-gateway:${tag}"]
  platforms  = ["linux/arm64"]
}

target "api" {
  dockerfile = "apps/api/Dockerfile"
  context    = "."
  tags       = [for tag in tags : "agpenton/pihole-ai-api:${tag}"]
  platforms  = ["linux/arm64"]
}
