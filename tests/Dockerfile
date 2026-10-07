FROM --platform=linux/amd64 mirror.gcr.io/library/node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS toolchain

ARG TERRAFORM_VERSION=1.15.8
ARG OPENTOFU_VERSION=1.12.4
ARG AWS_PROVIDER_VERSION=6.51.0
ARG NULL_PROVIDER_VERSION=3.2.4
ARG RANDOM_PROVIDER_VERSION=3.7.2
ARG TIME_PROVIDER_VERSION=0.13.1
ARG LOCAL_PROVIDER_VERSION=2.5.3
ARG ARCHIVE_PROVIDER_VERSION=2.7.1

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AWS_DEFAULT_REGION=us-east-1 \
    AWS_ENDPOINT_URL=http://aws:4566 \
    TF_PLUGIN_CACHE_DIR=/opt/terraform-plugin-cache \
    TF_CLI_CONFIG_FILE=/etc/terraformrc.offline

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash ca-certificates curl unzip git jq ripgrep python3 python3-venv python3-pip \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g opencode-ai@1.17.8

RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir \
      awscli==1.45.51 boto3==1.43.51 jsonschema requests

ENV PATH=/opt/venv/bin:/usr/local/bin:${PATH}

RUN curl -fsSLo /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
 && curl -fsSLo /tmp/terraform_SHA256SUMS \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
 && cd /tmp \
 && grep "terraform_${TERRAFORM_VERSION}_linux_amd64.zip" terraform_SHA256SUMS \
      | sed 's/terraform_.*_linux_amd64.zip/terraform.zip/' | sha256sum -c - \
 && unzip -q /tmp/terraform.zip -d /usr/local/bin \
 && rm -f /tmp/terraform.zip /tmp/terraform_SHA256SUMS

RUN curl -fsSLo /tmp/tofu.zip \
      "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" \
 && curl -fsSLo /tmp/tofu_SHA256SUMS \
      "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_SHA256SUMS" \
 && cd /tmp \
 && grep "tofu_${OPENTOFU_VERSION}_linux_amd64.zip" tofu_SHA256SUMS \
      | sed 's/tofu_.*_linux_amd64.zip/tofu.zip/' | sha256sum -c - \
 && unzip -q /tmp/tofu.zip -d /usr/local/bin \
 && rm -f /tmp/tofu.zip /tmp/tofu_SHA256SUMS

# The workload network is offline, so every provider must come from this
# mirror. Each registry's own packages are seeded (OpenTofu's builds differ
# from HashiCorp's, so lock-file checksums only match their own registry). No
# `direct` installation is configured: an unmirrored provider fails in the
# agent container exactly as it would in the verifier runner.
RUN mkdir -p /opt/terraform-plugin-cache /tmp/provider-seed \
 && printf '%s\n' \
      'terraform {' \
      '  required_providers {' \
      "    aws     = { source = \"hashicorp/aws\", version = \"=${AWS_PROVIDER_VERSION}\" }" \
      "    null    = { source = \"hashicorp/null\", version = \"=${NULL_PROVIDER_VERSION}\" }" \
      "    random  = { source = \"hashicorp/random\", version = \"=${RANDOM_PROVIDER_VERSION}\" }" \
      "    time    = { source = \"hashicorp/time\", version = \"=${TIME_PROVIDER_VERSION}\" }" \
      "    local   = { source = \"hashicorp/local\", version = \"=${LOCAL_PROVIDER_VERSION}\" }" \
      "    archive = { source = \"hashicorp/archive\", version = \"=${ARCHIVE_PROVIDER_VERSION}\" }" \
      '  }' \
      '}' > /tmp/provider-seed/main.tf \
 && TF_CLI_CONFIG_FILE=/dev/null terraform -chdir=/tmp/provider-seed init -backend=false -input=false \
 && rm -rf /tmp/provider-seed/.terraform /tmp/provider-seed/.terraform.lock.hcl \
 && TF_CLI_CONFIG_FILE=/dev/null tofu -chdir=/tmp/provider-seed init -backend=false -input=false \
 && printf '%s\n' \
      'disable_checkpoint = true' \
      'provider_installation {' \
      '  filesystem_mirror {' \
      '    path    = "/opt/terraform-plugin-cache"' \
      '    include = ["registry.terraform.io/hashicorp/*", "registry.opentofu.org/hashicorp/*"]' \
      '  }' \
      '}' > /etc/terraformrc.offline \
 && rm -rf /tmp/provider-seed/.terraform /tmp/provider-seed/.terraform.lock.hcl \
 && env -u TF_PLUGIN_CACHE_DIR terraform -chdir=/tmp/provider-seed init -backend=false -input=false \
 && rm -rf /tmp/provider-seed/.terraform /tmp/provider-seed/.terraform.lock.hcl \
 && env -u TF_PLUGIN_CACHE_DIR tofu -chdir=/tmp/provider-seed init -backend=false -input=false \
 && rm -rf /tmp/provider-seed

# The read-only provider mirror and the writable runtime cache must differ.
ENV TF_PLUGIN_CACHE_DIR=/tmp/terraform-plugin-cache-runtime
RUN mkdir -p /tmp/terraform-plugin-cache-runtime \
 && chmod 1777 /tmp/terraform-plugin-cache-runtime

RUN groupadd --gid 10001 agent \
 && useradd --uid 10001 --gid 10001 --create-home --shell /bin/bash agent \
 && groupadd --gid 10002 verifier \
 && useradd --uid 10002 --gid 10002 --create-home --shell /bin/bash verifier \
 && chmod -R a+rX /opt/terraform-plugin-cache

FROM toolchain AS runner
COPY runtime/runner.py /opt/frostpass-runner.py
# Mirror the agent workspace so submitted scripts see the same paths.
COPY contracts/ /workspace/contracts/
RUN mkdir -p /workspace/submission /workspace/config /workspace/evidence /workspace/.copies \
 && chmod -R a+rX,a-w /workspace/contracts \
 && chown -R agent:agent /workspace/submission /workspace/evidence /workspace/.copies /home/agent
WORKDIR /workspace
USER agent

FROM toolchain AS verifier
COPY . /tests/
COPY contracts/ /contracts/
RUN mkdir -p /workspace/submission /workspace/config /logs/verifier \
 && chmod 0755 /tests/test.sh \
 && chown -R verifier:verifier /logs/verifier /home/verifier
WORKDIR /workspace
USER verifier
