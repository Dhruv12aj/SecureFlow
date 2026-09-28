# Jenkins controller with everything the SecureFlow pipeline needs baked in:
# docker CLI + compose, python, trivy and sonar-scanner. Configuration
# (admin user, credentials, the pipeline job) comes from casc.yaml.
FROM jenkins/jenkins:lts-jdk17

USER root

ARG TRIVY_VERSION=0.58.1
ARG SONAR_SCANNER_VERSION=6.2.1.4610

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg jq unzip git python3 python3-venv python3-pip \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# trivy + sonar-scanner (works on both Intel/AMD and ARM laptops)
RUN ARCH=$(dpkg --print-architecture) \
    && if [ "$ARCH" = "arm64" ]; then T_ARCH=ARM64; S_ARCH=linux-aarch64; else T_ARCH=64bit; S_ARCH=linux-x64; fi \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${T_ARCH}.tar.gz" \
        | tar -xz -C /usr/local/bin trivy \
    && curl -fsSL -o /tmp/scanner.zip \
        "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-${S_ARCH}.zip" \
    && unzip -q /tmp/scanner.zip -d /opt \
    && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-${S_ARCH}/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && rm /tmp/scanner.zip

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY casc.yaml /var/jenkins_home/casc_configs/casc.yaml
ENV CASC_JENKINS_CONFIG=/var/jenkins_home/casc_configs/casc.yaml \
    JAVA_OPTS="-Djenkins.install.runSetupWizard=false"

# stays root so it can talk to Docker Desktop's socket - fine for a local lab,
# would be a dedicated build agent in a real company
