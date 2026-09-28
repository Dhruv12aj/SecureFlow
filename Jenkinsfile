// SecureFlow CI/CD pipeline
// Build -> Test -> Code Quality -> Security -> Deploy (staging) -> Release (prod) -> Monitoring
// (stages are added one at a time)

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 40, unit: 'MINUTES')
    }

    // webhooks can't reach a laptop, so poll GitHub every couple of minutes
    triggers {
        pollSCM('H/2 * * * *')
    }

    environment {
        REGISTRY       = 'localhost:5000'
        IMAGE          = "${REGISTRY}/secureflow"
        DOCKER_NETWORK = 'secureflow-net'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_SHORT   = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.APP_VERSION = "${readFile('VERSION').trim()}.${env.BUILD_NUMBER}"
                    currentBuild.displayName = "#${env.BUILD_NUMBER}  v${env.APP_VERSION}"
                    currentBuild.description = "commit ${env.GIT_SHORT}"
                }
            }
        }

        stage('Build') {
            steps {
                sh '''
                    docker network inspect $DOCKER_NETWORK >/dev/null 2>&1 || docker network create $DOCKER_NETWORK

                    echo "==> python environment"
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install --quiet --upgrade pip
                    pip install --quiet -r requirements-dev.txt

                    echo "==> docker image $IMAGE:$APP_VERSION"
                    docker build \
                        --build-arg APP_VERSION=$APP_VERSION \
                        --label org.opencontainers.image.revision=$GIT_SHORT \
                        -t $IMAGE:$APP_VERSION -t $IMAGE:$GIT_SHORT .
                    docker push --quiet $IMAGE:$APP_VERSION
                    docker push --quiet $IMAGE:$GIT_SHORT

                    mkdir -p reports
                    jq -n --arg v "$APP_VERSION" --arg c "$GIT_SHORT" --arg b "$BUILD_NUMBER" \
                          --arg img "$IMAGE:$APP_VERSION" \
                          --arg size "$(docker image inspect -f '{{.Size}}' $IMAGE:$APP_VERSION)" \
                          '{version: $v, commit: $c, build: $b, image: $img, size_bytes: $size, built_at: (now | todate)}' \
                          > reports/build-info.json
                    cat reports/build-info.json
                '''
            }
            post {
                success { archiveArtifacts artifacts: 'reports/build-info.json', fingerprint: true }
            }
        }
    }
}
