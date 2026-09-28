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

    parameters {
        booleanParam(name: 'RELEASE_TO_PROD', defaultValue: true,
            description: 'Promote to production once staging is healthy')
        booleanParam(name: 'REQUIRE_APPROVAL', defaultValue: false,
            description: 'Pause for a manual OK before the production release')
        booleanParam(name: 'SIMULATE_BAD_DEPLOY', defaultValue: false,
            description: 'Rollback demo: break the staging deployment on purpose')
    }

    environment {
        REGISTRY       = 'localhost:5000'
        IMAGE          = "${REGISTRY}/secureflow"
        SONAR_HOST_URL = 'http://sonarqube:9000'
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

        stage('Test') {
            steps {
                sh '''
                    . .venv/bin/activate
                    echo "==> unit tests"
                    pytest -m unit -q --junitxml=reports/junit-unit.xml --cov=app

                    echo "==> integration tests"
                    pytest -m integration -q --junitxml=reports/junit-integration.xml \
                        --cov=app --cov-append \
                        --cov-report=term --cov-report=xml:reports/coverage.xml \
                        --cov-report=html:reports/htmlcov \
                        --cov-fail-under=80
                '''
            }
            post {
                always {
                    junit 'reports/junit-*.xml'
                    publishHTML(target: [reportName: 'Coverage Report', reportDir: 'reports/htmlcov',
                                         reportFiles: 'index.html', keepAll: true,
                                         alwaysLinkToLastBuild: true, allowMissing: true])
                }
            }
        }

        stage('Code Quality') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        bash scripts/sonar_quality_gate.sh
                        sonar-scanner \
                            -Dsonar.host.url=$SONAR_HOST_URL \
                            -Dsonar.token=$SONAR_TOKEN \
                            -Dsonar.projectVersion=$APP_VERSION \
                            -Dsonar.qualitygate.wait=true \
                            -Dsonar.qualitygate.timeout=300
                    '''
                }
            }
        }

        stage('Security') {
            steps {
                sh '''
                    . .venv/bin/activate
                    mkdir -p reports/security

                    echo "==> Bandit (Python code)"
                    bandit -r app -f json -o reports/security/bandit.json --exit-zero
                    bandit -r app -ll

                    echo "==> pip-audit (dependencies)"
                    pip-audit -r requirements.txt -f json -o reports/security/pip-audit.json || true
                    pip-audit -r requirements.txt --desc

                    echo "==> Trivy (secrets in the repo)"
                    trivy fs --scanners secret --skip-dirs .git,.venv,reports --exit-code 1 --no-progress .

                    echo "==> Trivy (container image)"
                    trivy image --format json -o reports/security/trivy-image.json --no-progress $IMAGE:$APP_VERSION
                    trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress $IMAGE:$APP_VERSION
                '''
            }
            post {
                always { archiveArtifacts artifacts: 'reports/security/**', allowEmptyArchive: true }
            }
        }

        stage('Deploy: Staging') {
            steps {
                withCredentials([string(credentialsId: 'staging-analyst-key', variable: 'ANALYST_API_KEY'),
                                 string(credentialsId: 'staging-admin-key',   variable: 'ADMIN_API_KEY')]) {
                    withEnv(["BREAK_DEPLOY=${params.SIMULATE_BAD_DEPLOY}"]) {
                        sh 'bash scripts/deploy.sh staging $APP_VERSION'
                    }
                    sh '''
                        bash scripts/smoke_test.sh http://secureflow-staging:8000
                        echo "==> checking the detector blocks real attacks"
                        python3 scripts/attack_sim.py --target http://secureflow-staging:8000 --delay 0.1
                    '''
                }
            }
        }

        stage('Release: Production') {
            when { expression { params.RELEASE_TO_PROD } }
            steps {
                script {
                    if (params.REQUIRE_APPROVAL) {
                        input message: "Release v${env.APP_VERSION} to production?", ok: 'Release'
                    }
                }
                withCredentials([string(credentialsId: 'prod-analyst-key', variable: 'ANALYST_API_KEY'),
                                 string(credentialsId: 'prod-admin-key',   variable: 'ADMIN_API_KEY')]) {
                    sh '''
                        echo "==> promoting $IMAGE:$APP_VERSION -> v$APP_VERSION"
                        docker tag $IMAGE:$APP_VERSION $IMAGE:v$APP_VERSION
                        docker tag $IMAGE:$APP_VERSION $IMAGE:latest
                        docker push --quiet $IMAGE:v$APP_VERSION
                        docker push --quiet $IMAGE:latest

                        bash scripts/deploy.sh prod v$APP_VERSION
                        bash scripts/smoke_test.sh http://secureflow-prod:8000
                    '''
                }
                withCredentials([usernamePassword(credentialsId: 'github-creds',
                                                  usernameVariable: 'GH_USER', passwordVariable: 'GH_TOKEN')]) {
                    sh 'bash scripts/release_tag.sh v$APP_VERSION'
                }
            }
            post {
                success { archiveArtifacts artifacts: 'reports/release-notes-*.md', allowEmptyArchive: true }
            }
        }
    }
}
