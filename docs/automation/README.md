# ⚙️ Advanced Automation & CI/CD

**Mission:** Master automation frameworks, CI/CD pipelines, and workflow orchestration.  
**Skills:** Shell scripting, Python automation, GitHub Actions, GitLab CI, Jenkins  
**Prerequisites:** Programming basics, Git fundamentals

---

## Python Automation Scripts

### System Administration
```python
#!/usr/bin/env python3
"""
Enterprise-grade system monitoring and alerting
"""
import psutil
import smtplib
from email.mime.text import MIMEText
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_disk_usage(threshold=90):
    """Alert if disk usage exceeds threshold"""
    for partition in psutil.disk_partitions():
        usage = psutil.disk_usage(partition.mountpoint)
        if usage.percent > threshold:
            logging.warning(f"Disk {partition.mountpoint} at {usage.percent}%")
            send_alert(f"Disk Alert: {partition.mountpoint} at {usage.percent}%")

def check_memory_usage(threshold=85):
    """Alert if memory usage exceeds threshold"""
    memory = psutil.virtual_memory()
    if memory.percent > threshold:
        logging.warning(f"Memory usage at {memory.percent}%")
        send_alert(f"Memory Alert: {memory.percent}% used")

def check_cpu_usage(threshold=80, duration=5):
    """Alert if CPU usage sustained above threshold"""
    cpu_percent = psutil.cpu_percent(interval=duration)
    if cpu_percent > threshold:
        logging.warning(f"CPU usage at {cpu_percent}%")
        send_alert(f"CPU Alert: {cpu_percent}% usage")

def send_alert(message):
    """Send email alert"""
    msg = MIMEText(message)
    msg['Subject'] = 'System Alert'
    msg['From'] = 'monitoring@example.com'
    msg['To'] = 'admin@example.com'
    
    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)

if __name__ == '__main__':
    check_disk_usage()
    check_memory_usage()
    check_cpu_usage()
```

### AWS Resource Management
```python
#!/usr/bin/env python3
"""
Automated AWS resource tagging and cleanup
"""
import boto3
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')
s3 = boto3.client('s3')

def tag_untagged_resources():
    """Tag resources missing required tags"""
    instances = ec2.describe_instances()
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
            
            if 'Environment' not in tags:
                ec2.create_tags(
                    Resources=[instance['InstanceId']],
                    Tags=[{'Key': 'Environment', 'Value': 'unspecified'}]
                )
                print(f"Tagged instance {instance['InstanceId']}")

def cleanup_old_snapshots(days=90):
    """Delete snapshots older than specified days"""
    cutoff_date = datetime.now() - timedelta(days=days)
    snapshots = ec2.describe_snapshots(OwnerIds=['self'])
    
    for snapshot in snapshots['Snapshots']:
        if snapshot['StartTime'].replace(tzinfo=None) < cutoff_date:
            print(f"Deleting snapshot {snapshot['SnapshotId']}")
            ec2.delete_snapshot(SnapshotId=snapshot['SnapshotId'])

def cleanup_empty_s3_buckets():
    """Delete empty S3 buckets"""
    buckets = s3.list_buckets()
    
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        objects = s3.list_objects_v2(Bucket=bucket_name)
        
        if objects.get('KeyCount', 0) == 0:
            print(f"Deleting empty bucket {bucket_name}")
            s3.delete_bucket(Bucket=bucket_name)

if __name__ == '__main__':
    tag_untagged_resources()
    cleanup_old_snapshots()
    cleanup_empty_s3_buckets()
```

---

## GitHub Actions CI/CD

### Complete CI/CD Pipeline
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
        
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov
        
    - name: Run tests
      run: |
        pytest tests/ --cov=src --cov-report=xml
        
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  build:
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      
    steps:
    - uses: actions/checkout@v3
    
    - name: Log in to Container Registry
      uses: docker/login-action@v2
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
        
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=sha,prefix={{branch}}-
          
    - name: Build and push Docker image
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure kubectl
      uses: azure/k8s-set-context@v3
      with:
        method: kubeconfig
        kubeconfig: ${{ secrets.KUBE_CONFIG }}
        
    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/webapp \
          webapp=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        kubectl rollout status deployment/webapp
        
    - name: Notify Slack
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        text: 'Deployment to production: ${{ job.status }}'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
      if: always()
```

---

## GitLab CI/CD

### Advanced Pipeline
```yaml
# .gitlab-ci.yml
stages:
  - test
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  IMAGE_TAG: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA

test:
  stage: test
  image: python:3.11
  script:
    - pip install -r requirements.txt
    - pytest tests/ --junitxml=report.xml --cov
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      junit: report.xml
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml

build:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $IMAGE_TAG .
    - docker push $IMAGE_TAG
  only:
    - main
    - develop

deploy_staging:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - kubectl config use-context staging
    - kubectl set image deployment/webapp webapp=$IMAGE_TAG
    - kubectl rollout status deployment/webapp
  environment:
    name: staging
    url: https://staging.example.com
  only:
    - develop

deploy_production:
  stage: deploy
  image: bitnami/kubectl:latest
  script:
    - kubectl config use-context production
    - kubectl set image deployment/webapp webapp=$IMAGE_TAG
    - kubectl rollout status deployment/webapp
  environment:
    name: production
    url: https://example.com
  when: manual
  only:
    - main
```

---

## Jenkins Pipeline (Jenkinsfile)

### Declarative Pipeline
```groovy
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = 'registry.example.com'
        IMAGE_NAME = 'myapp'
        KUBECONFIG = credentials('kubeconfig-production')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Test') {
            steps {
                sh '''
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install -r requirements.txt
                    pytest tests/
                '''
            }
        }
        
        stage('Build') {
            steps {
                script {
                    def image = docker.build("${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}")
                    docker.withRegistry("https://${DOCKER_REGISTRY}", 'docker-credentials') {
                        image.push()
                        image.push('latest')
                    }
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'develop'
            }
            steps {
                sh '''
                    kubectl set image deployment/webapp \
                        webapp=${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} \
                        --kubeconfig=${KUBECONFIG}
                '''
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy'
                sh '''
                    kubectl set image deployment/webapp \
                        webapp=${DOCKER_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} \
                        --kubeconfig=${KUBECONFIG} \
                        --namespace=production
                '''
            }
        }
    }
    
    post {
        success {
            slackSend color: 'good', message: "Build ${BUILD_NUMBER} succeeded"
        }
        failure {
            slackSend color: 'danger', message: "Build ${BUILD_NUMBER} failed"
        }
    }
}
```

---

## Ansible Automation

### Inventory Management
```ini
# inventory/production/hosts
[webservers]
web01.example.com ansible_host=10.0.1.10
web02.example.com ansible_host=10.0.1.11

[databases]
db01.example.com ansible_host=10.0.2.10

[all:vars]
ansible_user=deploy
ansible_ssh_private_key_file=~/.ssh/deploy_key
```

### Playbook Example
```yaml
# playbooks/deploy.yml
---
- name: Deploy application
  hosts: webservers
  become: yes
  
  vars:
    app_version: "{{ lookup('env', 'APP_VERSION') | default('latest') }}"
    
  tasks:
    - name: Pull Docker image
      docker_image:
        name: "registry.example.com/myapp:{{ app_version }}"
        source: pull
        
    - name: Stop old container
      docker_container:
        name: myapp
        state: stopped
      ignore_errors: yes
      
    - name: Remove old container
      docker_container:
        name: myapp
        state: absent
        
    - name: Start new container
      docker_container:
        name: myapp
        image: "registry.example.com/myapp:{{ app_version }}"
        state: started
        restart_policy: always
        ports:
          - "8080:8080"
        env:
          DATABASE_URL: "{{ database_url }}"
```

---

**Automation module complete. CI/CD mastery achieved.**

**Module Status:** ✅ COMPLETE  
**Coverage:** Python automation, GitHub Actions, GitLab CI, Jenkins, Ansible