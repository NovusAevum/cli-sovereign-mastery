⭐ Strategic Command: System Mastery & Enterprise Architecture

**Mission Objective:** Achieve complete system sovereignty through infrastructure orchestration, multi-cloud mastery, and architectural excellence.  
**Skill Level:** Expert - Requires mastery of all previous modules  
**Certifications:** AWS Solutions Architect Professional, GCP Architect, Azure Solutions Architect, Terraform Associate

---

## 🎯 Strategic Command Philosophy

**Strategic commanders don't just execute—they architect.** This module elevates you from tactical operator to strategic architect, capable of designing and orchestrating enterprise-scale infrastructure, implementing disaster recovery at global scale, and optimizing systems for both performance and cost.

---

## PART 1: INFRASTRUCTURE AS CODE (IAC)

### Terraform Enterprise Patterns

**Multi-Environment Architecture:**
```hcl
# Directory structure:
# terraform/
# ├── modules/
# │   ├── networking/
# │   ├── compute/
# │   └── database/
# ├── environments/
# │   ├── dev/
# │   ├── staging/
# │   └── production/
# └── global/

# modules/networking/main.tf
variable "environment" {
  type = string
}

variable "vpc_cidr" {
  type = string
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.environment}-private-${count.index + 1}"
    Environment = var.environment
    Type        = "Private"
  }
}

# Output for use by other modules
output "vpc_id" {
  value = aws_vpc.main.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

# environments/production/main.tf
terraform {
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

module "networking" {
  source      = "../../modules/networking"
  environment = "production"
  vpc_cidr    = "10.0.0.0/16"
}

module "compute" {
  source            = "../../modules/compute"
  environment       = "production"
  vpc_id            = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
}
```

**Terraform CLI Operations:**
```bash
# Initialize with backend configuration
terraform init -backend-config="environments/production/backend.hcl"

# Plan with variable files
terraform plan -var-file="environments/production/terraform.tfvars" -out=production.tfplan

# Apply with approval
terraform apply production.tfplan

# Targeted resource changes
terraform apply -target=module.networking.aws_vpc.main

# Import existing infrastructure
terraform import aws_instance.web i-1234567890abcdef0

# State management
terraform state list
terraform state show aws_instance.web
terraform state mv aws_instance.web module.compute.aws_instance.web

# Workspace management (alternative to directories)
terraform workspace new production
terraform workspace select production
terraform workspace list

# Destroy with protection
terraform destroy -target=aws_instance.test  # Targeted destroy

# Advanced: Dynamic provider configuration
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      configuration_aliases = [aws.us_east_1, aws.eu_west_1]
    }
  }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"
}

# Multi-region deployment
resource "aws_s3_bucket" "primary" {
  provider = aws.us_east_1
  bucket   = "primary-bucket"
}

resource "aws_s3_bucket" "replica" {
  provider = aws.eu_west_1
  bucket   = "replica-bucket"
}
```

---

### Ansible Enterprise Orchestration

**Inventory Management:**
```yaml
# inventory/production/hosts.yml
all:
  children:
    webservers:
      hosts:
        web[01:03].prod.company.com:
      vars:
        ansible_user: deploy
        app_port: 8080
        
    databases:
      hosts:
        db01.prod.company.com:
          postgres_version: "14"
        db02.prod.company.com:
          postgres_version: "14"
          postgres_role: standby
      vars:
        ansible_user: dbadmin
        
    loadbalancers:
      hosts:
        lb[01:02].prod.company.com:
      vars:
        nginx_worker_processes: 8
        
  vars:
    ansible_ssh_private_key_file: ~/.ssh/production_key
    environment: production
```

**Advanced Playbooks:**
```yaml
# playbooks/deploy-application.yml
---
- name: Zero-downtime application deployment
  hosts: webservers
  serial: 1  # Rolling deployment (one host at a time)
  max_fail_percentage: 0
  
  pre_tasks:
    - name: Take server out of load balancer
      delegate_to: "{{ item }}"
      community.general.haproxy:
        state: disabled
        host: "{{ inventory_hostname }}"
        socket: /var/run/haproxy.sock
      loop: "{{ groups['loadbalancers'] }}"
      
  tasks:
    - name: Stop application
      systemd:
        name: myapp
        state: stopped
        
    - name: Backup current version
      archive:
        path: /opt/myapp
        dest: "/backups/myapp_{{ ansible_date_time.epoch }}.tar.gz"
        
    - name: Deploy new version
      unarchive:
        src: "{{ artifact_url }}"
        dest: /opt/myapp
        remote_src: yes
        
    - name: Run database migrations
      command: /opt/myapp/bin/migrate
      run_once: true
      
    - name: Start application
      systemd:
        name: myapp
        state: started
        enabled: yes
        
    - name: Wait for application health check
      uri:
        url: "http://localhost:{{ app_port }}/health"
        status_code: 200
      retries: 30
      delay: 2
      
  post_tasks:
    - name: Add server back to load balancer
      delegate_to: "{{ item }}"
      community.general.haproxy:
        state: enabled
        host: "{{ inventory_hostname }}"
        socket: /var/run/haproxy.sock
      loop: "{{ groups['loadbalancers'] }}"
      
  handlers:
    - name: Rollback on failure
      block:
        - name: Stop failed version
          systemd:
            name: myapp
            state: stopped
            
        - name: Restore previous version
          unarchive:
            src: "/backups/{{ rollback_version }}.tar.gz"
            dest: /opt/myapp
            
        - name: Start application
          systemd:
            name: myapp
            state: started
```

**Ansible CLI Operations:**
```bash
# Ad-hoc commands
ansible webservers -i inventory/production/hosts.yml -m ping
ansible webservers -m shell -a "uptime"
ansible databases -m command -a "df -h" --become

# Playbook execution
ansible-playbook -i inventory/production/hosts.yml playbooks/deploy-application.yml

# With extra variables
ansible-playbook playbooks/deploy.yml -e "artifact_url=https://artifacts/v2.3.0.tar.gz"

# Dry run (check mode)
ansible-playbook playbooks/deploy.yml --check --diff

# Limit to specific hosts
ansible-playbook playbooks/deploy.yml --limit web01.prod.company.com

# Tags for partial execution
ansible-playbook playbooks/full-setup.yml --tags "configuration,deployment"

# Vault for secrets
ansible-vault create secrets.yml
ansible-vault encrypt secrets.yml
ansible-playbook playbooks/deploy.yml --ask-vault-pass

# Dynamic inventory (AWS)
ansible-playbook -i aws_ec2.yml playbooks/deploy.yml

# Parallel execution control
ansible-playbook playbooks/deploy.yml --forks=10
```

---

## PART 2: MULTI-CLOUD ORCHESTRATION

### AWS CLI Mastery

**Advanced EC2 Operations:**
```bash
# Launch instance with detailed configuration
aws ec2 run-instances \
    --image-id ami-0c55b159cbfafe1f0 \
    --instance-type t3.medium \
    --key-name production-key \
    --security-group-ids sg-0123456789abcdef0 \
    --subnet-id subnet-0123456789abcdef0 \
    --iam-instance-profile Name=EC2-S3-Access \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=WebServer01},{Key=Environment,Value=Production}]' \
    --user-data file://userdata.sh \
    --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100,"VolumeType":"gp3","Iops":3000,"Throughput":125,"DeleteOnTermination":true}}]'

# Describe instances with advanced filtering
aws ec2 describe-instances \
    --filters "Name=tag:Environment,Values=Production" "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[*].[InstanceId,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' \
    --output table

# Automated instance management
# Stop all non-production instances (cost optimization)
aws ec2 describe-instances \
    --filters "Name=tag:Environment,Values=Development,Staging" "Name=instance-state-name,Values=running" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text | xargs -n 1 aws ec2 stop-instances --instance-ids

# Create AMI from running instance
aws ec2 create-image \
    --instance-id i-1234567890abcdef0 \
    --name "WebServer-Backup-$(date +%Y%m%d-%H%M%S)" \
    --description "Automated backup" \
    --no-reboot

# Cross-region AMI copy
aws ec2 copy-image \
    --source-region us-east-1 \
    --source-image-id ami-0123456789abcdef0 \
    --region eu-west-1 \
    --name "WebServer-DR-Copy"
```

**S3 Advanced Operations:**
```bash
# Sync with versioning and encryption
aws s3 sync /local/path s3://bucket/prefix \
    --storage-class INTELLIGENT_TIERING \
    --sse AES256 \
    --exclude "*.tmp" \
    --include "*.log" \
    --delete

# Lifecycle policy (cost optimization)
cat > lifecycle.json << 'EOF'
{
  "Rules": [{
    "Id": "Archive old logs",
    "Status": "Enabled",
    "Filter": {"Prefix": "logs/"},
    "Transitions": [
      {"Days": 30, "StorageClass": "STANDARD_IA"},
      {"Days": 90, "StorageClass": "GLACIER"},
      {"Days": 365, "StorageClass": "DEEP_ARCHIVE"}
    ],
    "Expiration": {"Days": 2555}
  }]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
    --bucket my-bucket \
    --lifecycle-configuration file://lifecycle.json

# Cross-region replication
aws s3api put-bucket-replication \
    --bucket source-bucket \
    --replication-configuration file://replication.json

# Inventory and analytics
aws s3api put-bucket-inventory-configuration \
    --bucket my-bucket \
    --id daily-inventory \
    --inventory-configuration file://inventory-config.json
```

**RDS Management:**
```bash
# Create production database with high availability
aws rds create-db-instance \
    --db-instance-identifier prod-postgres \
    --db-instance-class db.r6g.2xlarge \
    --engine postgres \
    --engine-version 14.7 \
    --master-username admin \
    --master-user-password "SecureP@ssw0rd" \
    --allocated-storage 500 \
    --storage-type gp3 \
    --iops 12000 \
    --storage-throughput 500 \
    --multi-az \
    --backup-retention-period 30 \
    --preferred-backup-window "03:00-04:00" \
    --preferred-maintenance-window "sun:04:00-sun:05:00" \
    --db-subnet-group-name production-db-subnet \
    --vpc-security-group-ids sg-0123456789abcdef0 \
    --enable-performance-insights \
    --performance-insights-retention-period 731 \
    --enable-cloudwatch-logs-exports '["postgresql"]' \
    --deletion-protection

# Create read replica
aws rds create-db-instance-read-replica \
    --db-instance-identifier prod-postgres-replica \
    --source-db-instance-identifier prod-postgres \
    --db-instance-class db.r6g.xlarge \
    --availability-zone us-east-1b

# Automated snapshots management
aws rds create-db-snapshot \
    --db-instance-identifier prod-postgres \
    --db-snapshot-identifier manual-backup-$(date +%Y%m%d)

# Copy snapshot to another region (DR)
aws rds copy-db-snapshot \
    --source-db-snapshot-identifier arn:aws:rds:us-east-1:123456789012:snapshot:prod-postgres-snapshot \
    --target-db-snapshot-identifier prod-postgres-dr-snapshot \
    --source-region us-east-1 \
    --region eu-west-1
```

---

### Google Cloud Platform (GCP) CLI

**GKE (Kubernetes Engine) Operations:**
```bash
# Create production-grade GKE cluster
gcloud container clusters create production-cluster \
    --region us-central1 \
    --node-locations us-central1-a,us-central1-b,us-central1-c \
    --num-nodes 3 \
    --machine-type n2-standard-4 \
    --disk-type pd-ssd \
    --disk-size 100 \
    --enable-autoscaling \
    --min-nodes 3 \
    --max-nodes 10 \
    --enable-autorepair \
    --enable-autoupgrade \
    --enable-ip-alias \
    --network projects/my-project/global/networks/production-vpc \
    --subnetwork projects/my-project/regions/us-central1/subnetworks/gke-subnet \
    --enable-private-nodes \
    --master-ipv4-cidr 172.16.0.0/28 \
    --enable-master-authorized-networks \
    --master-authorized-networks 10.0.0.0/8 \
    --enable-stackdriver-kubernetes \
    --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
    --enable-shielded-nodes \
    --shielded-secure-boot \
    --shielded-integrity-monitoring \
    --workload-pool=my-project.svc.id.goog

# Get cluster credentials
gcloud container clusters get-credentials production-cluster --region us-central1

# Node pool management
gcloud container node-pools create high-memory-pool \
    --cluster production-cluster \
    --region us-central1 \
    --machine-type n2-highmem-8 \
    --num-nodes 2 \
    --enable-autoscaling \
    --min-nodes 2 \
    --max-nodes 5

# Cluster upgrade
gcloud container clusters upgrade production-cluster \
    --region us-central1 \
    --master \
    --cluster-version 1.27.3-gke.100

gcloud container clusters upgrade production-cluster \
    --region us-central1 \
    --node-pool default-pool
```

**BigQuery Data Warehouse:**
```bash
# Create dataset
bq mk --dataset --location=US --description "Production analytics" my_project:analytics

# Load data from GCS
bq load \
    --source_format=CSV \
    --skip_leading_rows=1 \
    --autodetect \
    analytics.user_events \
    gs://my-bucket/events/*.csv

# Run query and save results
bq query \
    --use_legacy_sql=false \
    --destination_table=analytics.daily_summary \
    --replace \
    --allow_large_results \
'SELECT
    DATE(timestamp) as date,
    user_id,
    COUNT(*) as event_count,
    SUM(revenue) as total_revenue
FROM `my_project.analytics.user_events`
WHERE DATE(timestamp) = CURRENT_DATE() - 1
GROUP BY date, user_id'

# Export query results
bq extract \
    --destination_format=AVRO \
    --compression=SNAPPY \
    analytics.daily_summary \
    gs://export-bucket/daily_summary_*.avro

# Scheduled queries (automation)
bq mk \
    --transfer_config \
    --project_id=my_project \
    --data_source=scheduled_query \
    --display_name="Daily Revenue Aggregation" \
    --schedule="every day 01:00" \
    --params='{"query":"SELECT ...", "destination_table_name_template":"revenue_{run_date}", "write_disposition":"WRITE_TRUNCATE"}'
```

---

### Azure CLI Operations

**AKS (Azure Kubernetes Service):**
```bash
# Create resource group
az group create --name production-rg --location eastus

# Create AKS cluster with advanced configuration
az aks create \
    --resource-group production-rg \
    --name production-aks \
    --location eastus \
    --kubernetes-version 1.27.3 \
    --node-count 3 \
    --node-vm-size Standard_D4s_v3 \
    --node-osdisk-size 128 \
    --node-osdisk-type Managed \
    --enable-cluster-autoscaler \
    --min-count 3 \
    --max-count 10 \
    --network-plugin azure \
    --network-policy calico \
    --vnet-subnet-id /subscriptions/.../subnets/aks-subnet \
    --service-cidr 10.2.0.0/16 \
    --dns-service-ip 10.2.0.10 \
    --enable-managed-identity \
    --enable-addons monitoring \
    --workspace-resource-id /subscriptions/.../workspaces/production-logs \
    --enable-azure-rbac \
    --enable-pod-identity \
    --enable-secret-rotation \
    --attach-acr productionacr

# Get credentials
az aks get-credentials --resource-group production-rg --name production-aks

# Scale cluster
az aks scale --resource-group production-rg --name production-aks --node-count 5

# Upgrade cluster
az aks upgrade --resource-group production-rg --name production-aks --kubernetes-version 1.27.4
```

---

**Strategic Command establishing enterprise architecture patterns...**

**Continuing with disaster recovery, cost optimization, and operational excellence...**