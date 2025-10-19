# ☁️ Cloud Platform Mastery: Multi-Cloud CLI Excellence

**Mission:** Master AWS, GCP, and Azure CLI tools for professional cloud operations.  
**Certifications:** AWS Solutions Architect, GCP Professional Architect, Azure Administrator  
**Prerequisites:** Networking fundamentals, Linux administration

---

## AWS CLI Complete Reference

### EC2 Instance Management
```bash
# List instances with custom output
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PrivateIpAddress,Tags[?Key==`Name`].Value|[0]]' --output table

# Start/stop instances by tag
aws ec2 describe-instances --filters "Name=tag:Environment,Values=Development" --query 'Reservations[*].Instances[*].InstanceId' --output text | xargs aws ec2 stop-instances --instance-ids

# Create instance from CLI
aws ec2 run-instances --image-id ami-12345678 --instance-type t3.medium --key-name my-key --security-group-ids sg-12345 --subnet-id subnet-12345 --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=WebServer}]'
```

### S3 Operations
```bash
# Sync with exclusions
aws s3 sync ./local s3://bucket/prefix --exclude "*.tmp" --include "*.log"

# Multipart upload for large files
aws s3 cp large-file.zip s3://bucket/ --storage-class GLACIER

# Pre-signed URLs (temporary access)
aws s3 presign s3://bucket/file.txt --expires-in 3600
```

### Lambda Functions
```bash
# Create function
aws lambda create-function --function-name MyFunction --runtime python3.11 --role arn:aws:iam::123456789012:role/lambda-role --handler lambda_function.lambda_handler --zip-file fileb://function.zip

# Invoke function
aws lambda invoke --function-name MyFunction --payload '{"key":"value"}' response.json

# Update function code
aws lambda update-function-code --function-name MyFunction --zip-file fileb://function-v2.zip
```

---

## Google Cloud Platform (gcloud)

### Compute Engine
```bash
# Create instance
gcloud compute instances create web-server --zone=us-central1-a --machine-type=n2-standard-2 --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud

# SSH into instance
gcloud compute ssh web-server --zone=us-central1-a

# Create instance template
gcloud compute instance-templates create web-template --machine-type=n2-standard-2 --image-family=ubuntu-2204-lts

# Managed instance group (auto-scaling)
gcloud compute instance-groups managed create web-group --base-instance-name=web --template=web-template --size=3 --zone=us-central1-a
```

### Cloud Storage
```bash
# Create bucket
gsutil mb -l us-central1 gs://my-bucket

# Upload/download
gsutil cp file.txt gs://my-bucket/
gsutil cp gs://my-bucket/file.txt ./

# Sync directories
gsutil -m rsync -r ./local gs://my-bucket/prefix

# Set lifecycle
gsutil lifecycle set lifecycle.json gs://my-bucket
```

### BigQuery
```bash
# Run query
bq query --use_legacy_sql=false 'SELECT * FROM `project.dataset.table` LIMIT 10'

# Load data
bq load --source_format=CSV dataset.table gs://bucket/data.csv schema.json

# Extract data
bq extract dataset.table gs://bucket/export/*.csv
```

---

## Azure CLI (az)

### Virtual Machines
```bash
# Create VM
az vm create --resource-group myRG --name myVM --image UbuntuLTS --size Standard_D2s_v3 --admin-username azureuser --generate-ssh-keys

# List VMs
az vm list --output table

# Start/stop VM
az vm start --resource-group myRG --name myVM
az vm stop --resource-group myRG --name myVM
```

### Storage Accounts
```bash
# Create storage account
az storage account create --name mystorageaccount --resource-group myRG --location eastus --sku Standard_LRS

# Upload blob
az storage blob upload --account-name mystorageaccount --container-name mycontainer --name myblob --file ./file.txt

# Generate SAS token
az storage blob generate-sas --account-name mystorageaccount --container-name mycontainer --name myblob --permissions r --expiry 2025-12-31T23:59Z
```

### Azure Kubernetes Service
```bash
# Create AKS cluster
az aks create --resource-group myRG --name myAKSCluster --node-count 3 --enable-addons monitoring --generate-ssh-keys

# Get credentials
az aks get-credentials --resource-group myRG --name myAKSCluster

# Scale cluster
az aks scale --resource-group myRG --name myAKSCluster --node-count 5
```

---

## Multi-Cloud Cost Optimization

### AWS Cost Explorer CLI
```bash
# Get cost and usage
aws ce get-cost-and-usage --time-period Start=2025-01-01,End=2025-01-31 --granularity MONTHLY --metrics UnblendedCost --group-by Type=DIMENSION,Key=SERVICE

# Get rightsizing recommendations
aws ce get-rightsizing-recommendation --service AmazonEC2
```

### GCP Billing
```bash
# Export billing data to BigQuery
gcloud beta billing accounts list
gcloud beta billing accounts projects link my-project --billing-account=ABCDEF-123456-7890AB

# Query costs in BigQuery
bq query --use_legacy_sql=false 'SELECT service.description, SUM(cost) as total_cost FROM `project.billing.gcp_billing_export_v1` WHERE _PARTITIONDATE >= "2025-01-01" GROUP BY service.description ORDER BY total_cost DESC'
```

### Azure Cost Management
```bash
# Show costs
az consumption usage list --start-date 2025-01-01 --end-date 2025-01-31

# Get budget
az consumption budget list
```

---

**Cloud module complete. Multi-cloud mastery achieved.**