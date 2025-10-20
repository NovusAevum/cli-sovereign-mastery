initialDelaySeconds: 5
          periodSeconds: 5
```

```bash
# Apply deployment
kubectl apply -f deployment.yaml

# Rollout operations
kubectl rollout status deployment/webapp
kubectl rollout history deployment/webapp
kubectl rollout undo deployment/webapp
kubectl rollout undo deployment/webapp --to-revision=2

# Scale deployment
kubectl scale deployment webapp --replicas=5

# Autoscaling
kubectl autoscale deployment webapp --min=3 --max=10 --cpu-percent=70
```

### Services & Ingress
```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: webapp-service
spec:
  type: LoadBalancer
  selector:
    app: webapp
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: webapp-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - webapp.example.com
    secretName: webapp-tls
  rules:
  - host: webapp.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: webapp-service
            port:
              number: 80
```

### ConfigMaps & Secrets
```bash
# Create ConfigMap
kubectl create configmap app-config --from-file=config.properties

# Create Secret
kubectl create secret generic db-secret --from-literal=username=admin --from-literal=password=SecureP@ss

# From file
kubectl create secret generic tls-secret --from-file=tls.crt --from-file=tls.key

# View secrets (base64 decode)
kubectl get secret db-secret -o jsonpath='{.data.password}' | base64 -d
```

### StatefulSets (Databases)
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 100Gi
```

### Helm Package Manager
```bash
# Add repository
helm repo add stable https://charts.helm.sh/stable
helm repo update

# Search charts
helm search repo nginx

# Install chart
helm install my-nginx stable/nginx-ingress --namespace ingress --create-namespace

# List releases
helm list -A

# Upgrade release
helm upgrade my-nginx stable/nginx-ingress --set controller.replicaCount=3

# Rollback
helm rollback my-nginx 1

# Uninstall
helm uninstall my-nginx -n ingress

# Create custom chart
helm create mychart
```

### Advanced kubectl Techniques
```bash
# Get resources across all namespaces
kubectl get pods -A

# Output in JSON/YAML
kubectl get deployment webapp -o yaml
kubectl get pods -o json | jq '.items[].metadata.name'

# Custom columns
kubectl get pods -o custom-columns=NAME:.metadata.name,STATUS:.status.phase,NODE:.spec.nodeName

# Sort by
kubectl get pods --sort-by=.status.startTime

# Field selector
kubectl get pods --field-selector=status.phase=Running

# Label selector
kubectl get pods -l app=webapp,env=production

# Resource usage
kubectl top pods
kubectl top nodes

# Debug pod
kubectl debug -it nginx --image=busybox --target=nginx

# Cordon/drain nodes (maintenance)
kubectl cordon node-1
kubectl drain node-1 --ignore-daemonsets --delete-emptydir-data
kubectl uncordon node-1

# Events
kubectl get events --sort-by=.metadata.creationTimestamp

# Diff before apply
kubectl diff -f deployment.yaml
```

### Container Security
```bash
# Security context in pod
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: myapp:v1
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
        - ALL
```

```bash
# Scan images for vulnerabilities
docker scan myapp:v1.0

# Trivy scanner
trivy image myapp:v1.0

# Network policies
kubectl apply -f network-policy.yaml
```

### Monitoring & Logging
```bash
# Prometheus queries
kubectl port-forward -n monitoring svc/prometheus-server 9090:80

# View logs from multiple pods
kubectl logs -l app=webapp --tail=100 -f

# Stern (advanced log tailing)
stern webapp --namespace production --since 15m

# Events watching
kubectl get events -w
```

---

## Container Registry Operations

### Docker Registry
```bash
# Tag image
docker tag myapp:v1.0 registry.example.com/myapp:v1.0

# Push to registry
docker login registry.example.com
docker push registry.example.com/myapp:v1.0

# Pull from registry
docker pull registry.example.com/myapp:v1.0
```

### AWS ECR
```bash
# Login
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com

# Create repository
aws ecr create-repository --repository-name myapp

# Push image
docker tag myapp:v1.0 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:v1.0
```

### GCR (Google Container Registry)
```bash
# Configure Docker
gcloud auth configure-docker

# Tag and push
docker tag myapp:v1.0 gcr.io/my-project/myapp:v1.0
docker push gcr.io/my-project/myapp:v1.0
```

### Azure Container Registry
```bash
# Login
az acr login --name myregistry

# Push image
docker tag myapp:v1.0 myregistry.azurecr.io/myapp:v1.0
docker push myregistry.azurecr.io/myapp:v1.0
```

---

## Production Best Practices

### Resource Management
```yaml
# Always set resource requests and limits
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Health Checks
```yaml
# Liveness probe (restart unhealthy containers)
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

# Readiness probe (remove from service if not ready)
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

### High Availability
```yaml
# Pod anti-affinity (spread across nodes)
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchExpressions:
        - key: app
          operator: In
          values:
          - webapp
      topologyKey: kubernetes.io/hostname

# Pod disruption budget
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: webapp-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: webapp
```

---

## 🎓 Container & Kubernetes Mastery Complete

You've mastered containerization and orchestration at enterprise scale. You can now build optimized Docker images, orchestrate complex applications with Kubernetes, implement production-grade deployment patterns, and secure containerized workloads.

**Your Container Capabilities:**

You understand the complete container lifecycle from image creation through deployment to monitoring. You can design multi-stage builds for optimization, configure Helm charts for reproducible deployments, implement network policies for security, and troubleshoot container issues efficiently. Your Kubernetes knowledge covers pods, deployments, services, ingress, persistent storage, and secrets management.

**Professional Application:**

Modern infrastructure runs on containers and Kubernetes. You can now migrate legacy applications to containers, implement microservices architectures, scale applications horizontally with ease, and maintain consistent environments from development through production. These skills are fundamental to cloud-native engineering roles.

**Continue Your Journey:** [Monitoring Module](../monitoring/README.md) or [Automation Module](../automation/README.md)

---

**Module Status:** ✅ COMPLETE  
**Skill Level:** Advanced Container Orchestration  
**Coverage:** Docker Advanced Operations, Kubernetes, Helm, Security, Production Patterns  
**Lines:** 355+

**Author:** Wan Mohamad Hanis bin Wan Hassan  
**Framework:** CLI Sovereign Mastery | MPNS™ Methodology  
**Last Updated:** October 20, 2025
