
    fi
    log "INFO: CPU usage at ${cpu_usage}%"
    return 0
}

check_memory() {
    mem_usage=$(free | grep Mem | awk '{print ($3/$2) * 100.0}')
    if (( $(echo "$mem_usage > $THRESHOLD_MEM" | bc -l) )); then
        log "WARNING: Memory usage at ${mem_usage}%"
        return 1
    fi
    log "INFO: Memory usage at ${mem_usage}%"
    return 0
}

check_disk() {
    while read -r line; do
        usage=$(echo "$line" | awk '{print $5}' | sed 's/%//')
        mount=$(echo "$line" | awk '{print $6}')
        if [ "$usage" -gt "$THRESHOLD_DISK" ]; then
            log "WARNING: Disk $mount at ${usage}%"
            return 1
        fi
    done < <(df -h | grep -vE '^Filesystem|tmpfs|cdrom')
    log "INFO: Disk usage acceptable"
    return 0
}

check_services() {
    services=("nginx" "postgresql" "redis")
    for service in "${services[@]}"; do
        if ! systemctl is-active --quiet "$service"; then
            log "CRITICAL: Service $service is down"
            return 1
        fi
    done
    log "INFO: All services running"
    return 0
}

main() {
    log "=== System Monitor Started ==="
    
    check_cpu
    check_memory
    check_disk
    check_services
    
    log "=== System Monitor Complete ==="
}

main
```

---

## Kubernetes Monitoring

### kubectl Top Commands
```bash
# Node resource usage
kubectl top nodes

# Pod resource usage
kubectl top pods -A

# Specific namespace
kubectl top pods -n production

# Sort by CPU
kubectl top pods -A --sort-by=cpu

# Sort by memory
kubectl top pods -A --sort-by=memory

# Container-level metrics
kubectl top pod webapp-5d8f7c9b6-xk2p9 --containers
```

### Prometheus ServiceMonitor (CRD)
```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: webapp-monitor
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: webapp
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

---

## Alerting Integration

### AlertManager Configuration
```yaml
# alertmanager.yml
global:
  resolve_timeout: 5m
  slack_api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'

route:
  group_by: ['alertname', 'cluster']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'slack-notifications'
  
  routes:
  - match:
      severity: critical
    receiver: 'pagerduty-critical'
    
  - match:
      severity: warning
    receiver: 'slack-warnings'

receivers:
- name: 'slack-notifications'
  slack_configs:
  - channel: '#alerts'
    title: 'Alert: {{ .GroupLabels.alertname }}'
    text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
    
- name: 'pagerduty-critical'
  pagerduty_configs:
  - service_key: 'YOUR_PAGERDUTY_KEY'
    
- name: 'slack-warnings'
  slack_configs:
  - channel: '#warnings'
    title: 'Warning: {{ .GroupLabels.alertname }}'

inhibit_rules:
- source_match:
    severity: 'critical'
  target_match:
    severity: 'warning'
  equal: ['alertname', 'instance']
```

### Slack Webhook Testing
```bash
# Send test alert to Slack
curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Test Alert: System monitoring active"}' \
    https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

---

## Performance Profiling

### Application Profiling (Python)
```python
import cProfile
import pstats
import io

def profile_function():
    pr = cProfile.Profile()
    pr.enable()
    
    # Your code to profile
    expensive_operation()
    
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats()
    print(s.getvalue())

# Memory profiling
from memory_profiler import profile

@profile
def memory_intensive_function():
    large_list = [i for i in range(1000000)]
    return sum(large_list)
```

### System Performance Tools
```bash
# CPU profiling with perf
perf record -g ./your-application
perf report

# System call tracing
strace -c ./your-application

# I/O statistics
iostat -x 1 10

# Network statistics
netstat -s

# Process tree with resource usage
pstree -p | grep your-process
ps aux --forest | grep your-process
```

---

## Custom Metrics Export

### Prometheus Custom Metrics (Python)
```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time

# Define metrics
request_count = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
active_users = Gauge('active_users', 'Number of active users')

# Use metrics
@request_duration.time()
def handle_request(method, endpoint):
    request_count.labels(method=method, endpoint=endpoint).inc()
    # Your request handling logic
    time.sleep(0.1)
    return "OK"

# Update gauge
active_users.set(42)

# Start metrics server
if __name__ == '__main__':
    start_http_server(8000)
    while True:
        handle_request('GET', '/api/users')
        time.sleep(1)
```

---

## Distributed Tracing

### Jaeger Integration (Python)
```python
from jaeger_client import Config
from flask import Flask
from flask_opentracing import FlaskTracing

def init_tracer(service_name):
    config = Config(
        config={
            'sampler': {'type': 'const', 'param': 1},
            'logging': True,
            'local_agent': {
                'reporting_host': 'localhost',
                'reporting_port': 6831
            }
        },
        service_name=service_name
    )
    return config.initialize_tracer()

app = Flask(__name__)
tracer = init_tracer('webapp')
tracing = FlaskTracing(tracer, True, app)

@app.route('/api/data')
def get_data():
    with tracer.start_span('database_query') as span:
        span.set_tag('db.type', 'postgresql')
        # Database query here
        result = query_database()
    return result
```

---

## Log Aggregation Best Practices

### Structured Logging (JSON)
```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

# Configure logger
logger = logging.getLogger()
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Usage
logger.info("User logged in", extra={'user_id': 12345, 'ip': '192.168.1.1'})
```

### Centralized Logging Commands
```bash
# Filebeat configuration for log shipping
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/app/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "app-logs-%{+yyyy.MM.dd}"

# Start Filebeat
filebeat -e -c filebeat.yml

# Query logs in Elasticsearch
curl -X GET "localhost:9200/app-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        { "match": { "level": "ERROR" } },
        { "range": { "timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}
'
```

---

## Monitoring Dashboard Automation

### Grafana API Usage
```bash
# Create dashboard via API
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @dashboard.json

# Create datasource
curl -X POST http://admin:admin@localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Prometheus",
    "type": "prometheus",
    "url": "http://localhost:9090",
    "access": "proxy",
    "isDefault": true
  }'

# Create alert notification channel
curl -X POST http://admin:admin@localhost:3000/api/alert-notifications \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Slack Alerts",
    "type": "slack",
    "isDefault": true,
    "settings": {
      "url": "https://hooks.slack.com/services/YOUR/WEBHOOK"
    }
  }'
```

---

## Health Check Endpoints

### Application Health Check
```python
from flask import Flask, jsonify
import psutil
import redis

app = Flask(__name__)

@app.route('/health')
def health_check():
    """Basic health check"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/health/detailed')
def detailed_health_check():
    """Detailed health check with dependencies"""
    health_status = {
        'status': 'healthy',
        'checks': {}
    }
    
    # Check database
    try:
        # db.execute("SELECT 1")
        health_status['checks']['database'] = {'status': 'up'}
    except Exception as e:
        health_status['checks']['database'] = {'status': 'down', 'error': str(e)}
        health_status['status'] = 'unhealthy'
    
    # Check Redis
    try:
        r = redis.Redis()
        r.ping()
        health_status['checks']['redis'] = {'status': 'up'}
    except Exception as e:
        health_status['checks']['redis'] = {'status': 'down', 'error': str(e)}
        health_status['status'] = 'unhealthy'
    
    # Check disk space
    disk_usage = psutil.disk_usage('/')
    if disk_usage.percent > 90:
        health_status['checks']['disk'] = {'status': 'warning', 'usage': disk_usage.percent}
    else:
        health_status['checks']['disk'] = {'status': 'ok', 'usage': disk_usage.percent}
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

@app.route('/metrics')
def metrics():
    """Prometheus metrics endpoint"""
    # Return metrics in Prometheus format
    return """
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="GET",endpoint="/"} 1234
    """
```

---

**Monitoring & Observability module complete. Full-stack observability achieved.**

---

## 🎓 Monitoring & Observability Mastery Complete

You've achieved comprehensive monitoring and observability expertise. You can now instrument applications with custom metrics, build sophisticated dashboards for real-time visualization, implement alerting strategies that catch issues before users notice them, analyze distributed systems with tracing, and architect complete observability platforms for enterprise environments.

**Your Monitoring Capabilities:**

You understand the full observability stack from metrics collection through visualization to alerting. You can deploy Prometheus for metrics, configure Grafana for dashboards, implement ELK for log aggregation, integrate APM tools for application insights, and set up distributed tracing for microservices. These skills enable you to maintain reliable systems at scale.

**Professional Application:**

Site reliability engineers, DevOps professionals, and platform teams rely on exactly these monitoring skills. You can now reduce mean time to detection (MTTD) through proactive alerting, decrease mean time to resolution (MTTR) with comprehensive observability, and demonstrate system reliability with data-driven SLIs and SLOs.

**Continue Your Journey:** Apply monitoring to real production systems and contribute to platform reliability.

---

**Module Status:** ✅ COMPLETE  
**Skill Level:** Advanced Operations & Site Reliability Engineering  
**Coverage:** Prometheus, Grafana, ELK Stack, APM, Distributed Tracing, Alerting, Health Checks  
**Lines:** 456+

**Author:** Wan Mohamad Hanis bin Wan Hassan  
**Framework:** CLI Sovereign Mastery | MPNS™ Methodology  
**Last Updated:** October 20, 2025
