# configs are baked into the image so the pipeline can ship them like code
FROM prom/prometheus:v2.55.1
COPY prometheus.yml alert_rules.yml /etc/prometheus/
