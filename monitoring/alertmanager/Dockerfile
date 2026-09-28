FROM prom/alertmanager:v0.27.0
COPY alertmanager.yml.tmpl /etc/alertmanager/alertmanager.yml.tmpl
COPY --chmod=755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
