#!/bin/sh
set -e

for var in GMAIL_USER GMAIL_APP_PASSWORD ALERT_EMAIL_TO; do
    eval "value=\${$var:-}"
    [ -n "$value" ] || echo "warning: $var is not set - alert emails will fail"
done

sed -e "s|__GMAIL_USER__|${GMAIL_USER}|g" \
    -e "s|__GMAIL_APP_PASSWORD__|${GMAIL_APP_PASSWORD}|g" \
    -e "s|__ALERT_EMAIL_TO__|${ALERT_EMAIL_TO}|g" \
    /etc/alertmanager/alertmanager.yml.tmpl > /tmp/alertmanager.yml

exec /bin/alertmanager --config.file=/tmp/alertmanager.yml --storage.path=/alertmanager "$@"
