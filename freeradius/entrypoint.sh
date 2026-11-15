#!/bin/bash
set -euo pipefail

: "${DB_HOST:=127.0.0.1}"
: "${DB_PORT:=3306}"
: "${DB_NAME:=radius}"
: "${DB_USER:=radius}"
: "${DB_PASSWORD:?DB_PASSWORD required}"
: "${RADIUS_SECRET:?RADIUS_SECRET required}"

export DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD RADIUS_SECRET

envsubst '${DB_HOST} ${DB_PORT} ${DB_NAME} ${DB_USER} ${DB_PASSWORD}' \
  < /etc/raddb/templates/sql.tmpl \
  > /etc/raddb/mods-available/sql

envsubst '${RADIUS_SECRET}' \
  < /etc/raddb/templates/clients.conf.tmpl \
  > /etc/raddb/clients.conf

ln -sf ../mods-available/sql /etc/raddb/mods-enabled/sql
ln -sf ../mods-available/pap /etc/raddb/mods-enabled/pap
ln -sf ../mods-available/preprocess /etc/raddb/mods-enabled/preprocess
ln -sf ../mods-available/acct_unique /etc/raddb/mods-enabled/acct_unique

rm -f /etc/raddb/mods-enabled/eap

chown root:radiusd /etc/raddb/clients.conf /etc/raddb/mods-available/sql
chmod 0640 /etc/raddb/clients.conf /etc/raddb/mods-available/sql

mkdir -p /var/run/radiusd /var/log/radius
chown -R radiusd:radiusd /var/run/radiusd /var/log/radius

exec /usr/sbin/radiusd -f -l stdout