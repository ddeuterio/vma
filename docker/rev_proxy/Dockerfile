FROM nginx:1.29

RUN apt-get update && apt-get install -y cron

RUN mkdir -p /etc/certs

COPY cert.cron /etc/cron.d/cert.cron
RUN chmod 0644 /etc/cron.d/cert.cron

COPY cert.sh /root
RUN /root/cert.sh

COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
