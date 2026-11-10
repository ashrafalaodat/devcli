FROM quay.io/keycloak/keycloak:26.5.2@sha256:fb31a59deb46f746f2aaa25adc5da39ceccac4fd22d36a519562b0bf02e8df20
USER root
# Give fresh named volumes the service user's ownership before Keycloak starts.
RUN mkdir -p /opt/keycloak/data/h2 && chown 1000:0 /opt/keycloak/data/h2 && chmod 700 /opt/keycloak/data/h2
USER 1000
COPY --chown=1000:0 deploy/keycloak-realm.json /opt/keycloak/data/import/devctl-realm.json
