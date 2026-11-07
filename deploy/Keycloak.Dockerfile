FROM quay.io/keycloak/keycloak:26.5.2@sha256:fb31a59deb46f746f2aaa25adc5da39ceccac4fd22d36a519562b0bf02e8df20
COPY --chown=1000:0 deploy/keycloak-realm.json /opt/keycloak/data/import/devctl-realm.json
