FROM keycloak/keycloak
COPY ./keycloak.conf /opt/keycloak/conf/keycloak.conf
ENV KEYCLOAK_ADMIN=root
ENV KEYCLOAK_ADMIN_PASSWORD=root
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev"]