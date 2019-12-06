FROM azul/zulu-openjdk-alpine:11 AS jlink

RUN $JAVA_HOME/bin/jlink --compress=2 --module-path /opt/java/openjdk/jmods --add-modules java.base,java.compiler,java.datatransfer,jdk.crypto.ec,java.desktop,java.instrument,java.logging,java.management,java.naming,java.rmi,java.scripting,java.security.sasl,java.sql,java.transaction.xa,java.xml,jdk.unsupported --output /jlinked

FROM mcr.microsoft.com/dotnet/core/runtime:2.2-alpine3.9

MAINTAINER Jeremy Long <jeremy.long@owasp.org>

ARG VERSION
ARG POSTGRES_DRIVER_VERSION=42.2.6
ARG MYSQL_DRIVER_VERSION=8.0.17

ENV user=dependencycheck
ENV JAVA_HOME=/opt/jdk
ENV JAVA_OPTS=-Danalyzer.assembly.dotnet.path=/usr/bin/dotnet -Danalyzer.bundle.audit.path=/usr/bin/bundle-audit

COPY --from=jlink /jlinked /opt/jdk/

ADD target/dependency-check-${VERSION}-release.zip /

RUN apk update                                                                                       && \
    apk add --no-cache --virtual .build-deps curl tar                                                && \
    apk add --no-cache ruby ruby-rdoc                                                                && \
    gem install bundle-audit                                                                         && \
    bundle audit update                                                                              && \
    unzip dependency-check-${VERSION}-release.zip -d /usr/share/                                     && \
    rm dependency-check-${VERSION}-release.zip                                                       && \
    cd /usr/share/dependency-check/plugins                                                           && \
    curl -Os "https://jdbc.postgresql.org/download/postgresql-${POSTGRES_DRIVER_VERSION}.jar"        && \
    curl -Ls "https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-${MYSQL_DRIVER_VERSION}.tar.gz" \
        | tar -xz --directory "/usr/share/dependency-check/plugins" --strip-components=1 --no-same-owner \
            "mysql-connector-java-${MYSQL_DRIVER_VERSION}/mysql-connector-java-${MYSQL_DRIVER_VERSION}.jar" && \
    addgroup -S ${user} && adduser -S -G ${user} ${user}                                             && \
    mkdir /usr/share/dependency-check/data                                                           && \
    chown -R ${user}:${user} /usr/share/dependency-check                                             && \
    mkdir /report                                                                                    && \
    chown -R ${user}:${user} /report                                                                 && \
    apk del .build-deps
    
USER ${user}

VOLUME ["/src", "/report"]

WORKDIR /src

CMD ["--help"]
ENTRYPOINT ["/usr/share/dependency-check/bin/dependency-check.sh"]
