FROM openjdk:8-jre-slim

MAINTAINER Jeremy Long <jeremy.long@owasp.org>

## For dotnet core installation see
## https://dotnet.microsoft.com/download/linux-package-manager/debian9/sdk-current
## https://stackoverflow.com/a/47545040

ARG VERSION
ENV user=dependencycheck
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1

## ensure everything is up-to-date
RUN apt-get update                                                                                   && \
    apt-get install -y --no-install-recommends ruby wget gpg apt-transport-https ca-certificates     && \
    gem install bundle-audit                                                                         && \
    gem cleanup                                                                                      && \
    rm -rf /var/lib/apt/lists/*

RUN wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg  && \
    mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/                                                     && \
    wget -q https://packages.microsoft.com/config/debian/9/prod.list                                 && \
    mv prod.list /etc/apt/sources.list.d/microsoft-prod.list                                         && \
    chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg                                         && \
    chown root:root /etc/apt/sources.list.d/microsoft-prod.list                                      && \
    apt-get update                                                                                   && \
    apt-get install -y --no-install-recommends dotnet-sdk-2.2                                        && \
    apt-get --purge remove -y wget gpg apt-transport-https                                           && \
    rm -rf /var/lib/apt/lists/*

ADD target/dependency-check-${VERSION}-release.zip /

RUN unzip dependency-check-${VERSION}-release.zip -d /usr/share/                                     && \
    rm dependency-check-${VERSION}-release.zip                                                       && \
    useradd -ms /bin/bash ${user}                                                                    && \
    chown -R ${user}:${user} /usr/share/dependency-check                                             && \
    mkdir /report                                                                                    && \
    chown -R ${user}:${user} /report                                                                 && \
    apt-get autoremove -y                                                                            && \
    rm -rf /var/lib/apt/lists/* /tmp/*
 
USER ${user}

VOLUME ["/src" "/usr/share/dependency-check/data" "/report"]

WORKDIR /src

CMD ["--help"]
ENTRYPOINT ["/usr/share/dependency-check/bin/dependency-check.sh"]
