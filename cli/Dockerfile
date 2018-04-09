FROM openjdk:8-jre-slim

MAINTAINER Timo Pagel <dependencycheckmaintainer@timo-pagel.de>

ENV user=dependencycheck

ARG VERSION

RUN apt-get update                                                          && \
    apt-get install -y --no-install-recommends ruby mono-runtime            && \
    gem install bundle-audit                                                && \
    gem cleanup

ADD target/dependency-check-${VERSION}-release.zip /

RUN unzip dependency-check-${VERSION}-release.zip -d /usr/share/            && \
    rm dependency-check-${VERSION}-release.zip                              && \
    useradd -ms /bin/bash ${user}                                           && \
    chown -R ${user}:${user} /usr/share/dependency-check                    && \
    mkdir /report                                                           && \
    chown -R ${user}:${user} /report                                        && \
    rm -rf /var/lib/apt/lists/* /tmp/*
 
USER ${user}

VOLUME ["/src" "/usr/share/dependency-check/data" "/report"]

WORKDIR /src

CMD ["--help"]
ENTRYPOINT ["/usr/share/dependency-check/bin/dependency-check.sh"]
