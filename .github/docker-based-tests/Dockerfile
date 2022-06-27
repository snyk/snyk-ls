FROM ubuntu:latest
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y sudo git squid curl golang git traceroute net-tools iptables vim make
RUN apt-get auto-remove -y && apt-get clean -y && rm -rf /var/lib/apt/
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy

RUN useradd snyk --create-home
RUN echo "snyk ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

RUN mkdir -p /app
COPY . /app
RUN rm -rf /app/build /app/.bin
RUN cp /app/.github/docker-based-tests/entrypoint.sh /bin
RUN chmod +x /bin/entrypoint.sh
RUN chmod 777 /app && chown -R snyk /app

ENV http_proxy="http://localhost:3128"
ENV https_proxy="http://localhost:3128"
ENV no_proxy "localhost,127.0.0.1"
ENV INTEG_TESTS=true

RUN env
USER snyk
WORKDIR /app
ENTRYPOINT ["/bin/entrypoint.sh"]
