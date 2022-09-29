# Copyright 2022 Snyk Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
FROM golang:latest
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y sudo git squid curl git traceroute net-tools iptables vim make maven libx11-dev xvfb

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

# maven setup
RUN mkdir -p /home/snyk/.m2
RUN cp /app/.github/docker-based-tests/settings.xml /home/snyk/.m2/settings.xml
RUN chmod 777 /home/snyk/.m2/settings.xml && chown -R snyk /home/snyk/.m2

ENV http_proxy="http://localhost:3128"
ENV https_proxy="http://localhost:3128"
ENV no_proxy "localhost,127.0.0.1"
ENV INTEG_TESTS=true
ENV SMOKE_TESTS=true

RUN env
USER snyk
WORKDIR /app
ENTRYPOINT ["/bin/entrypoint.sh"]
