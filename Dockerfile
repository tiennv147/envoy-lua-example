FROM envoyproxy/envoy:latest
RUN apt-get update && apt-get install -y curl
ADD ./lib /lib
COPY envoy.yaml /etc/envoy/envoy.yaml