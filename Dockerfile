FROM quay.io/cilium/cilium-runtime:f232bafe61ba306e783d83001bc58cd04e73423d@sha256:ff28a34f1853f222716773aac9497b1622c488da985c93e72e72f469f2a007f5
Add ./pwru /usr/bin/pwru
ADD ./xfrm-tracing /usr/bin/xfrm-tracing