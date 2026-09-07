FROM ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends dbus gnome-keyring && rm -rf /var/lib/apt/lists/*
RUN useradd --create-home --uid 10001 cli-fixture
USER 10001
ENTRYPOINT ["dbus-run-session", "--", "/bin/sh", "-ec"]
CMD ["eval \"$(printf '%s' fixture-only | gnome-keyring-daemon --unlock)\"; export GNOME_KEYRING_CONTROL; gnome-keyring-daemon --start --components=secrets >/dev/null; CLI_NATIVE_STORE_REQUIRED=1 /proof/native-store.test -test.v -test.run '^TestNativeSecretService$'"]
