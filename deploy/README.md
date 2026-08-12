# Deploying the split

Two users, so the daemon cannot read the signer's memory.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin purser-signer
sudo useradd --system --no-create-home --shell /usr/sbin/nologin purser
sudo usermod -aG purser purser-signer      # the daemon's group owns the socket
sudo install -m 0644 deploy/purser-signer.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## Getting the key in

Never as a flag and never as an environment variable. Use a systemd encrypted credential, which is
sealed to this machine and decrypted only into the unit's private credential directory:

```bash
sudo mkdir -p /etc/purser
sudo systemd-ask-password --no-tty | sudo systemd-creds encrypt --name=key - /etc/purser/key.cred
sudo chmod 0600 /etc/purser/key.cred
```

The shipped unit already carries the matching pair of directives:

```ini
LoadCredentialEncrypted=key:/etc/purser/key.cred
StandardInput=file:/run/credentials/purser-signer.service/key
```

## Verify the hardening actually applied

```bash
systemd-analyze security purser-signer.service
```

Directives are silently ignored when misspelled, so read the score rather than trusting the file.
The unit as shipped should land in the low ones. Anything above 4.0 means something is not taking
effect.

## Check the isolation is real

```bash
# must fail: different users, so no reading the signer's memory
sudo -u purser cat /proc/"$(pidof purser-signer)"/mem

# must show no usable interfaces: the signer has no network namespace
sudo nsenter -t "$(pidof purser-signer)" -n ip addr
```

## Then run the daemon against it

```bash
purser run --signer-socket /run/purser/signer.sock
```

With `--signer-socket` the daemon never prompts for a key, because it never holds one.
