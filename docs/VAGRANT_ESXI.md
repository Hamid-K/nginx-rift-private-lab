# Vagrant ESXi Lab

Last updated: 2026-05-15 00:58:38 CEST

## Purpose

Use the `Ultra` ESXi host to run a real x86_64 Ubuntu VM for the Nginx Rift lab. This keeps the target architecture aligned with the published PoC while avoiding Docker Desktop amd64 emulation artifacts on the local arm64 Mac.

## Provider

The repo `Vagrantfile` targets `vagrant-vmware-esxi` by default when run with:

```bash
vagrant up --provider=vmware_esxi
```

Default non-secret settings:

```text
ESXI_HOST=ultra.home
ESXI_USERNAME=root
ESXI_GUEST_NAME=nginx-rift-lab
ESXI_GUEST_MEMSIZE=4096
ESXI_GUEST_VCPUS=4
ESXI_GUEST_DISK_GB=40
```

Secrets and site-specific settings are environment-driven and must not be committed:

```bash
export ESXI_NETWORK='VM Network'
export ESXI_DATASTORE='datastore1'
export ESXI_RESOURCE_POOL='/Vagrant'
```

The default is `ESXI_PASSWORD_SPEC=key:` because `root@ultra.home` accepts SSH key authentication in this lab. That key path is for provider SSH operations only. `ovftool` upload/import operations can still require ESXi password authentication, so use a password source only for that path:

```bash
export ESXI_PASSWORD_SPEC='env:ESXI_PASSWORD'
export ESXI_PASSWORD='...'
```

In this branch, the working launch used a hidden macOS prompt to populate `ESXI_PASSWORD` for `ovftool` while leaving SSH to `Ultra` key-based. Do not commit the password or any generated password file.

Current target launch status:

- `ssh root@ultra.home` works with key authentication.
- `vagrant validate` succeeds.
- `vagrant up --provider=vmware_esxi` successfully created VMID `24`.
- Guest IP observed through ESXi/VMware Tools: `192.168.1.205`.
- The provider still hit a guest communication issue after the VM booted, so provisioning was completed through direct Vagrant-key SSH and manual rsync to `/vagrant`.

Conclusion: to launch through this Vagrant ESXi provider, provide an ESXi password via `ESXI_PASSWORD_SPEC=env:ESXI_PASSWORD`, `ESXI_PASSWORD_SPEC=file:/path/to/password-file`, or `ESXI_PASSWORD_SPEC=prompt:` in an interactive terminal. Treat that as an `ovftool` credential, not a replacement for SSH key auth.

For an interactive terminal run, use:

```bash
export ESXI_PASSWORD_SPEC='prompt:'
```

## Lab Service

Provisioning installs the same vulnerable nginx build and same-port PHP LFI/phpinfo setup used by the Docker CTF lab:

- vulnerable target: `http://<vm-ip>:19321/api/...`
- spray route: `http://<vm-ip>:19321/spray`
- LFI route: `http://<vm-ip>:19321/lfi.php?file=...`
- phpinfo route: `http://<vm-ip>:19321/phpinfo.php`

The nginx service runs under systemd with `LimitCORE=infinity`; nginx workers still drop to `nobody:nogroup`.

The Vagrant provisioner also configures the VM core-dump behavior for the core-guided lab path:

```text
kernel.core_pattern=core
kernel.core_uses_pid=0
fs.suid_dumpable=2
apport disabled
/app/tmp owned by nobody:nogroup
```

## Finding The VM IP

The ESXi provider uses the VM network rather than localhost port forwarding. After `vagrant up`, use either Vagrant or ESXi/VMware Tools:

```bash
vagrant ssh -c "hostname -I"
```

Then run the remote driver against that IP:

```bash
./ctf_remote_exploit.py --host <vm-ip> --port 19321 --core-guided --tries-per-candidate 3 --verbose
```

## Status

Running. The current VM target is `192.168.1.205:19321`.

A separate debug/twin VM is also running at `192.168.1.89:19321`. It is provisioned from the same repo and may be modified for live debugging, gdb tracing, and layout experiments. Do not use addresses or object locations learned from the debug/twin as target-specific exploit inputs for the CTF target.

Latest smoke test:

```text
HTTP /: ok
PHP-FPM UID/GID via LFI: 65534/65534
randomize_va_space via LFI: 2
core_pattern via LFI: core
guest architecture: x86_64
```

Latest core-guided result: the driver recovered 20 sprayed fake-structure addresses from an LFI-readable core, but all 20 were URI-unsafe in the current ASLR layout, so no marker proof was achieved.

Latest ASLR sampling result: 12 fresh nginx master layouts produced `0 / 12` cases with any URI-safe legacy cleanup candidate.

Latest debug/twin result: reducing `connection_pool_size` and adding a short literal prefix can create a stable 69-byte partial-overwrite near miss, but crossing that remaining gap changes nginx allocation geometry.
