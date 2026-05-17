# Vagrant ESXi Lab

## Purpose

This optional path runs the lab on a real x86_64 Ubuntu VM instead of a non-native Docker runtime. Use it when validating ASLR, heap layout, coredump behavior, or other process-layout details that may differ in emulated containers.

## Provider

The repo `Vagrantfile` targets `vagrant-vmware-esxi`:

```bash
vagrant up --provider=vmware_esxi
```

Site-specific values are environment-driven and should not be committed:

```bash
export ESXI_HOST='<hypervisor-host>'
export ESXI_USERNAME='<username>'
export ESXI_NETWORK='<port-group>'
export ESXI_DATASTORE='<datastore>'
export ESXI_RESOURCE_POOL='<resource-pool>'
```

If the provider needs an `ovftool` password, provide it through `ESXI_PASSWORD_SPEC`:

```bash
export ESXI_PASSWORD_SPEC='env:ESXI_PASSWORD'
export ESXI_PASSWORD='...'
```

## Lab Service

Provisioning installs the vulnerable nginx build and a same-port PHP-FPM local-file-read/phpinfo setup:

- vulnerable target: `http://<target-host>:19321/api/...`
- spray route: `http://<target-host>:19321/spray`
- LFI route: `http://<target-host>:19321/lfi.php?file=...`
- phpinfo route: `http://<target-host>:19321/phpinfo.php`

The VM track may configure local coredumps for the core-guided research path:

```text
kernel.core_pattern=core
kernel.core_uses_pid=0
fs.suid_dumpable=2
apport/systemd-coredump disabled or bypassed for this service
/app/tmp readable by the nginx/PHP worker UID
```

That coredump policy is a lab amplifier, not a default production assumption. The assessor should report this as a target property instead of assuming it.

## Usage

Find the VM IP with:

```bash
vagrant ssh -c "hostname -I"
```

Then assess:

```bash
./nginx_rifter.py --target <target-host>:19321
```

Run the integrated exploit path only when the target is authorized and the assessment shows the required primitives:

```bash
./nginx_rifter.py --target <target-host>:19321 --exploit --cmd id
```
