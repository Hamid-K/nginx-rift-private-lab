Vagrant.configure("2") do |config|
  config.vm.box = ENV.fetch("VAGRANT_BOX", "generic/ubuntu2204")
  config.vm.hostname = "nginx-rift-lab"

  config.vm.synced_folder ".", "/vagrant", type: "rsync",
    rsync__exclude: [".git/", ".vagrant/", "__pycache__/"]

  config.vm.provider "virtualbox" do |vb|
    vb.name = "nginx-rift-lab"
    vb.memory = 2048
    vb.cpus = 2
  end

  config.vm.provider :vmware_esxi do |esxi|
    esxi.esxi_hostname = ENV.fetch("ESXI_HOST", "esxi.example.local")
    esxi.esxi_username = ENV.fetch("ESXI_USERNAME", "root")
    esxi.esxi_password = ENV.fetch("ESXI_PASSWORD_SPEC", "key:")

    esxi.esxi_virtual_network = ENV["ESXI_NETWORK"] if ENV["ESXI_NETWORK"]
    esxi.esxi_disk_store = ENV["ESXI_DATASTORE"] if ENV["ESXI_DATASTORE"]
    esxi.esxi_resource_pool = ENV["ESXI_RESOURCE_POOL"] if ENV["ESXI_RESOURCE_POOL"]

    esxi.guest_name = ENV.fetch("ESXI_GUEST_NAME", "nginx-rift-lab")
    esxi.guest_username = ENV.fetch("ESXI_GUEST_USERNAME", "vagrant")
    esxi.guest_memsize = ENV.fetch("ESXI_GUEST_MEMSIZE", "4096")
    esxi.guest_numvcpus = ENV.fetch("ESXI_GUEST_VCPUS", "4")
    esxi.guest_boot_disk_size = ENV.fetch("ESXI_GUEST_DISK_GB", "40")
    esxi.guest_disk_type = ENV.fetch("ESXI_GUEST_DISK_TYPE", "thin")
    esxi.local_allow_overwrite = ENV.fetch("ESXI_ALLOW_OVERWRITE", "False")
  end

  config.vm.provision "shell", privileged: true, path: "vagrant/provision.sh"
end
