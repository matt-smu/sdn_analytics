# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "att" do |config|
  
  config.vm.box = "generic/ubuntu1804"
  config.vm.hostname = "att"  

  
  # Run Ansible from the Vagrant Host
  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "playbooks/att.yml"
  end

end

end
