# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vaprobash: http://fideloper.github.io/Vaprobash/install-scripts.html#php

# Config Github Settings
github_username = "fideloper"
github_repo     = "Vaprobash"
github_branch   = "1.4.1"
github_url      = "https://raw.githubusercontent.com/#{github_username}/#{github_repo}/#{github_branch}"

# Because this:https://developer.github.com/changes/2014-12-08-removing-authorizations-token/
# https://github.com/settings/tokens
github_pat          = ""

# Server Configuration

hostname        = "vaprobash.dev"

# Set a local private network IP address.
# See http://en.wikipedia.org/wiki/Private_network for explanation
# You can use the following IP ranges:
#   10.0.0.1    - 10.255.255.254
#   172.16.0.1  - 172.31.255.254
#   192.168.0.1 - 192.168.255.254
server_ip             = "10.0.0.200"
server_cpus           = "1"   # Cores
server_memory         = "384" # MB
server_swap           = "768" # Options: false | int (MB) - Guideline: Between one or two times the server_memory

# UTC        for Universal Coordinated Time
# EST        for Eastern Standard Time
# US/Central for American Central
# US/Eastern for American Eastern
server_timezone  = "UTC"

# Database Configuration
mysql_root_password   = "root"   # We'll assume user "root"
mysql_version         = "5.5"    # Options: 5.5 | 5.6
mysql_enable_remote   = "false"  # remote access enabled when true
pgsql_root_password   = "root"   # We'll assume user "root"
mongo_version         = "2.6"    # Options: 2.6 | 3.0
mongo_enable_remote   = "false"  # remote access enabled when true

# Languages and Packages
php_timezone          = "UTC"    # http://php.net/manual/en/timezones.php
php_version           = "5.6"    # Options: 5.5 | 5.6
ruby_version          = "latest" # Choose what ruby version should be installed (will also be the default version)
ruby_gems             = [        # List any Ruby Gems that you want to install
  #"jekyll",
  #"sass",
  #"compass",
]

go_version            = "latest" # Example: go1.4 (latest equals the latest stable version)

# To install HHVM instead of PHP, set this to "true"
hhvm                  = "false"

# PHP Options
composer_packages     = [        # List any global Composer packages that you want to install
  #"phpunit/phpunit:4.0.*",
  #"codeception/codeception=*",
  #"phpspec/phpspec:2.0.*@dev",
  #"squizlabs/php_codesniffer:1.5.*",
]

# Default web server document root
# Symfony's public directory is assumed "web"
# Laravel's public directory is assumed "public"
public_folder         = "/vagrant/public"

laravel_root_folder   = "/vagrant/laravel" # Where to install Laravel. Will `composer install` if a composer.json file exists
laravel_version       = "latest-stable" # If you need a specific version of Laravel, set it here
symfony_root_folder   = "/vagrant/symfony" # Where to install Symfony.

nodejs_version        = "latest"   # By default "latest" will equal the latest stable version
nodejs_packages       = [          # List any global NodeJS packages that you want to install
  #"grunt-cli",
  #"gulp",
  #"bower",
  #"yo",
]

# RabbitMQ settings
rabbitmq_user = "user"
rabbitmq_password = "password"

sphinxsearch_version  = "rel22" # rel20, rel21, rel22, beta, daily, stable


Vagrant.configure("2") do |config|

  # Set server to Ubuntu 14.04
  config.vm.box = "ubuntu/trusty64"

  config.vm.define "Vaprobash" do |vapro|
  end

  if Vagrant.has_plugin?("vagrant-hostmanager")
    config.hostmanager.enabled = true
    config.hostmanager.manage_host = true
    config.hostmanager.ignore_private_ip = false
    config.hostmanager.include_offline = false
  end

  # Create a hostname, don't forget to put it to the `hosts` file
  # This will point to the server's default virtual host
  # TO DO: Make this work with virtualhost along-side xip.io URL
  config.vm.hostname = hostname

  # Create a static IP
  # config.vm.network :private_network, ip: server_ip
  config.vm.network :public_network, ip: server_ip

  config.vm.network :forwarded_port, guest: 80, host: 8000

  # Enable agent forwarding over SSH connections
  config.ssh.forward_agent = true

  # Use NFS for the shared folder
  config.vm.synced_folder ".", "/vagrant",
            id: "core",
            :nfs => true,
            :mount_options => ['nolock,vers=3,udp,noatime,actimeo=2']

  # Replicate local .gitconfig file if it exists
  if File.file?(File.expand_path("~/.gitconfig"))
    config.vm.provision "file", source: "~/.gitconfig", destination: ".gitconfig"
  end

  # If using VMWare Fusion
  config.vm.provider "vmware_fusion" do |vb, override|
    override.vm.box_url = "http://files.vagrantup.com/precise64_vmware.box"

    # Set server memory
    vb.vmx["memsize"] = server_memory

  end

  # If using Vagrant-Cachier
  # http://fgrehm.viewdocs.io/vagrant-cachier
  if Vagrant.has_plugin?("vagrant-cachier")
    # Configure cached packages to be shared between instances of the same base box.
    # Usage docs: http://fgrehm.viewdocs.io/vagrant-cachier/usage
    config.cache.scope = :box

    config.cache.synced_folder_opts = {
        type: :nfs,
        mount_options: ['rw', 'vers=3', 'tcp', 'nolock']
    }
  end

  ####
  # Base Items
  ##########

  # Provision Base Packages
  config.vm.provision "shell", path: "#{github_url}/scripts/base.sh", args: [github_url, server_swap, server_timezone]

  # optimize base box
  # config.vm.provision "shell", path: "#{github_url}/scripts/base_box_optimizations.sh", privileged: true

  # Provision PHP
  config.vm.provision "shell", path: "#{github_url}/scripts/php.sh", args: [php_timezone, hhvm, php_version]

  # Enable MSSQL for PHP
  # config.vm.provision "shell", path: "#{github_url}/scripts/mssql.sh"

  # Provision Vim
  config.vm.provision "shell", path: "#{github_url}/scripts/vim.sh", args: github_url

  # Provision Docker
  # config.vm.provision "shell", path: "#{github_url}/scripts/docker.sh", args: "permissions"

  ####
  # Web Servers
  ##########

  # Provision Apache Base
  # config.vm.provision "shell", path: "#{github_url}/scripts/apache.sh", args: [server_ip, public_folder, hostname, github_url]

  # Provision Nginx Base
  config.vm.provision "shell", path: "#{github_url}/scripts/nginx.sh", args: [server_ip, public_folder, hostname, github_url]


  ####
  # Databases
  ##########

  # Provision MySQL
  # config.vm.provision "shell", path: "#{github_url}/scripts/mysql.sh", args: [mysql_root_password, mysql_version, mysql_enable_remote]

  # Provision PostgreSQL
  # config.vm.provision "shell", path: "#{github_url}/scripts/pgsql.sh", args: pgsql_root_password

  # Provision SQLite
  # config.vm.provision "shell", path: "#{github_url}/scripts/sqlite.sh"

  # Provision RethinkDB
  # config.vm.provision "shell", path: "#{github_url}/scripts/rethinkdb.sh", args: pgsql_root_password

  # Provision Couchbase
  # config.vm.provision "shell", path: "#{github_url}/scripts/couchbase.sh"

  # Provision CouchDB
  # config.vm.provision "shell", path: "#{github_url}/scripts/couchdb.sh"

  # Provision MongoDB
  # config.vm.provision "shell", path: "#{github_url}/scripts/mongodb.sh", args: [mongo_enable_remote, mongo_version]

  # Provision MariaDB
  # config.vm.provision "shell", path: "#{github_url}/scripts/mariadb.sh", args: [mysql_root_password, mysql_enable_remote]

  # Provision Neo4J
  # config.vm.provision "shell", path: "#{github_url}/scripts/neo4j.sh"

  ####
  # Search Servers
  ##########

  # Install Elasticsearch
  # config.vm.provision "shell", path: "#{github_url}/scripts/elasticsearch.sh"

  # Install SphinxSearch
  # config.vm.provision "shell", path: "#{github_url}/scripts/sphinxsearch.sh", args: [sphinxsearch_version]

  ####
  # Search Server Administration (web-based)
  ##########

  # Install ElasticHQ
  # Admin for: Elasticsearch
  # Works on: Apache2, Nginx
  # config.vm.provision "shell", path: "#{github_url}/scripts/elastichq.sh"


  ####
  # In-Memory Stores
  ##########

  # Install Memcached
  # config.vm.provision "shell", path: "#{github_url}/scripts/memcached.sh"

  # Provision Redis (without journaling and persistence)
  # config.vm.provision "shell", path: "#{github_url}/scripts/redis.sh"

  # Provision Redis (with journaling and persistence)
  # config.vm.provision "shell", path: "#{github_url}/scripts/redis.sh", args: "persistent"
  # NOTE: It is safe to run this to add persistence even if originally provisioned without persistence


  ####
  # Utility (queue)
  ##########

  # Install Beanstalkd
  # config.vm.provision "shell", path: "#{github_url}/scripts/beanstalkd.sh"

  # Install Heroku Toolbelt
  # config.vm.provision "shell", path: "https://toolbelt.heroku.com/install-ubuntu.sh"

  # Install Supervisord
  # config.vm.provision "shell", path: "#{github_url}/scripts/supervisord.sh"

  # Install Kibana
  # config.vm.provision "shell", path: "#{github_url}/scripts/kibana.sh"

  # Install ØMQ
  # config.vm.provision "shell", path: "#{github_url}/scripts/zeromq.sh"

  # Install RabbitMQ
  # config.vm.provision "shell", path: "#{github_url}/scripts/rabbitmq.sh", args: [rabbitmq_user, rabbitmq_password]

  ####
  # Additional Languages
  ##########

  # Install Nodejs
  # config.vm.provision "shell", path: "#{github_url}/scripts/nodejs.sh", privileged: false, args: nodejs_packages.unshift(nodejs_version, github_url)

  # Install Ruby Version Manager (RVM)
  # config.vm.provision "shell", path: "#{github_url}/scripts/rvm.sh", privileged: false, args: ruby_gems.unshift(ruby_version)

  # Install Go Version Manager (GVM)
  # config.vm.provision "shell", path: "#{github_url}/scripts/go.sh", privileged: false, args: [go_version]

  ####
  # Frameworks and Tooling
  ##########

  # Provision Composer
  # You may pass a github auth token as the first argument
  # config.vm.provision "shell", path: "#{github_url}/scripts/composer.sh", privileged: false, args: [github_pat, composer_packages.join(" ")]

  # Provision Laravel
  # config.vm.provision "shell", path: "#{github_url}/scripts/laravel.sh", privileged: false, args: [server_ip, laravel_root_folder, public_folder, laravel_version]

  # Provision Symfony
  # config.vm.provision "shell", path: "#{github_url}/scripts/symfony.sh", privileged: false, args: [server_ip, symfony_root_folder, public_folder]

  # Install Screen
  # config.vm.provision "shell", path: "#{github_url}/scripts/screen.sh"

  # Install Mailcatcher
  # config.vm.provision "shell", path: "#{github_url}/scripts/mailcatcher.sh"

  # Install git-ftp
  # config.vm.provision "shell", path: "#{github_url}/scripts/git-ftp.sh", privileged: false

  # Install Ansible
  # config.vm.provision "shell", path: "#{github_url}/scripts/ansible.sh"

  # Install Android
  # config.vm.provision "shell", path: "#{github_url}/scripts/android.sh"

  ####
  # Local Scripts
  # Any local scripts you may want to run post-provisioning.
  # Add these to the same directory as the Vagrantfile.
  ##########
  # config.vm.provision "shell", path: "./local-script.sh"

end
