#!/bin/bash

# Define common variables
vault_ver="${VAULT_VER:=vault-1.7.3}"
ecs_plugin_ver="${ECS_PLUGIN_VER:=0.4.3}"
ecs_plugin_name="vault-plugin-secrets-objectscale"
ecs_vault_endpoint="objectscale"
pscale_plugin_ver="${PSCALE_PLUGIN_VER:=0.3.1}"
pscale_plugin_name="vault-plugin-secrets-onefs"
pscale_vault_endpoint="pscale"
export VAULT_ADDR="http://127.0.0.1:8200"

# Define ECS variables
ecs_username="root"
ecs_password="Password123!"
ecs_role_name="admins"
#ecs_token is exported to the environment holding the current authentication token

# Define PowerScale variables
pscale_username="root"
pscale_password="Password123!"

# Defining IAM Users
iam_users=("plugin-admin" "iam-admin1" "iam-user1")

# Defining IAM Policies
iam_policies=("urn:ecs:iam:::policy/IAMFullAccess" "urn:ecs:iam:::policy/ECSS3FullAccess" "urn:ecs:iam:::policy/ECSS3ReadOnlyAccess")

function install_packages() {
	# Install extra packages
	echo "Installing additional required packages"
	yum install -y yum-utils aws-cli
	yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
	yum install -y ${vault_ver}
	mkdir /opt/vault/plugins
	wget -P /opt/vault/plugins https://github.com/murkyl/${ecs_plugin_name}/releases/download/v${ecs_plugin_ver}/${ecs_plugin_name}-linux-amd64-${ecs_plugin_ver}
	wget -P /opt/vault/plugins https://github.com/murkyl/${pscale_plugin_name}/releases/download/v${pscale_plugin_ver}/${pscale_plugin_name}-linux-amd64-${pscale_plugin_ver}
	chmod 755 /opt/vault/plugins/*
	chown -R vault:vault /opt/vault/plugins
	echo "Packages installed"
}

function login_ecs() {
	# Extract Management Session Token for future commands
	export ecs_token=$(curl -k https://ecs.demo.local:4443/login -u ${ecs_username}:${ecs_password} -Is | grep 'X-SDS-AUTH-TOKEN' | cut -d " " -f 2)
	echo "Logged into ECS as ${ecs_username}"
}

function logout_ecs() {
	# Log out of Management API
	echo "Logging out from ECS"
	curl -ks https://ecs.demo.local:4443/logout -H "X-SDS-AUTH-TOKEN: ${ecs_token}"
	unset ecs_token
}

function create_ecs_users_and_policies() {
	# Create general IAM User with no permissions
	echo "Creating new IAM users with no permission"
	for iamUser in "${iam_users[@]}"; do
			curl -ks -X POST "https://ecs.demo.local:4443/iam?UserName=$iamUser&Action=CreateUser" -H "X-SDS-AUTH-TOKEN: ${ecs_token}"
	done
	echo "Created Users"

	# Give users permission via IAM policies
	echo "Adding permissions to IAM users"
	for index in ${!iam_users[*]}; do
			curl -ks -X POST "https://ecs.demo.local:4443/iam?UserName=${iam_users[$index]}&PolicyArn=${iam_policies[$index]}&Action=AttachUserPolicy" -H "X-SDS-AUTH-TOKEN: ${ecs_token}"
	done
	echo "Permissions added"

	# Create Access Key for Admin Users
	# xmlstarlet package will need to be installed on client machine from CentOS EPEL repository
	echo " Creating Admin Users Access/Secret Keys"
	for iamUser in "${iam_users[@]:0:2}"; do
			#curl -ks -X POST "https://ecs.demo.local:4443/iam?UserName=$iamUser&Action=CreateAccessKey" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" | xmlstarlet sel -t -c "ns2:CreateAccessKeyResponse/CreateAccessKeyResult/AccessKey" >> cred.xml
			curl -ks -X POST "https://ecs.demo.local:4443/iam?UserName=$iamUser&Action=CreateAccessKey" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" >> ~/ecs_cred.txt
	done
	echo "Admins have keys"

	# Create Roles RoleDocument is URL encoded
	echo "Creating an IAM Role for IAM-User1"
	curl -ks --data-urlencode "AssumeRolePolicyDocument@rolepolicy.json" --data "RoleName=${ecs_role_name}" --data "Action=CreateRole" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" https://ecs.demo.local:4443/iam?
	curl -ks -X POST "https://ecs.demo.local:4443/iam?PolicyArn=${iam_policies[@]:0:2}&RoleName=${ecs_role_name}&Action=AttachRolePolicy" -H "X-SDS-AUTH-TOKEN: ${ecs_token}"
	echo "Role created"
}

function configure_vault_server() {
	# Configure Vault server
	echo "Configuring Vault server"
	echo "api_addr = \"http://127.0.0.1:8200\"" >> /etc/vault.d/vault.hcl
	echo "plugin_directory = \"/opt/vault/plugins\"" >> /etc/vault.d/vault.hcl
	sed -Eie "/tls_key_file.*/a\\  tls_disable = 1" /etc/vault.d/vault.hcl
	echo "Vault server configured"
}

function start_vault_server() {
	# Start Vault server
	echo "Starting Vault service"
	systemctl start vault.service
	echo "Vault server started"
}

function stop_vault_server() {
	# Stop Vault server
	echo "Stopping Vault service"
	systemctl stop vault.service
	echo "Vault server stopped"
}

function init_vault_server() {
	if test -f "~/vault.keys"; then
		echo "Vault is already initialized. To reset demo run 'rm -rf /opt/vault/data/*'"
	else
		vault operator init -key-shares=1 -key-threshold=1 > ~/vault.keys
	fi
}

function unseal_and_login_vault() {
	echo "Unsealing Vault and logging in as root"
	vault operator unseal `grep Unseal ~/vault.keys | awk '{ print $4 }'`
	vault login `grep Root ~/vault.keys | awk '{ print $4 }'`
	echo "Vault unsealed and logged in"
}

function register_ecs_plugin() {
  # Register plugin
	echo "Registering ECS plugin"
  VAULT_ECS_PLUGIN_VERSION=`ls /opt/vault/plugins/${ecs_plugin_name}-linux-* | sort -R | tail -n 1 | sed 's/.*\///'`
  VAULT_ECS_PLUGIN_SHA256=`sha256sum /opt/vault/plugins/${VAULT_ECS_PLUGIN_VERSION} | cut -d " " -f 1`
  vault plugin register -sha256=${VAULT_ECS_PLUGIN_SHA256} -command ${VAULT_ECS_PLUGIN_VERSION} secret ${ecs_vault_endpoint}
	echo "Plugin registered"
}

function register_pscale_plugin() {
  # Register plugin
	echo "Registering PowerScale plugin"
  VAULT_PSCALE_PLUGIN_VERSION=`ls /opt/vault/plugins/${pscale_plugin_name}-linux-* | sort -R | tail -n 1 | sed 's/.*\///'`
  VAULT_PSCALE_PLUGIN_SHA256=`sha256sum /opt/vault/plugins/${VAULT_PSCALE_PLUGIN_VERSION} | cut -d " " -f 1`
  vault plugin register -sha256=${VAULT_PSCALE_PLUGIN_SHA256} -command ${VAULT_PSCALE_PLUGIN_VERSION} secret ${pscale_vault_endpoint}
	echo "Plugin registered"
}

install_packages()
login_ecs()
create_ecs_users_and_policies()
configure_vault_server()
start_vault_server()
init_vault_server()
unseal_and_login_vault()
register_ecs_plugin()
register_pscale_plugin()
