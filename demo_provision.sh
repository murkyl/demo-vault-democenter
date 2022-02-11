#!/bin/bash
IFS='' read -r -d '' USAGE << EOF
Usage: demo_provision.sh <operation>

Valid operations:
all
	- Perform a full install
install
	- Install packages and plugins
init_ecs
	- Setup ECS
configure_vault_server
	- Configure Vault configuration file
start_vault_server
	- Start Vault server
init_vault_server
	- Initialize Vault storage and store unseal keys and root token
stop_vault_server
	- Stop Vault server
unseal_and_login_vault
	- Unseal Vault and login as root
register_ecs_plugin
	- Register ECS plugin into Vault
register_pscale_plugin
	- Register PowerScale plugin into Vault
EOF

# Define common variables with defaults. You can override these from the shell by setting the environment variables appropriately
vault_ver="${VAULT_VER:=vault-1.7.3}"
vault_cfg_file="/etc/vault.d/vault.hcl"
ecs_endpoint="${ECS_ENDPOINT:=ecs.demo.local}"
ecs_plugin_ver="${ECS_PLUGIN_VER:=0.4.3}"
ecs_plugin_name="vault-plugin-secrets-objectscale"
ecs_vault_endpoint="objectscale"
pscale_endpoint="${PSCALE_ENDPOINT:=192.168.1.21}"
pscale_plugin_ver="${PSCALE_PLUGIN_VER:=0.3.1}"
pscale_plugin_name="vault-plugin-secrets-onefs"
pscale_vault_endpoint="pscale"
# VAULT_ADDR needs to be in the shell's environment and this line will be added to the user's ~/.bash_profile
# The user will have to reload their profile to have it take effect after the script runs. e.g. source ~/.bash_profile
VAULT_ADDR="http://127.0.0.1:8200"

# Define ECS variables
ecs_username="root"
ecs_password="Password123!"
ecs_role_name="admins"
ecs_role_policy_file="role_iam-user1.json"
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
	yum install -y yum-utils awscli
	yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
	yum install -y ${vault_ver}
	mkdir /opt/vault/plugins
	wget -N -P /opt/vault/plugins https://github.com/murkyl/${ecs_plugin_name}/releases/download/v${ecs_plugin_ver}/${ecs_plugin_name}-linux-amd64-${ecs_plugin_ver}
	wget -N -P /opt/vault/plugins https://github.com/murkyl/${pscale_plugin_name}/releases/download/v${pscale_plugin_ver}/${pscale_plugin_name}-linux-amd64-${pscale_plugin_ver}
	wget -N https://raw.githubusercontent.com/murkyl/demo-vault-democenter/main/role_iam-user1.json
	chmod 755 /opt/vault/plugins/*
	chown -R vault:vault /opt/vault/plugins
	echo "Packages installed"
}

function install_env() {
	grep -q VAULT_ADDR ~/.bash_profile
	if [ $? -eq 1 ]; then
		echo "VAULT_ADDR=${VAULT_ADDR}" >> ~/.bash_profile
		echo "export VAULT_ADDR" >> ~/.bash_profile
	fi
	echo "VAULT_ADDR environment variable written to ~/.bash_profile. You must manually source this file to activate the variable. Please run the following command:"
	echo "    source ~/.bash_profile"
}

function login_ecs() {
	# Extract Management Session Token for future commands
	export ecs_token=$(curl -k https://${ecs_endpoint}:4443/login -u ${ecs_username}:${ecs_password} -Is | grep 'X-SDS-AUTH-TOKEN' | cut -d " " -f 2)
	echo "Logged into ECS as ${ecs_username}"
}

function logout_ecs() {
	# Log out of Management API
	echo "Logging out from ECS"
	curl -ks https://${ecs_endpoint}:4443/logout -H "X-SDS-AUTH-TOKEN: ${ecs_token}" > /dev/null
	unset ecs_token
}

function create_ecs_users_and_policies() {
	# Create general IAM User with no permissions
	echo "Creating new IAM users with no permission"
	rm -f ~/log_iam_user_create.txt
	for iamUser in "${iam_users[@]}"; do
		curl -ks -X POST "https://${ecs_endpoint}:4443/iam?UserName=$iamUser&Action=CreateUser" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" >> ~/log_iam_user_create.txt
		echo -e "\n" >> ~/log_iam_user_create.txt
		echo "User created: ${iamUser}"
	done
	echo "Created Users"

	# Give users permission via IAM policies
	echo "Adding permissions to IAM users"
	rm -f ~/log_iam_add_permission.txt
	for index in ${!iam_users[*]}; do
		curl -ks -X POST "https://${ecs_endpoint}:4443/iam?UserName=${iam_users[$index]}&PolicyArn=${iam_policies[$index]}&Action=AttachUserPolicy" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" >> ~/log_iam_add_permission.txt
		echo -e "\n" >> ~/log_iam_add_permission.txt
		echo "Permission added: ${index}"
	done
	echo "Permissions added"

	# Create Access Key for Users
	echo "Creating Admin User Access Key and Secret Keys"
	for iamUser in "${iam_users[@]:0:2}"; do
		curl -ks -X POST "https://${ecs_endpoint}:4443/iam?UserName=$iamUser&Action=CreateAccessKey" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" > ~/creds_${iamUser}.txt
		sed -E -i "s/.*AccessKeyId>(.*)<\/Access.*SecretAccessKey>(.*)<\/Secret.*/\1 \2/" ~/creds_${iamUser}.txt
		echo "Key created: ${iamUser}"
	done
	echo "User keys created"

	# Create Roles RoleDocument is URL encoded
	echo "Creating an IAM Role for IAM-User1"
	rm -f ~/log_create_role.txt
	curl -ks --data-urlencode "AssumeRolePolicyDocument@${ecs_role_policy_file}" --data "RoleName=${ecs_role_name}" --data "Action=CreateRole" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" "https://${ecs_endpoint}:4443/iam?" >> ~/log_create_role.txt
	echo -e "\n" >> ~/log_create_role.txt
	curl -ks -X POST "https://${ecs_endpoint}:4443/iam?PolicyArn=${iam_policies[@]:0:2}&RoleName=${ecs_role_name}&Action=AttachRolePolicy" -H "X-SDS-AUTH-TOKEN: ${ecs_token}" >> ~/log_create_role.txt
	echo "Role created"
}

function configure_vault_server() {
	# Configure Vault server
	echo "Configuring Vault server"
	grep -q api_addr /etc/vault.d/vault.hcl
	if [ $? -eq 1 ]; then
		echo "api_addr = \"http://127.0.0.1:8200\"" >> ${vault_cfg_file}
	else
		echo "api_addr already set in ${vault_cfg_file} file"
	fi
	grep -q plugin_directory /etc/vault.d/vault.hcl
	if [ $? -eq 1 ]; then
		echo "plugin_directory = \"/opt/vault/plugins\"" >> ${vault_cfg_file}
	else
		echo "plugin_directory already set in ${vault_cfg_file} file"
	fi
	grep -q tls_disable /etc/vault.d/vault.hcl
	if [ $? -eq 1 ]; then
		sed -E -i "/tls_key_file.*/a\\  tls_disable = 1" ${vault_cfg_file}
	else
		echo "tls_disable already set in ${vault_cfg_file} file"
	fi
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
		echo "Vault is already initialized. To reset Vault run 'rm -rf /opt/vault/data/*'"
	else
		vault operator init -key-shares=1 -key-threshold=1 | grep -E "(Unseal Key|Root Token)" > ~/vault.keys
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
	vault secrets enable -path=${ecs_vault_endpoint} ${ecs_vault_endpoint}
	echo "Plugin registered"
}

function register_pscale_plugin() {
	# Register plugin
	echo "Registering PowerScale plugin"
	VAULT_PSCALE_PLUGIN_VERSION=`ls /opt/vault/plugins/${pscale_plugin_name}-linux-* | sort -R | tail -n 1 | sed 's/.*\///'`
	VAULT_PSCALE_PLUGIN_SHA256=`sha256sum /opt/vault/plugins/${VAULT_PSCALE_PLUGIN_VERSION} | cut -d " " -f 1`
	vault plugin register -sha256=${VAULT_PSCALE_PLUGIN_SHA256} -command ${VAULT_PSCALE_PLUGIN_VERSION} secret ${pscale_vault_endpoint}
	vault secrets enable -path=${pscale_vault_endpoint} ${pscale_vault_endpoint}
	echo "Plugin registered"
}

function verify_vault_plugins() {
	unseal_and_login_vault > /dev/null
	echo "Verifying Vault plugin installation"
	echo "You should see objectscale and pscale output following this line:"
	vault plugin list | grep -E "(objectscale|pscale)"
	echo "=========="
	echo "You should see both the objectscale/ and pscale/ paths in the enabled plugin list:"
	vault secrets list
	echo "=========="
}

if [ $# -eq 0 ]; then
	echo "$USAGE"
	exit 1
fi

case $1 in
	all)
		install_packages
		login_ecs
		create_ecs_users_and_policies
		logout_ecs
		configure_vault_server
		start_vault_server
		init_vault_server
		unseal_and_login_vault
		register_ecs_plugin
		register_pscale_plugin
		install_env
		;;
	install)
		install_packages
		;;
	install_env)
		install_env
		;;
	init_ecs)
		login_ecs
		create_ecs_users_and_policies
		logout_ecs
		;;
	configure_vault_server)
		configure_vault_server
		;;
	start_vault_server)
		start_vault_server
		;;
	init_vault_server)
		init_vault_server
		;;
	stop_vault_server)
		stop_vault_server
		;;
	unseal_and_login_vault)
		unseal_and_login_vault
		;;
	register_ecs_plugin)
		register_ecs_plugin
		;;
	register_pscale_plugin)
		register_pscale_plugin
		;;
	verify_vault_plugins)
		verify_vault_plugins
		;;
	*)
		echo "$USAGE"
		;;
esac
