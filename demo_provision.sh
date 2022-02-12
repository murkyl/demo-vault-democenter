#!/bin/bash
IFS='' read -r -d '' USAGE << EOF
Usage: demo_provision.sh <operation>

Quickstart:
Execute the script with the 'all' operation to setup both ObjectScale and PowerScale demos
    ./demo_provision.sh all

Valid operations:
all
	- Perform a full install and configuration
install
	- Install packages and plugins
init_ecs
	- Setup ECS
configure_vault
	- Configure Vault configuration file
start_vault
	- Start Vault server
init_vault
	- Initialize Vault storage and store unseal keys and root token
stop_vault
	- Stop Vault server
unseal_and_login_vault
	- Unseal Vault and login as root
register_ecs_plugin
	- Register ECS plugin into Vault
config_ecs_plugin
	- Configure the ObjectScale plugin (endpoint and credentials)
config_ecs_demo
	-	Setup ObjectScale demo endpoints
register_pscale_plugin
	- Register PowerScale plugin into Vault
config_pscale_plugin
	- Configure the PowerScale plugin (endpoint and credentials)
config_pscale_demo
	- Setup PowerScale demo endpoints
verify_vault_plugins
	- Verify if the Vault plugins are installed and enabled
EOF

# Define common variables with defaults. You can override these from the shell by setting the environment variables appropriately
vault_ver="${VAULT_VER:=vault-1.7.3}"
vault_cfg_file="${VAULT_CFG_FILE:=/etc/vault.d/vault.hcl}"
ecs_endpoint="${ECS_ENDPOINT:=https://ecs.demo.local}"
ecs_mgmt_port="${ECS_MGMT_PORT:=4443}"
ecs_plugin_ver="${ECS_PLUGIN_VER:=0.4.3}"
ecs_plugin_name="${ECS_PLUGIN_NAME:=vault-plugin-secrets-objectscale}"
ecs_vault_endpoint="${ECS_VAULT_ENDPOINT:=objectscale}"
pscale_endpoint="${PSCALE_ENDPOINT:=192.168.1.21}"
pscale_plugin_ver="${PSCALE_PLUGIN_VER:=0.3.1}"
pscale_plugin_name="${PSCALE_PLUGIN_NAME:=vault-plugin-secrets-onefs}"
pscale_vault_endpoint="${PSCALE_VAULT_ENDPOINT:=pscale}"
# VAULT_ADDR needs to be in the shell's environment and this line will be added to the user's ~/.bash_profile
# The user will have to reload their profile to have it take effect after the script runs. e.g. source ~/.bash_profile
export VAULT_ADDR="${VAULT_ADDR:=http://127.0.0.1:8200}"

# Define ECS variables
ecs_username="root"
ecs_password="Password123!"
ecs_role_name="admins"
ecs_role_policy_file="role_iam-user1.json"
ecs_dynamic_role_1="readonly_app1"
#ecs_token is exported to the environment holding the current authentication token

# Define PowerScale variables
pscale_username="root"
pscale_password="Password123!"

# Defining IAM Users
# The first user MUST be the account that will be used by the plugin
# The second user is the account that will have their secrets rotated
# The third user is an IAM user that will use STS to assume a role
iam_users=("plugin-admin" "iam-admin1" "iam-user1")

# Defining IAM Policies
# There must be a 1 to 1 match between the iam_users and iam_policies arrays
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
	export ecs_token=$(curl -k ${ecs_endpoint}:${ecs_mgmt_port}/login -u ${ecs_username}:${ecs_password} -Is | grep 'X-SDS-AUTH-TOKEN' | cut -d " " -f 2)
	echo "Logged into ECS as ${ecs_username}"
}

function logout_ecs() {
	# Log out of Management API
	echo "Logging out from ECS"
	curl -ks \
		"${ecs_endpoint}:${ecs_mgmt_port}/logout" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		> /dev/null
	unset ecs_token
}

function create_ecs_users_and_policies() {
	# Create general IAM User with no permissions
	echo "Creating new IAM users with no permission"
	rm -f ~/log_iam_user_create.txt
	for user in "${iam_users[@]}"; do
		curl -ks -X \
			POST \
			"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${user}&Action=CreateUser" \
			-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
			>> ~/log_iam_user_create.txt
		echo -e "\n" >> ~/log_iam_user_create.txt
		echo "User created: ${user}"
	done
	echo "Created Users"

	# Give users permission via IAM policies
	echo "Adding permissions to IAM users"
	rm -f ~/log_iam_add_permission.txt
	for index in ${!iam_users[@]}; do
		curl -ks -X \
			POST \
			"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${iam_users[$index]}&PolicyArn=${iam_policies[$index]}&Action=AttachUserPolicy" \
			-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
			>> ~/log_iam_add_permission.txt
		echo -e "\n" >> ~/log_iam_add_permission.txt
		echo "Permission added: ${iam_users[$index]}"
	done
	echo "Permissions added"

	# Create Access Key for Users
	echo "Creating User access keys and secret keys"
	for user in "${iam_users[@]}"; do
		curl -ks -X \
			POST \
			"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${user}&Action=CreateAccessKey" \
			-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
			> ~/creds_${user}.txt
		sed -E -i "s/.*AccessKeyId>(.*)<\/Access.*SecretAccessKey>(.*)<\/Secret.*/\1 \2/" ~/creds_${user}.txt
		echo "Key created: ${user}"
	done
	echo "User keys created"

	# Create Roles, RoleDocument is URL encoded
	echo "Creating an IAM Role for IAM-User1"
	rm -f ~/log_create_role.txt
	curl -ks \
		--data-urlencode "AssumeRolePolicyDocument@${ecs_role_policy_file}" \
		--data "RoleName=${ecs_role_name}" \
		--data "Action=CreateRole" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		"${ecs_endpoint}:${ecs_mgmt_port}/iam?" \
		>> ~/log_create_role.txt
	echo -e "\n" >> ~/log_create_role.txt
	curl -ks \
		-X POST "${ecs_endpoint}:${ecs_mgmt_port}/iam?PolicyArn=${iam_policies[@]:0:2}&RoleName=${ecs_role_name}&Action=AttachRolePolicy" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		>> ~/log_create_role.txt
	echo "Role created"
}

function configure_vault() {
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
	grep -q -A2 tls_key_file /etc/vault.d/vault.hcl | grep -q tls_disable
	if [ $? -eq 1 ]; then
		sed -E -i "/tls_key_file.*/a\\  tls_disable = 1" ${vault_cfg_file}
	else
		echo "tls_disable already set in ${vault_cfg_file} file"
	fi
	echo "Vault server configured"
}

function start_vault() {
	# Start Vault server
	echo "Starting Vault service"
	systemctl start vault.service
	echo "Vault server started"
}

function stop_vault() {
	# Stop Vault server
	echo "Stopping Vault service"
	systemctl stop vault.service
	echo "Vault server stopped"
}

function init_vault() {
	if [ -s ~/vault.keys ]; then
		echo "Vault is already initialized. To reset Vault run 'rm -rf /opt/vault/data/*; rm -f ~/vault.keys'"
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
	vault plugin register \
		-sha256=${VAULT_ECS_PLUGIN_SHA256} \
		-command ${VAULT_ECS_PLUGIN_VERSION} secret ${ecs_vault_endpoint}
	vault secrets enable -path=${ecs_vault_endpoint} ${ecs_vault_endpoint}
	echo "Plugin registered"
}

function config_ecs_plugin() {
	# Configure ECS plugin
	unseal_and_login_vault > /dev/null
	echo "Configure ECS plugin"
	# The user is actually the access key and the password is the secret generated in the init_ecs function
	vault write ${ecs_vault_endpoint}/config/root \
		user=`cat ~/creds_${iam_users[0]}.txt | awk '{print $1}'` \
		password=`cat ~/creds_${iam_users[0]}.txt | awk '{print $2}'` \
		endpoint=${ecs_endpoint}:${ecs_mgmt_port} \
		bypass_cert_check=true
	vault read ${ecs_vault_endpoint}/config/root
}

function config_ecs_demo() {
	# Configure the demo Vault endpoints
	echo "Configuring ECS demo user endpoints"
	unseal_and_login_vault > /dev/null
	vault write ${ecs_vault_endpoint}/roles/predefined/${iam_users[1]} namespace=ns1
	vault write ${ecs_vault_endpoint}/roles/predefined/${iam_users[2]} namespace=ns1
	vault write ${ecs_vault_endpoint}/roles/dynamic/${ecs_dynamic_role_1} namespace=ns1 policy=IAMReadOnlyAccess
	echo "Demo endpoints configured"
	echo "Usable endpoints"
	echo "    # Rotate access key and secret"
	echo "    ${ecs_vault_endpoint}/creds/predefined/${iam_users[1]}"
	echo "    # IAM Read only access"
	echo "    ${ecs_vault_endpoint}/creds/dynamic/${ecs_dynamic_role_1}"
	echo "    # Assume role: admins"
	echo "    ${ecs_vault_endpoint}/sts/predefined/${iam_users[2]} role_arn=urn:ecs:iam::ns1:role/${ecs_role_name}"
	echo ""
	echo "Example:"
	echo "  vault read ${ecs_vault_endpoint}/creds/predefined/${iam_users[1]}"
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

function config_pscale_plugin() {
	echo ""
}

function config_pscale_demo() {
	echo ""
}

function verify_vault_plugins() {
	unseal_and_login_vault > /dev/null
	echo "Verifying Vault plugin installation"
	echo "You should see ${ecs_vault_endpoint} and pscale_vault_endpoint output following this line:"
	vault plugin list | grep -E "(${ecs_vault_endpoint}|pscale_vault_endpoint)"
	echo "=========="
	echo "You should see both the ${ecs_vault_endpoint}/ and pscale_vault_endpoint/ paths in the enabled plugin list:"
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
		configure_vault
		start_vault
		echo "Sleeping for 2 seconds waiting for Vault to start"
		sleep 2
		init_vault
		unseal_and_login_vault
		register_ecs_plugin
		register_pscale_plugin
		config_ecs_plugin
		config_pscale_plugin
		config_ecs_demo
		config_pscale_demo
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
	configure_vault)
		configure_vault
		;;
	start_vault)
		start_vault
		;;
	init_vault)
		init_vault
		;;
	stop_vault)
		stop_vault
		;;
	unseal_and_login_vault)
		unseal_and_login_vault
		;;
	register_ecs_plugin)
		register_ecs_plugin
		;;
	config_ecs_plugin)
		config_ecs_plugin
		;;
	config_ecs_demo)
		config_ecs_demo
		;;
	register_pscale_plugin)
		register_pscale_plugin
		;;
	config_pscale_plugin)
		config_pscale_plugin
		;;
	config_pscale_demo)
		config_pscale_demo
		;;
	verify_vault_plugins)
		verify_vault_plugins
		;;
	*)
		echo "$USAGE"
		;;
esac
