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
	- Setup ECS by creating users and policies. Clears existing keys if they exist.
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
	- Setup ObjectScale demo endpoints
register_pscale_plugin
	- Register PowerScale plugin into Vault
config_pscale_plugin
	- Configure the PowerScale plugin (endpoint and credentials)
config_pscale_demo
	- Setup PowerScale demo endpoints
verify_vault_plugins
	- Verify if the Vault plugins are installed and enabled
reset_ecs_access_key
	- Reset a specific ECS user's access key. Usage: demo_provision.sh reset_ecs_access_key <username>
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
	wget -N https://raw.githubusercontent.com/EMCECS/s3curl/master/s3curl.pl
	chmod 755 /opt/vault/plugins/*
	chown -R vault:vault /opt/vault/plugins
	# Create AWS Cli configuration files
	mkdir -p ~/.aws
	chmod 755 ~/.aws
	echo "[default]" > ~/.aws/config
	echo "region = \"\"" >> ~/.aws/config
	echo "[default]" > ~/.aws/credentials
	echo "aws_access_key_id = \"\"" >> ~/.aws/credentials
	echo "aws_secret_access_key = \"\"" >> ~/.aws/credentials
	chmod 600 ~/.aws/*
	echo "Packages installed"
}

function install_env() {
	grep -q VAULT_ADDR ~/.bash_profile
	if [ $? -eq 1 ]; then
		cat << EOF > ~/.bash_profile
VAULT_ADDR=${VAULT_ADDR}
export VAULT_ADDR
alias ecsiamuser1='aws --profile=iamuser1 --endpoint-url=http://ecs.demo.local:9020'
alias ecsiamadmin1='aws --profile=iamadmin1 --endpoint-url=http://ecs.demo.local:9020'
EOF
	fi
	echo "VAULT_ADDR environment variable written to ~/.bash_profile"
	echo "Aliases wrapping the AWS cli command written to ~/.bash_profile"
	echo "    Aliases: ecsiamuser1, ecsiamadmin1"
	echo "You must manually source this file to update your environment. Please run the following command:"
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

function reset_ecs_access_key() {
	tag="accesskey"
	# Get list of current user's access key
	key_list=`curl -ks -X\
		POST "${ecs_endpoint}:${ecs_mgmt_port}/iam?Action=ListAccessKeys&UserName=${1}" \
		-H "Accept: application/xml" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}"` | \
		sed -E -e "s~(.*)</${tag}>.*~\1~" -e "s~</${tag}>.*<${tag}>~ ~" -e "s~.*?<${tag}>~~"
	# Delete all access keys
	for key in ${key_list}; do
		curl -ks -X \
			POST \
			"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${1}&Action=DeleteAccessKey&AccessKeyId=${key}"
			-H 'Accept: application/xml' \
			-H "X-SDS-AUTH-TOKEN: $token"
	done
	# Create access key
	curl -ks -X \
		POST \
		"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${1}&Action=CreateAccessKey" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		> ~/creds_${1}.txt
	sed -E -i "s/.*AccessKeyId>(.*)<\/Access.*SecretAccessKey>(.*)<\/Secret.*/\1 \2/" ~/creds_${1}.txt
}

function get_ecs_predefined_from_vault() {
	vault read objectscale/vault/predefined/${1} | tee ~/creds_${1}.txt
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

	# Create Access Key for plugin-admin
	echo "Creating plugin-admin access keys and secret key"
	reset_ecs_access_key "iam-admin1"
	echo "Plugin-admin keys created"

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

# Function expects 3 arguments
# Argument 1: file name with path to modify
# Argument 2: Header of the block to modify, e.g. "ecs" or "pscale"
# Argument 3: Heredoc to replace the block with
function write_awscli_file() {
	edit_block=0
	found=0
	while IFS= read -r line; do
		if [[ "${line}" =~ ^\[.*\]$ ]]; then
			edit_block=0
			if [ "${line}" = "[${2}]" ]; then
				edit_block=1
				found=1
			fi
		fi
		if [[ ${edit_block} -eq 1 ]]; then
			if [[ "${line}" = "[${2}]" ]]; then
				echo "[${2}]"
				echo "${3}"
				echo ""
			fi
		else
			printf '%s\n' "$line"
		fi
	done < ${1}
	if [[ ${found} -eq 0 ]]; then
		echo "[${2}]"
		echo "${3}"
		echo ""
	fi
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
	reset_ecs_access_key)
		reset_ecs_access_key $2
		;;
	get_ecs_predefined_from_vault)
		get_ecs_predefined_from_vault $2
	*)
		echo "$USAGE"
		;;
esac
