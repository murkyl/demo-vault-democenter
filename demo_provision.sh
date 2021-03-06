#!/bin/bash
IFS='' read -r -d '' USAGE << EOF
Usage: demo_provision.sh <operation>

Quickstart:
Run the script with 'all' to setup ObjectScale and PowerScale demos
    ./demo_provision.sh all

Valid operations:
all
	- Perform a full install and configuration
install
	- Install packages and plugins
init_ecs
	- Setup ECS with users and policies. Clears existing keys
init_pscale
	- Setup PowerScale with SSH key based login, users, and groups
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
reset_ecs_access_key <username>
	- Reset a user's access key
get_ecs_predefined <username>
	- Get ECS predefined access key, save to ~/creds_<username>.txt, and add to the AWS CLI config
	  Use alias: ecsiamuser1 or ecsiamadmin1
get_ecs_dynamic <username>
	- Get ECS dynamic access key, save to ~/creds_dynamic.txt, and add to the AWS CLI config
	  Use alias: ecsdynamic
get_ecs_sts <username>
	- Get ECS STS access key, save to ~/creds_<username>.txt, and add to the AWS CLI config
get_pscale_predefined <username>
	- Get PowerScale predefined access key, save to ~/creds_<username>.txt, and add to the AWS CLI config
	  Use alias: psuser1
get_pscale_dynamic <username>
	- Get PowerScle dynamic access key, save to ~/creds_ps_dynamic.txt, and add to the AWS CLI config
	  Use alias: psdynamic
EOF

# Define common variables with defaults. You can override these from the shell by setting the environment variables appropriately
vault_ver="${VAULT_VER:=vault-1.7.3}"
vault_cfg_file="${VAULT_CFG_FILE:=/etc/vault.d/vault.hcl}"
vault_default_expire=${VAULT_DEFAULT_EXPIRE:=300}
vault_default_sts_expire=${VAULT_DEFAULT_STS_EXPIRE:=3600}
ecs_endpoint="${ECS_ENDPOINT:=https://ecs.demo.local}"
ecs_mgmt_port="${ECS_MGMT_PORT:=4443}"
ecs_data_endpoint="${ECS_DATA_ENDPOINT:=http://ecs.demo.local}"
ecs_data_port="${ECS_DATA_PORT:=9020}"
ecs_plugin_ver="${ECS_PLUGIN_VER:=0.4.3}"
ecs_plugin_name="${ECS_PLUGIN_NAME:=vault-plugin-secrets-objectscale}"
ecs_vault_endpoint="${ECS_VAULT_ENDPOINT:=objectscale}"
pscale_endpoint="${PSCALE_ENDPOINT:=192.168.1.21}"
pscale_mgmt_port="${PSCALE_MGMT_PORT:=8080}"
pscale_data_endpoint="${PSCALE_DATA_ENDPOINT:=http://192.168.1.21}"
pscale_data_port="${PSCALE_DATA_PORT:=9020}"
pscale_plugin_ver="${PSCALE_PLUGIN_VER:=0.3.3}"
pscale_plugin_name="${PSCALE_PLUGIN_NAME:=vault-plugin-secrets-onefs}"
pscale_vault_endpoint="${PSCALE_VAULT_ENDPOINT:=pscale}"
# VAULT_ADDR needs to be in the shell's environment and this line will be added to the user's ~/.bash_profile
# The user will have to reload their profile to have it take effect after the script runs. e.g. source ~/.bash_profile
export VAULT_ADDR="${VAULT_ADDR:=http://127.0.0.1:8200}"

# Define ECS variables
ecs_username="${ECS_USERNAME:=root}"
ecs_password="${ECS_PASSWORD:=Password123!}"
ecs_role_name="${ECS_ROLE_NAME:=admins}"
ecs_role_policy_file="${ECS_ROLE_POLICY_FILE:=role_iam-user1.json}"
ecs_assume_policy_file="${ECS_ASSUME_POLICY_FILE:=assume_role_policy.json}"
ecs_dynamic_role_1="${ECS_DYNAMIC_ROLE_NAME:=readonly_app1}"
#ecs_token is exported to the environment holding the current authentication token

# Defining IAM Users
# The first user MUST be the account that will be used by the plugin
# The second user is the account that will have their secrets rotated
# The third user is an IAM user that will use STS to assume a role
iam_users=("plugin-admin" "iam-admin1" "iam-user1")

# Defining IAM Policies
# There must be a 1 to 1 match between the iam_users and iam_policies arrays
iam_policies=("urn:ecs:iam:::policy/IAMFullAccess" "urn:ecs:iam:::policy/ECSS3FullAccess" "urn:ecs:iam::ns1:policy/AllowAssumeRole")

# Define PowerScale variables
pscale_username="${PSCALE_USERNAME:=root}"
pscale_password="${PSCALE_PASSWORD:=Password123!}"
pscale_vault_user="${PSCALE_VAULT_USER:=vault_mgr}"
pscale_vault_password="${PSCALE_VAULT_PASSWORD:=isasecret}"
pscale_vault_home_dir="${PSCALE_VAULT_HOME_DIR:=/ifs/home/vault}"
pscale_vault_group="${PSCALE_VAULT_GROUP:=vault}"
pscale_vault_role="${PSCALE_VAULT_ROLE:=VaultMgr}"
pscale_dynamic_role="${PSCALE_DYNAMIC_ROLE:=s3-dynamic}"

#======================================================================
#
# Package, install, and misc functions
#
#======================================================================
function install_packages() {
	# Install extra packages
	echo "Installing additional required packages"
	yum install -y yum-utils python3 perl-Digest-HMAC sshpass
	python3 -m pip install -U pip
	pip3 install awscli
	yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
	yum install -y ${vault_ver}
	mkdir /opt/vault/plugins
	wget -N -P /opt/vault/plugins https://github.com/murkyl/${ecs_plugin_name}/releases/download/v${ecs_plugin_ver}/${ecs_plugin_name}-linux-amd64-${ecs_plugin_ver}
	wget -N -P /opt/vault/plugins https://github.com/murkyl/${pscale_plugin_name}/releases/download/v${pscale_plugin_ver}/${pscale_plugin_name}-linux-amd64-${pscale_plugin_ver}
	wget -N https://raw.githubusercontent.com/murkyl/demo-vault-democenter/main/role_iam-user1.json
	wget -N https://raw.githubusercontent.com/murkyl/demo-vault-democenter/main/assume_role_policy.json
	wget -N https://raw.githubusercontent.com/EMCECS/s3curl/master/s3curl.pl
	chmod a+x ~/s3curl.pl
	chmod 755 /opt/vault/plugins/*
	chown -R vault:vault /opt/vault/plugins
	reset_aws_config
	echo "Packages installed"
}

function install_env() {
	grep -q VAULT_ADDR ~/.bash_profile
	if [ $? -eq 1 ]; then
		cat << EOF >> ~/.bash_profile
VAULT_ADDR=${VAULT_ADDR}
export VAULT_ADDR
alias ecsiamuser1='aws --profile=iam-user1 --endpoint-url=${ecs_data_endpoint}:${ecs_data_port}'
alias ecsiamadmin1='aws --profile=iam-admin1 --endpoint-url=${ecs_data_endpoint}:${ecs_data_port}'
alias ecsdynamic='aws --profile=dynamic --endpoint-url=${ecs_data_endpoint}:${ecs_data_port}'
alias ecssts='s3curlwrapper'
alias psuser1='aws --profile=s3user1 --endpoint-url=${pscale_data_endpoint}:${pscale_data_port}'
alias psdynamic='aws --profile=psdynamic --endpoint-url=${pscale_data_endpoint}:${pscale_data_port}'

function strips3prefix() {
  if [[ \$1 =~ s3://.* ]]; then
    echo "\${1:5}"
  fi
}

# 3 function arguments
# Arg 1: Always s3
# Arg 2: Operation/Command, currently can have 'mb' and 'cp'
# Arg 3: Depends on operation
function s3curlwrapper() {
  op="\${2}"
  if [[ "\$1" != "s3" ]]; then
    op="help"
  fi
  token=\`grep security_token ~/creds_stsuser.txt | awk '{ print \$2 }'\`
  case \$op in
    cp)
      if [ \$token = "" ]; then
        echo "Missing security token in ~/creds_stsuser.txt"
      else
        ~/s3curl.pl --id=ecs --put=\${3} -- -H "X-Amz-Security-Token: \${token}" "${ecs_data_endpoint}:${ecs_data_port}/\$(strips3prefix \${4})/\$(strips3prefix \${3})"
      fi
      ;;
    ls)
      if [ \$token = "" ]; then
        echo "Missing security token in ~/creds_stsuser.txt"
      else
        ~/s3curl.pl --id=ecs -- -H "X-Amz-Security-Token: \${token}" "${ecs_data_endpoint}:${ecs_data_port}/\$(strips3prefix \${4}))"
      fi
      ;;
    mb)
      if [ \$token = "" ]; then
        echo "Missing security token in ~/creds_stsuser.txt"
      else
        ~/s3curl.pl --id=ecs --createBucket -- -H "X-Amz-Security-Token: \${token}" "${ecs_data_endpoint}:${ecs_data_port}/\$(strips3prefix \${3})"
      fi
      ;;
    *)
      echo "s3curlwrapper pretends to be the aws CLI command"
      echo "Usage:"
      echo "s3curlwrapper s3 cp <filename> s3://<bucketname>"
      echo "s3curlwrapper s3 ls <endpoint,s3://<bucketname>"
      echo "s3curlwrapper s3 mb s3://<bucketname>"
      ;;
  esac
}

EOF
	fi
	echo "VAULT_ADDR environment variable written to ~/.bash_profile"
	echo "Aliases wrapping the AWS cli command written to ~/.bash_profile"
	echo "    Aliases: ecsiamuser1, ecsiamadmin1, ecsdynamic, ecssts, psuser1, psdynamic"
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	echo "You MUST manually source this file to update your environment"
	echo "    source ~/.bash_profile"
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
}

function reset_aws_config() {
	# Create AWS Cli configuration files
	mkdir -p ~/.aws
	chmod 755 ~/.aws
	echo "[default]" > ~/.aws/config
	echo "region = \"\"" >> ~/.aws/config
	echo "[default]" > ~/.aws/credentials
	echo "aws_access_key_id = \"\"" >> ~/.aws/credentials
	echo "aws_secret_access_key = \"\"" >> ~/.aws/credentials
	echo ""
	chmod 600 ~/.aws/*
}

# Function expects 4 or 5 arguments
# Argument 1: file name with path to modify
# Argument 2: Header of the block to modify, e.g. "ecs" or "pscale"
# Argument 3: Access key
# Argument 4: Secret
# Argument 5: Security token (optional)
function write_awscli_file() {
	read -r -d '' creds << EOF
aws_access_key_id = ${3}
aws_secret_access_key = ${4}
EOF
	if [[ ${5} != "" ]]; then
		printf -v creds '%s\naws_session_token = %s' "${creds}" "${5}"
	fi

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
				echo "[${2}]" >> ${1}.tmp
				echo "${creds}" >> ${1}.tmp
				echo "" >> ${1}.tmp
			fi
		else
			echo "${line}" >> ${1}.tmp
		fi
	done < ${1}
	if [[ ${found} -eq 0 ]]; then
		echo "[${2}]" >> ${1}.tmp
		echo "${creds}" >> ${1}.tmp
		echo "" >> ${1}.tmp
	fi
	mv -f ${1}.tmp ${1}
}

function write_s3curl_file() {
	read -r -d '' creds << EOF
%awsSecretAccessKeys = (
    ecs => {
        id => '${2}',
        key => '${3}',
    },
);
EOF
	echo "${creds}" > ${1}
	chmod 600 ${1}
}

function print_expire_date() {
	now=`date +"%s"`
	echo "Credentials will expire at: "
	if [[ $1 = "" ]]; then
		echo -n `date`
	else
		future=$(expr $now + $1)
		echo -n `date --date="@${future}"`
	fi
	echo ", time is currently: `date`"
}

function generate_ssh_key_pair() {
	rm -f ~/.ssh/id_rsa
	ssh-keygen -b 2048 -t rsa -q -N "" -f ~/.ssh/id_rsa
	echo ${pscale_password} >> ~/.ssh/password.txt
	chmod 600 ~/.ssh/password.txt
	sshpass -f ~/.ssh/password.txt ssh-copy-id -o StrictHostKeyChecking=no root@${pscale_endpoint}
	rm -f ~/.ssh/password.txt
}

#======================================================================
#
# General Hashicorp Vault related functions
#
#======================================================================
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

#======================================================================
#
# ObjectScale/ECS related functions
#
#======================================================================
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
		user=`cat ~/creds_${iam_users[0]}.txt | grep access_key | awk '{print $2}'` \
		password=`cat ~/creds_${iam_users[0]}.txt | grep secret_key | awk '{print $2}'` \
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
	vault write ${ecs_vault_endpoint}/roles/dynamic/${ecs_dynamic_role_1} namespace=ns1 policy=ECSS3ReadOnlyAccess
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
	tag="AccessKeyId"
	# Get list of current user's access key
	response=`curl -ks -X\
		POST "${ecs_endpoint}:${ecs_mgmt_port}/iam?Action=ListAccessKeys&UserName=${1}" \
		-H "Accept: application/xml" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}"`
	key_list=`echo "${response}" | sed -E -e "s~(.*)</${tag}>.*~\1~" -e "s~</${tag}>.*<${tag}>~ ~" -e "s~.*?<${tag}>~~"`
	# Delete all access keys
	for key in ${key_list}; do
		curl -ks -X \
			POST \
			"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${1}&Action=DeleteAccessKey&AccessKeyId=${key}" \
			-H 'Accept: application/xml' \
			-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
			> /dev/null
	done
	# Create access key
	curl -ks -X \
		POST \
		"${ecs_endpoint}:${ecs_mgmt_port}/iam?UserName=${1}&Action=CreateAccessKey" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		> ~/creds_${1}.txt
	sed -E -i "s/.*AccessKeyId>(.*)<\/Access.*SecretAccessKey>(.*)<\/Secret.*/access_key    \1\nsecret_key    \2\n/" ~/creds_${1}.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_${1}.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_${1}.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials ${1} ${key} ${secret}
}

function get_ecs_predefined() {
	vault read ${ecs_vault_endpoint}/creds/predefined/${1} | tee ~/creds_${1}.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_${1}.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_${1}.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials ${1} ${key} ${secret}
	print_expire_date ${vault_default_expire}
}

function get_ecs_dynamic() {
	vault read ${ecs_vault_endpoint}/creds/dynamic/${1} | tee ~/creds_dynamic.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_dynamic.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_dynamic.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials dynamic ${key} ${secret}
	print_expire_date ${vault_default_expire}
}

# Function expects 2 arguments
# Argument 1: user name
# Argument 2: ARN of a role, e.g. urn:ecs:iam::ns1:role/admin
function get_ecs_sts() {
	vault read ${ecs_vault_endpoint}/sts/predefined/${1} role_arn=${2} | tee ~/creds_${1}.txt
	cp -f ~/creds_${1}.txt ~/creds_stsuser.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_${1}.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_${1}.txt | awk '{print $2}'`
	token=`grep security_token ~/creds_${1}.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials ${1} ${key} ${secret} ${token}
	write_s3curl_file ~/.s3curl $key $secret
	print_expire_date ${vault_default_sts_expire}
}

function create_ecs_users_and_policies() {
	echo "Creating new policy to allow a user to assume a role"
	# Create new policy which allows for STS role assumption
	curl -ks \
		--data-urlencode "PolicyDocument@${ecs_assume_policy_file}" \
		--data "PolicyName=AllowAssumeRole" \
		--data "Action=CreatePolicy" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		"${ecs_endpoint}:${ecs_mgmt_port}/iam?" \
		> ~/log_create_assume_policy.txt

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
	reset_ecs_access_key "plugin-admin"
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
		-X POST "${ecs_endpoint}:${ecs_mgmt_port}/iam?PolicyArn=${iam_policies[1]}&RoleName=${ecs_role_name}&Action=AttachRolePolicy" \
		-H "X-SDS-AUTH-TOKEN: ${ecs_token}" \
		>> ~/log_create_role.txt
	echo "Role created"
}

#======================================================================
#
# PowerScale related functions
#
#======================================================================
function register_pscale_plugin() {
	# Register plugin
	echo "[PSCALE] Registering plugin"
	VAULT_PSCALE_PLUGIN_VERSION=`ls /opt/vault/plugins/${pscale_plugin_name}-linux-* | sort -R | tail -n 1 | sed 's/.*\///'`
	VAULT_PSCALE_PLUGIN_SHA256=`sha256sum /opt/vault/plugins/${VAULT_PSCALE_PLUGIN_VERSION} | cut -d " " -f 1`
	vault plugin register -sha256=${VAULT_PSCALE_PLUGIN_SHA256} -command ${VAULT_PSCALE_PLUGIN_VERSION} secret ${pscale_vault_endpoint}
	vault secrets enable -path=${pscale_vault_endpoint} ${pscale_vault_endpoint}
	echo "[PSCALE] Plugin registered"
}

function config_pscale_plugin() {
	# Configure PowerScale plugin
	echo "[PSCALE] Configure plugin"
	vault write ${pscale_vault_endpoint}/config/root \
		user="${pscale_vault_user}" \
		password="${pscale_vault_password}" \
		endpoint=https://${pscale_endpoint}:${pscale_mgmt_port} \
		homedir="${pscale_vault_home_dir}" \
		primary_group="${pscale_vault_group}" \
		cleanup_period=300 \
		bypass_cert_check=true
	vault read ${pscale_vault_endpoint}/config/root
	echo "[PSCALE] Plugin configured"
}

function config_pscale_demo() {
	vault write ${pscale_vault_endpoint}/roles/predefined/s3user1 ttl=${vault_default_expire}
	vault write ${pscale_vault_endpoint}/roles/dynamic/${pscale_dynamic_role} ttl=${vault_default_expire} group="Backup Operators" bucket="${pscale_dynamic_role}" access-zone="System"
	echo "Demo endpoints configured"
	echo "Usable endpoints"
	echo "    # Rotate access key and secret"
	echo "    ${pscale_vault_endpoint}/creds/predefined/s3user1"
	echo "    # Dynamically created S3 user"
	echo "    ${pscale_vault_endpoint}/creds/dynamic/${pscale_dynamic_role}"
	echo ""
	echo "Example:"
	echo "  vault read ${pscale_vault_endpoint}/creds/predefined/s3user1"
}

function create_pscale_users_and_groups() {
	echo "[PSCALE] Allowing http access"
	ssh ${pscale_endpoint} isi s3 settings global modify --https-only=false
	echo "[PSCALE] Creating roles and adding privileges"
	ssh ${pscale_endpoint} isi auth roles create --name=${pscale_vault_role}
	ssh ${pscale_endpoint} isi auth roles modify VaultMgr --add-priv=ISI_PRIV_S3
	ssh ${pscale_endpoint} isi auth roles modify VaultMgr --add-priv=ISI_PRIV_LOGIN_PAPI
	ssh ${pscale_endpoint} isi auth roles modify VaultMgr --add-priv=ISI_PRIV_AUTH
	echo "[PSCALE] Creating common group for dynamic mode"
	ssh ${pscale_endpoint} isi auth groups create vault
	ssh ${pscale_endpoint} mkdir ${pscale_vault_home_dir}
	ssh ${pscale_endpoint} chown root:wheel ${pscale_vault_home_dir}
	ssh ${pscale_endpoint} chmod 755 ${pscale_vault_home_dir}
	echo "[PSCALE] Creating user to be used by Vault"
	ssh ${pscale_endpoint} isi auth users create ${pscale_vault_user} --enabled=True --password=${pscale_vault_password}
	ssh ${pscale_endpoint} isi auth roles modify ${pscale_vault_role} --add-user=${pscale_vault_user}
	echo "[PSCALE] Create standard user for S3 access"
	ssh ${pscale_endpoint} isi auth users create s3user1 --enabled=True
	ssh ${pscale_endpoint} isi s3 buckets create s3user1bucket /ifs/home/s3user1 --owner=s3user1
	echo "[PSCALE] Create dynamic user bucket"
	ssh ${pscale_endpoint} isi s3 buckets create --create-path --name=${pscale_dynamic_role} --path=/ifs/${pscale_dynamic_role} --owner=root
	ssh ${pscale_endpoint} isi s3 buckets modify ${pscale_dynamic_role} --add-ace=\"name=Backup Operators,type=group,perm=full_control\"
}

function get_pscale_predefined() {
	vault read ${pscale_vault_endpoint}/creds/predefined/${1} | tee ~/creds_${1}.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_${1}.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_${1}.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials ${1} ${key} ${secret}
	print_expire_date ${vault_default_expire}
}

function get_pscale_dynamic() {
	vault read ${pscale_vault_endpoint}/creds/dynamic/${1} | tee ~/creds_pscale_dynamic.txt
	# Update AWS CLI credentials
	key=`grep access_key ~/creds_pscale_dynamic.txt | awk '{print $2}'`
	secret=`grep secret_key ~/creds_pscale_dynamic.txt | awk '{print $2}'`
	write_awscli_file ~/.aws/credentials psdynamic ${key} ${secret}
	print_expire_date ${vault_default_expire}
}

#======================================================================
#
# CLI menu
#
#======================================================================
if [ $# -eq 0 ]; then
	echo "$USAGE"
	exit 1
fi

case $1 in
	all)
		install_packages
		configure_vault
		start_vault
		echo "Sleeping for 2 seconds waiting for Vault to start"
		sleep 2
		init_vault
		unseal_and_login_vault

		login_ecs
		create_ecs_users_and_policies
		logout_ecs
		register_ecs_plugin
		config_ecs_plugin

		generate_ssh_key_pair
		create_pscale_users_and_groups
		register_pscale_plugin
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
	init_pscale)
		generate_ssh_key_pair
		create_pscale_users_and_groups
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
	reset_aws_config)
		reset_aws_config
		;;
	reset_ecs_access_key)
		if [[ $2 = "" ]]; then
			echo "Please provide a user name as an option"
		else
			login_ecs
			reset_ecs_access_key $2
			logout_ecs
		fi
		;;
	get_ecs_predefined)
		if [[ $2 = "" ]]; then
			echo "Please provide a user name as an option"
		else
			get_ecs_predefined $2
		fi
		;;
	get_ecs_dynamic)
		if [[ $2 = "" ]]; then
			echo "Please provide a dynamic role name as an option"
			echo "e.g. ${ecs_dynamic_role_1}"
		else
			get_ecs_dynamic $2
		fi
		;;
	get_ecs_sts)
		if [[ $2 = "" ]] || [[ $3 = "" ]]; then
			echo "Please provide a user name and a role ARN as options"
			echo "e.g. iam-user1 urn:ecs:iam::ns1:role/admins"
		else
			get_ecs_sts $2 $3
		fi
		;;
	get_pscale_predefined)
		if [[ $2 = "" ]]; then
			echo "Please provide a user name as an option"
			echo "e.g. s3user1"
		else
			get_pscale_predefined $2
		fi
		;;
	get_pscale_dynamic)
		if [[ $2 = "" ]]; then
			echo "Please provide a dynamic role name as an option"
			echo "e.g. ${pscale_dynamic_role}"
		else
			get_pscale_dynamic $2
		fi
		;;
	*)
		echo "$USAGE"
		;;
esac
