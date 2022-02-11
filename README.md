# demo-vault-democenter
Scripts to help demonstrate Hashicorp Vault plugin for ObjectScale and PowerScale in Dell Demo Center

## Quickstart

Navigate to: https://democenter.delltechnologies.com/
Login to Demo Center
Search for and deploy: HOL-0543-01 (PowerScale, DataIQ & ECS Field Enablement)
Connect to lab after the lab is setup
Open RoyalTS
Connect to "ldap-kdc"
Run the following commands to download and setup the demo:

    wget -N https://raw.githubusercontent.com/murkyl/demo-vault-democenter/main/demo_provision.sh
    chmod a+x demo_provision.sh
    ./demo_provision.sh all

After all packages are installed update your environment

    source ~/.bash_profile

