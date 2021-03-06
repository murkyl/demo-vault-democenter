
# HashiCorp Vault Plugin demonstration for ECS/ObjectScale and PowerScale
Scripts to help demonstrate Hashicorp Vault plugin for ObjectScale and PowerScale in Dell Demo Center

## Create the demo environment

This demonstration environment is based on the Dell Technologies Demo Center. This is a registered environment and will require a partner or employee login. If you do not have a login you will not be able to proceed.

### Setup

1) Navigate to: https://democenter.delltechnologies.com/
2) Login to Demo Center
3) Search for and deploy: HOL-0543-01 (PowerScale, DataIQ & ECS Field Enablement)
4) Connect to lab after the lab is setup
5) Open RoyalTS
6) Connect to "ldap-kdc"

Run the following commands to download and setup the demo:

Clean up the Yum package cache due to very old entries in the cache causing problems
```bash
yum clean all
rm -rf /var/cache/yum/*
```

```bash
wget -N https://raw.githubusercontent.com/murkyl/demo-vault-democenter/main/demo_provision.sh
```

```bash
chmod a+x demo_provision.sh
```

```bash
./demo_provision.sh all
```

After all packages are installed update your environment

```bash
source ~/.bash_profile
```

The alias used for this demo populated by bash_profile are:

- [ ] ***ecsiamdynamic -*** uses the dynamically created credentials from Vault Server into the AWS Credentials file. AWS credentials profile is **dynamic**.
- [ ] ***ecsiamadmin1 -*** uses the predefined ECS IAM user iam-admin1. The secret is updated from Vault Server into the AWS Credentials file. AWS credentials profile is **iam-admin1**.
- [ ] ***ecsiamuser1 -*** uses the predefined ECS IAM user iam-user1. The secret is updated from Vault Server into the AWS Credentials file. AWS credentials profile is **iam-user1**.

------

### **Demo 1** - Predefined User Secret

Demo one demonstrates how an existing IAM user in ECS can have an S3 secret generated on the fly by Hashicorp Vault and used with an S3 compatible program. The user in this demo has a secret time to live (TTL) of 5 min. After 5 min the Vault Server will delete the ECS secret attached to iam-admin1.

In this demo the program being used is AWS CLI as the client of Vault Server. In a real world application the application could be a webapp, backup software, database, etc.

This demo environment uses Linux aliases to simply AWS CLI commands. If the AWS CLI commands do not look correct this is the reason why.

1. The installation script **demo_provision.sh** has already created an IAM user **iam-admin1** with an IAM Policy granting full access to the ECS S3 API (ECSS3FullAccess). 

2. To start using the AWS CLI we need to generate an IAM secret for **iam-admin1** user. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
./demo_provision.sh get_ecs_predefined iam-admin1
```

Once the above command is issued the secret for iam-admin1 will have a time to live (TTL) of 5 min. If your AWS CLI commands fail your secret may have expired. If so repeat the above command to receive another secret valid for 5 minuets.

3. Demonstrate there is no buckets inside the ECS by listing all buckets within the NS1 namespace. The command should return nothing.

```bash
ecsiamadmin1 s3 ls
```

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `An error occurred (InvalidAccessKeyId) when calling the ListBuckets operation: The Access Key Id you provided does not exist in our records.`
>
>  Issue step 2's command to re-issue iam-admin1's secret.

4. Create a bucket in the NS1 namespace with iam-admin1 user. The bucket will be called **admin1**.

```bash
ecsiamadmin1 s3 mb s3://admin1
```

``make_bucket admin1``

5. Perform a bucket list command to show the new bucket has been created.

```bash
ecsiamadmin1 s3 ls
```

``2022-02-14 16:52:56 admin1``

6. Upload data as iam-admin1 user into the new **admin1** bucket.

```
ecsiamadmin1 s3 cp s3curl.pl s3://admin1
```

``upload: ./s3curl.pl to s3://admin1/s3curl.pl``

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `upload failed: ./s3curl.pl to s3://admin1/s3curl.pl An error occurred (InvalidAccessKeyId) when calling the PutObject operation: The Access Key Id you provided does not exist in our records.`
>
> Issue step 2's command to re-issue iam-admin1's secret.

7. Finally list the contents of the admin1 bucket to verify the file has uploaded.

```bash
ecsiamadmin1 s3 ls s3://admin1
```

``2022-02-14 16:52:56	12161	s3curl.pl``

This concludes the demonstration of an existing ECS IAM user having its secrets managed by HashiCorp Vault Server.

------

### **Demo 2** - Dynamic User Secret

A real world scenario for demo two is a webapp which only needs to access an ECS bucket to read a file and present a response to a client. This webapp only needs read privileges using the concept of least privilege. When there are no clients connected to the webapp there is no need for long living credentials coded into the server. This also increases the security posture of the webapp and protects the ECS bucket. If the webapp is compromised by malicious attackers the Vault administrators can revoke the dynamic access credentials or the credentials may have expired preventing the attackers from progressing their attack.

1. The installation script **demo_provision.sh** has not created any users, this demo will show the power of HashiCorp Vault in creating dynamically a time limited user with set permissions. Users created dynamically will have the **ECSS3ReadOnlyAcces**s IAM Policy applied.

2. To start using the AWS CLI we need to generate an IAM user with an accessKey and SecretKey. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
./demo_provision.sh get_ecs_dynamic readonly_app1
```

Once the above command is issued the iam user, accessKey and secretKey will be created with a time to live (TTL) of 5 min. If your AWS CLI commands fails your secret may have expired. If so, repeat the above command to receive another secret valid for 5 minutes.



3. Demonstrate that the dynamic user can list all buckets within the NS1 namespace. The command should return nothing.

```
ecsdynamic s3 ls
```

``2022-02-14 16:52:56 admin1``

4. Let's try and create a bucket inside the NS1 namespace. This command should fail.

```bash
ecsdynamic s3 mb s3://dynamic1
```

``make_bucket failed: s3://dynamic1 An error occured (AccessDenied) when calling the CreateBucket operation: Access Denied``

**dynamic_user** cannot perform any other functions other than list buckets and object. This is because the dynamic user has been attached to an IAM Policy which allows only read-only access. The Vault administrator has already created a Vault Role inside Vault. It creates a relationship between the ECS IAM Policy and when anyone requests the dynamic user there is no ability to privilege escalate.

5. Let's try and PUT an object into a bucket. This command will fail as well.

```
ecsdynamic s3 cp s3curl.pl s3://admin1
```

For this dynamic user to perform any write or administrative function on the ECS the user will need to escalate their permissions via the IAM role assumption.

Proceed to the next demo to see how Vault Server and ECS can streamline Role assumptions.

------

### Demo 3 - IAM Assume Role

Demo three demonstrates how **iam-user1** an S3 read-only user can escalate privileges to perform administration functions on ECS inside the NS1 namespace. This demonstration will use ECS's IAM assumeRole API and the accessKey and secretKey will be issued by the IAM STS service.

The time to live (TTLS) on the role escalation will be valid for 1 hour. The Role in ECS's IAM which will be assumed is the admin role which has the **ECSS3FullAccess** policy applied.

These tasks will use the AWS CLI, the credentials will be fed from the Vault Server.


1. The installation script **demo_provision.sh** has already created an IAM user **iam-user1** and an custom IAM policy granting read-only access to the ECS S3 API and access to the IAM STS Service (**AllowAssumeRole**). 

2. To start using the AWS CLI we need to generate an IAM secret for **iam-user1** user. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
./demo_provision.sh get_ecs_predefined iam-user1
```

Once the above command is issued the secret for iam-admin1 will have a time to live (TTL) of 60 minutes. If your AWS CLI commands fails your secret may have expired. If so, repeat the above command to receive another secret valid for 60 minutes.

3. Demonstrate that iam-user1 with its read-only permissions cannot list buckets inside the NS1 namespace. The below command will list a bucket if buckets exist in the namespace.

```bash
ecsiamuser1 s3 ls
```

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `An error occurred (InvalidAccessKeyId) when calling the ListBuckets operation: The Access Key Id you provided does not exist in our records.`
>
>  Issue step 2's command to re-issue iam-admin1's secret.

4. Let's try and create a bucket inside the NS1 namespace. This command should fail.

```bash
ecsiamuser1 s3 mb s3://role1
```

``make_bucket failed: s3://role1 An error occured (AccessDenied) when calling the CreateBucket operation: Access Denied``

**iam-user1** needs to escalate its privileges temporarily to to create and upload object to buckets. To escalate privileges in S3 iam-user1 needs to assume the admin role which has the **ECSS3FullAccess** policy attached. Next **iam-user1** needs to alter its accessKey, secretKey and provide a securityToken to re-authenticate to ECS with the elevated privileges.

5. Perform the below command to instruct ECS to create credentials for **iam-user1** to temporarily have admin access via the ECS Role **admin** using the Secure Token Service (STS).

```bash
./demo_provision.sh get_ecs_sts iam-user1 urn:ecs:iam::ns1:role/admins
```

6. We use the **ecssts** alias which makes use of the security token returned in a role assumption. Try to create a bucket again and this time the command will complete successfully.

```bash
ecssts s3 mb s3://role1
```

``make_bucket: role1``

7. Let's upload an object into the newly create role1 bucket.

```bash
ecssts s3 cp s3curl.pl s3://role1
```

``		upload: ./s3curl.pl to s3://role1/s3curl.pl``

8. Let's list the contents of the role1 bucket. The previously uploaded object should be visable.

```bash
ecssts s3 ls s3://role1
```

``2022-02-15 01:45:08		12161	s3curl.pl``

------

### **Demo 4** - PowerScale Predefined User Secret

Demo four demonstrates how an existing S3 user in PowerScale can have an S3 secret generated on the fly by Hashicorp Vault and used with an S3 compatible program. The user in this demo has a secret time to live (TTL) of 5 min. After 5 min the Vault Server will delete the secret attached to s3user1.

In this demo the program being used is AWS CLI as the client of Vault Server. In a real world application the application could be a webapp, backup software, database, etc.

This demo environment uses Linux aliases to simply AWS CLI commands. If the AWS CLI commands do not look correct this is the reason why.

1. The installation script **demo_provision.sh** has already created an S3 user **s3user1**. This user has a bucket pointing to their home directory on the PowerScale cluster. 

2. To start using the AWS CLI we need to generate an access key and secret for **s3user1**. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
./demo_provision.sh get_pscale_predefined s3user1
```

Once the above command is issued the secret for s3user1 will have a time to live (TTL) of 5 min. If your AWS CLI commands fail your secret may have expired. If so repeat the above command to receive another secret valid for 5 minuets.

3. Demonstrate there is a single buckets by listing all buckets owned by the user. The command should return the user's pre-created bucket.

```bash
psuser1 s3 ls
```

``2022-02-23 01:25:44	s3user1bucket``

> If the s3user1's secret has expired, the below error message will appear.
>
> `An error occurred (SignatureDoesNotMatch) when calling the ListBuckets operation: The request signature we calculated does not match the signature provided. Check the Secret Access Key and signing method.`
>
>  Issue step 2's command to re-issue credentials.

4. Create a new bucket with the iam-admin1 user. The bucket will be called **newbucket**.

```bash
psuser1 s3 mb s3://newbucket
```

``make_bucket newbucket``

5. Perform a bucket list command to show the new bucket has been created.

```bash
psuser1 s3 ls
```

``2022-02-23 01:25:44	s3user1bucket``
``2022-02-23 01:38:59 newbucket``

6. Upload data as s3user1 user into the new **newbucket** bucket.

```
psuser1 s3 cp s3curl.pl s3://newbucket
```

``upload: ./s3curl.pl to s3://newbucket/s3curl.pl``

> If the s3user1's secret has expired, the below error message will appear.
>
> `upload failed: ./s3curl.pl to s3://admin1/s3curl.pl An error occurred (SignatureDoesNotMatch) when calling the PutObject operation: The request signature we calculated does not match the signature provided. Check the Secret Access Key and signing method.`
>
> Issue step 2's command to re-issue credentials.

7. Finally list the contents of the  bucket to verify the file has uploaded.

```bash
psuser1 s3 ls s3://newbucket
```

``2022-02-22 17:43:48	12161	s3curl.pl``

This concludes the demonstration of an existing PowerScale S3 user having its secrets managed by HashiCorp Vault Server.

------

### **Demo 5** - PowerScale Dynamic User Secret

Demo 5 follows demo 2 for ObjectScale. It can be used for the same purpose.

1. The installation script **demo_provision.sh** has not created any dynamic users. This demo will show the power of HashiCorp Vault in creating dynamically a time limited user with set permissions. Users created dynamically will belong to the **Backup Operators** group in the System Access Zone and have access to a pre-created bucket called s3-dynamic owned by root.

2. To start using the AWS CLI we need to generate a dynamic user with an accessKey and SecretKey. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
./demo_provision.sh get_pscale_dynamic s3-dynamic
```

Once the above command is issued the user, accessKey, and secretKey will be created with a time to live (TTL) of 5 min. If your AWS CLI commands fails your secret may have expired. If so, repeat the above command to receive another secret valid for 5 minutes.

3. Demonstrate that the dynamic user can list all buckets. The command should return nothing as the user does not own any buckets and only has access to a bucket.

```bash
psdynamic s3 ls
```

4. Let's try and list a bucket that the user has access.

```bash
psdynamic s3 ls s3://s3-dynamic
```
This command should also return nothing as no data is in the bucket yet.

If you attempt to list a bucket that does not exist or you do not have access you will see one of the following error messages

    An error occurred (NoSuchBucket) when calling the ListObjects operation: The specified bucket does not exist.
    
    An error occurred (AccessDenied) when calling the ListObjects operation: Access Denied.

5. Let's try and PUT an object into a bucket.

```bash
psdynamic s3 cp s3curl.pl s3://s3-dynamic
```
`upload: ./s3curl.pl to s3://s3-dynamic/s3curl.pl``

4. List the bucket again to see the uploaded file.

```bash
psdynamic s3 ls s3://s3-dynamic
```
``2022-02-22 18:08:49	12161	s3curl.pl``

5. You can see the names of the Vault users created on PowerScale.

```bash
ssh 192.168.1.21 isi auth users list 
```

    Name
    --------------------------------
    Guest
    vault_mgr
    s3user1
    vault_KzbSb5_c1bc_20220223020644
    root
    admin
    compadmin
    remotesupport
    ftp
    insightiq
    www
    _ypldap
    _lldpd
    nobody
    isdmgmt
    --------------------------------
    Total: 15

6. Wait until the user times out and re-run the query to see the user with the name prefix **vault_** automatically removed.

```bash
ssh 192.168.1.21 isi auth users list 
```

    Name
    --------------------------------
    Guest
    vault_mgr
    s3user1
    root
    admin
    compadmin
    remotesupport
    ftp
    insightiq
    www
    _ypldap
    _lldpd
    nobody
    isdmgmt
    --------------------------------
    Total: 14

After the user expires and is automatically cleaned up, access to the dynamic bucket is removed. To proceed further in testing, create a new dynamic user using Step 2 above and try out various S3 access commands of your own.

