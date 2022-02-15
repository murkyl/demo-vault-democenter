# demo-vault-democenter
Scripts to help demonstrate Hashicorp Vault plugin for ObjectScale and PowerScale in Dell Demo Center

## Create the demo environment

This demonstration environment is based on the Dell Technologies Demo Centre. This is a registered environment and will require a partner or employee login. If you do not have a login you will not be able to proceed.

### Setup

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



### **Demo 1**

Demo one demonstrates how an existing IAM user in ECS can have an S3 secret generated on the fly by Hashicorp Vault and used with an S3 compatible program. The user in this demo has a secret time to live (TTL) of 5 min. After 5 min the Vault Server will delete the ECS secret attached to iam-admin1.

In this demo the program being used is AWS CLI as the client of Vault Server. In a real world application the application could be a webapp, backup software, database, etc.

This demo environment use Linux aliases to simply AWS CLI commands. If the AWS CLI commands to not look correct this is the reason why.

1. The installation script **demo_provision.sh** has already created an IAM user **iam-admin1** with an IAM Policy granting full access to the ECS S3 API (ECSS3FullAccess). 
2. To start using the AWS CLI we need to generate an IAM secret for **iam-admin1** user. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
$ ./demo_provision.sh get_ecs_predefined iam-admin1
```

<!--Once the above command is issued the secret for iam-admin1 will have a time to live (TTL) of 5 min. If your AWS CLI commands fail your secret may have expired. If so repeat the above command to receive another secret valid for 5 minuets.-->

3. Demonstrate there is no buckets inside the ECS by listing all buckets within the NS1 namespace. The command should return nothing.

```bash
$ ecsiamadmin1 s3 ls
```

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `An error occurred (InvalidAccessKeyId) when calling the ListBuckets operation: The Access Key Id you provided does not exist in our records.`
>
>  Issue step 2's command to re-issue iam-admin1's secret.

4. Create a bucket in the NS1 namespace with iam-admin1 user. The bucket will be called **admin1**.

```bash
$ ecsiamadmin1 s3 mb s3://admin1
make_bucket admin1
```

5. Perform a bucket list command to show the new bucket has been created.

```bash
$ ecsiamadmin1 s3 ls
2022-02-14 16:52:56 admin1
```

6. Upload data as iam-admin1 user into the new **admin1** bucket.

```bash
$ ecsiamadmin1 s3 cp s3curl.pl s3://admin1
upload: ./s3curl.pl to s3://admin1/s3curl.pl
```

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `upload failed: ./s3curl.pl to s3://admin1/s3curl.pl An error occurred (InvalidAccessKeyId) when calling the PutObject operation: The Access Key Id you provided does not exist in our records.`
>
>  Issue step 2's command to re-issue iam-admin1's secret.

7. Finally list the contents of the admin1 bucket to verify the file has uploaded.

```bash
$ ecsiamadmin1 s3 ls
2022-02-14 16:52:56	12161	s3curl.pl
```

This concludes the demonstration of an existing ECS IAM user having its secrets managed by HashiCorp Vault Server.

### **Demo 2**

TBA!!!!

### Demo 3

Demo three demonstrates how **iam-user1** an S3 read-only user can escalate privilege's to perform administration functions on ECS inside the NS1 namespace. This demonstration will use ECS's IAM assumeRole API and the accessKey and secretKey will be issued by the IAM STS service.

The time to live (TTLS) on the role escalation will be valid for 1 hour. The Role in ECS's IAM which will be assumed is the admin role which has the **ECSS3FullAccess** policy applied.

These tasks will use a combination of AWS CLI and **s3curl**, both programs will have credential information fed from Vault Server.



1. The installation script **demo_provision.sh** has already created an IAM user **iam-user1** and an custom IAM policy granting read-only access to the ECS S3 API and access to the IAM STS Service (**AllowAssumeRole**). 
2. To start using the AWS CLI we need to generate an IAM secret for **iam-user1** user. To do this issue the below command within the **ldap-kdc** virtual machine in **RoyalTS**.

```bash
$ ./demo_provision.sh get_ecs_predefined iam-user1
```

<!--Once the above command is issued the secret for iam-admin1 will have a time to live (TTL) of 5 min. If your AWS CLI commands fail your secret may have expired. If so repeat the above command to receive another secret valid for 5 minuets.-->

3. Demonstrate that iam-user1 with its read-only permissions cannot list buckets inside the NS1 namespace. The below command will list a bucket if buckets exist in the namespace.

```bash
$ ecsiamuser1 s3 ls
```

> If the iam-admin1 users secret has expired, the below error message will appear.
>
> `An error occurred (InvalidAccessKeyId) when calling the ListBuckets operation: The Access Key Id you provided does not exist in our records.`
>
>  Issue step 2's command to re-issue iam-admin1's secret.

4. Lets try and create a bucket inside the NS1 namespace. This command should fail.

```bash
$ ecsiamuser1 s3 mb s3://user1bucket
make_bucket failed: s3://userbucket An error occured (AccessDenied) when calling the CreateBucket operation: Access Denied
```



4. iam-user1 needs to escalate its privilege's temporarily to to list, create, upload object to buckets. Perform the below command to instruct ECS to create credentials for iam-user1 to temporarily have admin access via the ECS Role **admin**.

```bash
$ ./demo_provision.sh get_ecs_sts iam-user1 urn:ecs:iam::ns1:role/admins
```

5. rarhaa

```bash
$ ecssts s3 mb s3://role1
```





