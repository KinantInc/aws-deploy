# Deploy Kinant on AWS:
One can deploy Kinant platform using the deploy.py python utility,
the operatons conducted by deploy utility is as follows:

1. The utility checks for users AWS credentials in the enviornment,
    one can configure the credentials using the aws cli and issuing the
    command $aws configure.

    If enviornment is not configured, it prompts the user to enter its AWS credentials
    (AWS ACCESS kEY, AWS SECRET KEY and region).

    Note: Make sure the credentials enterd have sufficient permissions to:
    a. Create a IAM Role
    b. Create a security group
    c. Add ingress rule to security group
    d. Launch an instance

2. The utility asks for the AMI-id to be deployed in your enviornment,
you can get the AMI-id by registering [here]()

3. User needs to select one of the available VPCs to deploy the platform in.
    Note: It is recommended that the VPC has an internet gateway attached to it.
    The gateway is required for you to access the user dashboard hosted by the platform.
    Also, if you need to examine your EFS resources, make sure you select the same VPC
    as the EFS, since EFS is not accessible outside the designated VPC.

4. The utility asks the user to select one of the subnets inside the selected VPC.

5. A security group with the name "KinantPlatform" is created inside the selected subnet.
    The security group has the following inbound rules:
    IpProtocol="tcp", CidrIp="0.0.0.0/0", Ports=22,8000 and 8443

6. A IAM Role by the name "KinantPlatform" is created for the deployment instance.
    THe Role will be applied to a ec2 service and has the following trust document
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

7. The utility asks for the type of instance to be created for the deployment,
    currently supported options are:'t2.medium', 't2.large', 't2.xlarge'

8. The platform is finally deployed in the selected subnet and the instance metadata is displayed on
the screen.

9. Logs for all the executed AWS commands go inside the logs folder in the current working directory.
