package aws.iam

import aws.AWS
import aws.AwsAsyncHandler.{awsToScala, handleAWSErrs}
import aws.ec2.EC2
import com.amazonaws.auth.AWSCredentialsProviderChain
import com.amazonaws.regions.{Region, Regions}
import com.amazonaws.services.cloudformation.model.{DescribeStackResourcesRequest, DescribeStackResourcesResult, DescribeStacksRequest, DescribeStacksResult}
import com.amazonaws.services.cloudformation.{AmazonCloudFormationAsync, AmazonCloudFormationAsyncClientBuilder}
import model.{AwsAccount, Stack, StackResource}
import utils.attempt.Attempt

import scala.collection.JavaConverters._
import scala.concurrent.ExecutionContext

object CloudFormation {
  private def client(auth: AWSCredentialsProviderChain, region: Region): AmazonCloudFormationAsync = {
    AmazonCloudFormationAsyncClientBuilder.standard()
      .withCredentials(auth)
      .withRegion(region.getName)
      .build()
  }
  private def client(awsAccount: AwsAccount, region: Region): AmazonCloudFormationAsync = {
    val auth = AWS.credentialsProvider(awsAccount)
    client(auth, region)
  }

  private def getStackDescriptions(client: AmazonCloudFormationAsync)(implicit ec: ExecutionContext): Attempt[List[Stack]] = {
    val request = new DescribeStacksRequest()
    handleAWSErrs(awsToScala(client.describeStacksAsync)(request)).map(parseStacksResult)
  }

  private def getStackResources(stackName: String, client: AmazonCloudFormationAsync)(implicit ec: ExecutionContext): Attempt[List[StackResource]] = {
    val request = new DescribeStackResourcesRequest().withStackName(stackName)
    handleAWSErrs(awsToScala(client.describeStackResourcesAsync)(request)).map(parseResourcesResult)
  }

  private def getStacksAndResources(account: AwsAccount, region: Region)(implicit ec: ExecutionContext): Attempt[List[Stack]] = {
    val cloudClient = CloudFormation.client(account, region)
    for {
      stacks <- getStackDescriptions(cloudClient)
      updatedStacks <- Attempt.traverse(stacks) { stack =>
        for {
          resources <- getStackResources(stack.id, cloudClient)
        } yield stack.copy(resources = resources, region = Some(region.getName))
      }
    } yield updatedStacks
  }

  private[iam] def getStacksFromAllRegions(account: AwsAccount)(implicit ec: ExecutionContext): Attempt[List[Stack]] = {
    val regionClient = EC2.client(account)
    for {
      availableRegions <- EC2.getAvailableRegions(regionClient)
      regions = availableRegions.map(region => Region.getRegion(Regions.fromName(region.getRegionName)))
      stacks <- Attempt.flatTraverse(regions)(region => getStacksAndResources(account, region))
    } yield stacks
  }

  private def parseResourcesResult(result: DescribeStackResourcesResult): List[StackResource] = {
    for {
      resource <- result.getStackResources.asScala.toList
    } yield StackResource(
      resource.getStackId,
      resource.getStackName,
      resource.getPhysicalResourceId,
      resource.getLogicalResourceId,
      resource.getResourceStatus,
      resource.getResourceType
    )
  }

  private[iam] def parseStacksResult(result: DescribeStacksResult): List[Stack] = {
    result.getStacks.asScala.toList.map { stack =>
      Stack(
        stack.getStackId,
        stack.getStackName,
        Nil,
        None
      )
    }
  }
}