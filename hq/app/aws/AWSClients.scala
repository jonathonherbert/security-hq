package aws

import aws.ec2.EC2
import aws.iam.IAMClient
import aws.support.TrustedAdvisor
import com.amazonaws.regions.Regions
import com.amazonaws.services.ec2.AmazonEC2Async
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementAsync
import com.amazonaws.services.support.AWSSupportAsync
import model.AwsAccount

class AWSClients(accounts: List[AwsAccount]) {

  private val mapOfAccountsToRegionsToClients: Map[AwsAccount, Map[Regions, Clients]] =
    accounts.map { account =>
      account -> Regions.values().map { region =>
        region -> new Clients(account, region)
      }.toMap
    }.toMap

  def getEC2Client(account: AwsAccount, region: Regions): AmazonEC2Async = mapOfAccountsToRegionsToClients(account)(region).ec2Client
  def getTAClient(account: AwsAccount): AWSSupportAsync = mapOfAccountsToRegionsToClients(account)(Regions.US_EAST_1).taClient
  def getIAMClient(account: AwsAccount): AmazonIdentityManagementAsync = mapOfAccountsToRegionsToClients(account)(Regions.EU_WEST_1).iamClient
}


class Clients(account: AwsAccount, region: Regions) {
  lazy val ec2Client: AmazonEC2Async = EC2.client(account, region)
  lazy val taClient: AWSSupportAsync = TrustedAdvisor.client(account)
  lazy val iamClient: AmazonIdentityManagementAsync = IAMClient.client(account, region)
}
