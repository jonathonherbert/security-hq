package aws.ec2

import aws.AwsAsyncHandler.{awsToScala, handleAWSErrs}
import aws.support.TrustedAdvisorSGOpenPorts
import aws.{AwsClient, AwsClients}
import cats.instances.map._
import cats.instances.set._
import cats.syntax.semigroup._
import model._
import software.amazon.awssdk.services.ec2.Ec2AsyncClient
import software.amazon.awssdk.services.ec2.model._
import software.amazon.awssdk.services.support.SupportAsyncClient
import software.amazon.awssdk.services.support.model.RefreshTrustedAdvisorCheckResponse
import utils.attempt.{Attempt, FailedAttempt}

import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}


object EC2 {

  def getAvailableRegions(client: AwsClient[Ec2AsyncClient])(implicit ec: ExecutionContext): Attempt[List[Region]] = {
    val request = DescribeRegionsRequest.builder.build
    handleAWSErrs(client)(awsToScala(client)(_.describeRegionsAsync)(request)).map { result =>
      result.getRegions.asScala.toList
    }
  }

  /**
    * Given a Trusted Advisor Security Group open ports result,
    * makes EC2 calls in each region to look up the Network Interfaces
    * attached to each flagged Security Group.
    */
  def getSgsUsage(
      sgReport: TrustedAdvisorDetailsResult[SGOpenPortsDetail],
      awsAccount: AwsAccount,
      ec2Clients: AwsClients[Ec2AsyncClient]
    )(implicit ec: ExecutionContext): Attempt[Map[String, Set[SGInUse]]] = {
    val allSgIds = TrustedAdvisorSGOpenPorts.sgIds(sgReport)
    val activeRegions = sgReport.flaggedResources.map(sgInfo => Region.builder.regionName(sgInfo.region).build).distinct

    for {

      dnirs <- Attempt.traverse(activeRegions){ region =>
        for {
          ec2Client <- ec2Clients.get(awsAccount, region)
          usage <- getSgsUsageForRegion(allSgIds, ec2Client)
        } yield usage

      }
    } yield {
      dnirs
        .map(parseDescribeNetworkInterfacesResults(_, allSgIds))
        .fold(Map.empty)(_ |+| _)
    }
  }

  def flaggedSgsForAccount(account: AwsAccount, ec2Clients: AwsClients[Ec2AsyncClient], taClients: AwsClients[SupportAsyncClient])(implicit ec: ExecutionContext): Attempt[List[(SGOpenPortsDetail, Set[SGInUse])]] = {
    for {
      supportClient <- taClients.get(account)
      sgResult <- TrustedAdvisorSGOpenPorts.getSGOpenPorts(supportClient)
      sgUsage <- getSgsUsage(sgResult, account, ec2Clients)
      flaggedSgs = sgResult.flaggedResources.filter(_.status != "ok")
      flaggedSgsIds = flaggedSgs.map(_.id)
      regions = flaggedSgs.map(sg => Region.builder.regionName(sg.region).build).distinct
      clients <- Attempt.traverse(regions)(region => ec2Clients.get(account, region))
      describeSecurityGroupsResults <- Attempt.traverse(clients)(EC2.describeSecurityGroups(flaggedSgsIds))
      sgTagDetails = describeSecurityGroupsResults.flatMap(extractTagsForSecurityGroups).toMap
      enrichedFlaggedSgs = enrichSecurityGroups(flaggedSgs, sgTagDetails)
      vpcs <- getVpcs(account, enrichedFlaggedSgs, ec2Clients)(getVpcsDetails)
      flaggedSgsWithVpc = addVpcName(enrichedFlaggedSgs, vpcs)
    } yield sortSecurityGroupsByInUse(flaggedSgsWithVpc, sgUsage)
  }

  def refreshSGSReports(accounts: List[AwsAccount], taClients: AwsClients[SupportAsyncClient])(implicit ec: ExecutionContext): Attempt[List[Either[FailedAttempt, RefreshTrustedAdvisorCheckResponse]]] = {
    Attempt.traverseWithFailures(accounts) { account =>
      for {
        supportClient <- taClients.get(account)
        result <- TrustedAdvisorSGOpenPorts.refreshSGOpenPorts(supportClient)
      } yield result
    }
  }

  def allFlaggedSgs(accounts: List[AwsAccount], ec2Clients: AwsClients[Ec2AsyncClient], taClients: AwsClients[SupportAsyncClient])(implicit ec: ExecutionContext): Attempt[List[(AwsAccount, Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]])]] = {
    Attempt.Async.Right {
      Future.traverse(accounts) { account =>
        flaggedSgsForAccount(account, ec2Clients, taClients).asFuture.map(account -> _)
      }
    }
  }

  private [ec2] def sortSecurityGroupsByInUse(sgsPortFlags : List[SGOpenPortsDetail], sgUsage: Map[String, Set[SGInUse]]) = {
    sgsPortFlags
      .map(sgOpenPortsDetail => sgOpenPortsDetail -> sgUsage.getOrElse(sgOpenPortsDetail.id, Set.empty))
      .sortWith { case  ((_, s1), (_, s2)) => s1.size > s2.size }
  }

  def sortAccountByFlaggedSgs[L, R](accountsWithFlaggedSgs: List[(AwsAccount, Either[L, List[R]])]): List[(AwsAccount, Either[L, List[R]])] = {
    accountsWithFlaggedSgs.sortBy {
      // first, non-empty flagged results list
      // sort internally by number of flagged results, decreasing (largest number of flagged results first)
      case (_, Right(flaggedSgs)) if flaggedSgs.nonEmpty =>
        (0, 0, flaggedSgs.length * -1, "")
      // second, failed to get results
      // sort internally by name of account
      case (account, Left(_)) =>
        (0, 1, 0, account.name)
      // finally, empty flagged results
      // sort internally by name of account
      case (account, Right(_)) =>
        (1, 0, 0, account.name)
    }
  }

  private def describeSecurityGroups(sgIds: List[String])(client: AwsClient[Ec2AsyncClient])(implicit ec: ExecutionContext): Attempt[DescribeSecurityGroupsResponse] = {
    val request = DescribeSecurityGroupsRequest.builder
      .filters(Filter.builder.name("group-id").values(sgIds.asJava).build)
      .build
    handleAWSErrs(client)(awsToScala(client)(_.describeSecurityGroupsAsync)(request))
  }

  private[ec2] def extractTagsForSecurityGroups(describeSecurityGroupsResponse: DescribeSecurityGroupsResponse): Map[String, List[Tag]] = {
    val sgs = describeSecurityGroupsResponse.securityGroups.asScala.toList
    sgs.map { sg =>
      sg.groupId -> sg.tags.asScala.toList
    }.toMap
  }

  private[ec2] def enrichSecurityGroups(sGOpenPortsDetails: List[SGOpenPortsDetail], sgTagDetails: Map[String, List[Tag]]): List[SGOpenPortsDetail] = {
    sGOpenPortsDetails.map { sGOpenPortsDetail =>
      val enrichedSGOpenPortsDetail = for {
        tags <- sgTagDetails.get(sGOpenPortsDetail.id)
        cfStackNameTag <- tags.find(_.key == "aws:cloudformation:stack-name")
        cfStackIdTag <- tags.find(_.key == "aws:cloudformation:stack-id")
      } yield sGOpenPortsDetail.copy(stackName = Some(cfStackNameTag.value), stackId = Some(cfStackIdTag.value))
      enrichedSGOpenPortsDetail.getOrElse(sGOpenPortsDetail)
    }
  }

  private[ec2] def getSgsUsageForRegion(sgIds: List[String], client: AwsClient[Ec2AsyncClient])(implicit ec: ExecutionContext): Attempt[DescribeNetworkInterfacesResponse] = {
    val request = DescribeNetworkInterfacesRequest.builder
      .filters(Filter.builder.name("group-id").values(sgIds.asJava).build)
      .build
    handleAWSErrs(client)(awsToScala(client)(_.describeNetworkInterfacesAsync)(request))
  }

  private[ec2] def parseDescribeNetworkInterfacesResults(dnir: DescribeNetworkInterfacesResponse, sgIds: List[String]): Map[String, Set[SGInUse]] = {
    dnir.networkInterfaces.asScala.toSet
      .flatMap { (ni: NetworkInterface) =>
        val sgUse = parseNetworkInterface(ni)
        val matchingGroupIds = ni.groups.asScala.toList.filter(gi => sgIds.contains(gi.groupId))
        matchingGroupIds.map(_ -> sgUse)
      }
      .groupBy { case (sgId, _) => sgId.groupId }
      .mapValues { pairs =>
        pairs.map { case (_, sgUse) => sgUse }
      }
  }

  private[ec2] def parseNetworkInterface(ni: NetworkInterface): SGInUse = {
    val elb = for {
      networkInterfaceAttachment  <- Option(ni.attachment)
      instanceOwnerID <- Option(networkInterfaceAttachment.instanceOwnerId)
      if instanceOwnerID == "amazon-elb"
    } yield ELB(ni.description.stripPrefix("ELB "))

    val instance = for {
      networkInterfaceAttachment <- Option(ni.attachment)
      instanceID <- Option(networkInterfaceAttachment.instanceId)
    } yield Ec2Instance(instanceID)

    elb
      .orElse(instance)
      .getOrElse(
        UnknownUsage(
          Option(ni.description).getOrElse("No network interface description"),
          Option(ni.networkInterfaceId).getOrElse("No network interface ID")
        )
      )
  }

  private[ec2] def addVpcName(flaggedSgs: List[SGOpenPortsDetail], vpcs: Map[String, Vpc]): List[SGOpenPortsDetail] = {
    def vpcName(vpc: Vpc) = vpc.tags.asScala.collectFirst { case tag if tag.key == "Name" => tag.value }

    flaggedSgs.map {
      case s if s.vpcId.nonEmpty => s.copy(vpcName = vpcs.get(s.vpcId) flatMap vpcName)
      case s => s
    }
  }

  private[ec2] def getVpcs(account: AwsAccount, flaggedSgs: List[SGOpenPortsDetail], ec2Clients: AwsClients[Ec2AsyncClient])(vpcsDetailsF: AwsClient[Ec2AsyncClient] => Attempt[Map[String, Vpc]])(implicit ec: ExecutionContext): Attempt[Map[String, Vpc]] = {
    Attempt.traverse(flaggedSgs.map(_.region).distinct) { region =>
      val awsRegion = Region.builder.regionName(region).build
      for {
        ec2Client <- ec2Clients.get(account, awsRegion)
        vpcDetails <- vpcsDetailsF(ec2Client)
      } yield vpcDetails

    }.map(_.fold(Map.empty)(_ ++ _))
  }

  private def getVpcsDetails(client: AwsClient[Ec2AsyncClient])(implicit ec: ExecutionContext): Attempt[Map[String, Vpc]] = {
    val request = DescribeVpcsRequest.builder.build
    val vpcsResult = handleAWSErrs(client)(awsToScala(client)(_.describeVpcsAsync)(request))
    vpcsResult.map { result =>
      result.vpcs.asScala.map(vpc => vpc.vpcId -> vpc).toMap
    }
  }
}
