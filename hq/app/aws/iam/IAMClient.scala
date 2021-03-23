package aws.iam

import aws.AwsAsyncHandler._
import aws.cloudformation.CloudFormation
import aws.{AwsClient, AwsClients}
import com.amazonaws.regions.Regions
import com.amazonaws.services.cloudformation.AmazonCloudFormationAsync
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementAsync
import com.amazonaws.services.identitymanagement.model.{GenerateCredentialReportRequest, GenerateCredentialReportResult, GetCredentialReportRequest}
import logic.{CredentialsReportDisplay, Retry}
import model.{AwsAccount, CredentialReportDisplay, IAMCredentialsReport}
import utils.attempt.{Attempt, FailedAttempt}

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}
import java.util.concurrent.Executors
import play.api.Logging


object IAMClient extends Logging {

  val SOLE_REGION = Regions.US_EAST_1

  private def generateCredentialsReport(client: AwsClient[AmazonIdentityManagementAsync])(implicit ec: ExecutionContext): Attempt[GenerateCredentialReportResult] = {
    logger.info("generate credentials report")
    val request = new GenerateCredentialReportRequest()
    handleAWSErrs(client)(awsToScala(client)(_.generateCredentialReportAsync)(request))
  }

  private def getCredentialsReport(client: AwsClient[AmazonIdentityManagementAsync])(implicit ec: ExecutionContext): Attempt[IAMCredentialsReport] = {
    logger.info("get credentials report")
    val request = new GetCredentialReportRequest()
    handleAWSErrs(client)(awsToScala(client)(_.getCredentialReportAsync)(request)).flatMap(CredentialsReport.extractReport)
  }

  def getCredentialReportDisplay(
    account: AwsAccount,
    cfnClients: AwsClients[AmazonCloudFormationAsync],
    iamClients: AwsClients[AmazonIdentityManagementAsync],
    regions: List[Regions]
  )(implicit ec: ExecutionContext): Attempt[CredentialReportDisplay] = {
    val delay = 3.seconds
    logger.info(s"Starting credential report for ${account.name}")

    for {
      client <- iamClients.get(account, SOLE_REGION)
      _ <- Retry.until(generateCredentialsReport(client), CredentialsReport.isComplete, "Failed to generate credentials report", delay)
      report <- getCredentialsReport(client)
      stacks <- CloudFormation.getStacksFromAllRegions(account, cfnClients, regions)
      enrichedReport = CredentialsReport.enrichReportWithStackDetails(report, stacks)
    } yield {
      val credentialsReportDisplay = CredentialsReportDisplay.toCredentialReportDisplay(enrichedReport)
      logger.info(s"FINISH credential report for ${account.name}")
      credentialsReportDisplay
    }
  }

  def getAllCredentialReports(
    accounts: Seq[AwsAccount],
    cfnClients: AwsClients[AmazonCloudFormationAsync],
    iamClients: AwsClients[AmazonIdentityManagementAsync],
    regions: List[Regions]
  ): Attempt[Seq[(AwsAccount, Either[FailedAttempt, CredentialReportDisplay])]] = {

    implicit val ec: ExecutionContext = ExecutionContext.fromExecutor(Executors.newFixedThreadPool(1))

    Attempt.Async.Right {
      Future.traverse(accounts) { account =>
        getCredentialReportDisplay(account, cfnClients, iamClients, regions).asFuture.map(account -> _)
      }
    }
  }
}