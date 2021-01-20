package aws.iam

import aws.AwsAsyncHandler._
import aws.cloudformation.CloudFormation
import aws.{AwsClient, AwsClients}
import logic.{CredentialsReportDisplay, Retry}
import model.{AwsAccount, CredentialReportDisplay, IAMCredentialsReport}
import software.amazon.awssdk.regions.Region
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient
import software.amazon.awssdk.services.iam.IamAsyncClient
import software.amazon.awssdk.services.iam.model.{GenerateCredentialReportRequest, GenerateCredentialReportResponse, GetCredentialReportRequest}
import utils.attempt.{Attempt, FailedAttempt}

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}


object IAMClient {

  val SOLE_REGION = Region.US_EAST_1

  private def generateCredentialsReport(client: AwsClient[IamAsyncClient])(implicit ec: ExecutionContext): Attempt[GenerateCredentialReportResponse] = {
    val request = GenerateCredentialReportRequest.builder.build
    handleAWSErrs(client)(awsToScala(client)(_.generateCredentialReportAsync)(request))
  }

  private def getCredentialsReport(client: AwsClient[IamAsyncClient])(implicit ec: ExecutionContext): Attempt[IAMCredentialsReport] = {
    val request = GetCredentialReportRequest.builder.build
    handleAWSErrs(client)(awsToScala(client)(_.getCredentialReportAsync)(request)).flatMap(CredentialsReport.extractReport)
  }

  def getCredentialReportDisplay(
    account: AwsAccount,
    cfnClients: AwsClients[CloudFormationAsyncClient],
    iamClients: AwsClients[IamAsyncClient],
    regions: List[Region]
  )(implicit ec: ExecutionContext): Attempt[CredentialReportDisplay] = {
    val delay = 3.seconds

    for {
      client <- iamClients.get(account, SOLE_REGION)
      _ <- Retry.until(generateCredentialsReport(client), CredentialsReport.isComplete, "Failed to generate credentials report", delay)
      report <- getCredentialsReport(client)
      stacks <- CloudFormation.getStacksFromAllRegions(account, cfnClients, regions)
      enrichedReport = CredentialsReport.enrichReportWithStackDetails(report, stacks)
    } yield CredentialsReportDisplay.toCredentialReportDisplay(enrichedReport)
  }

  def getAllCredentialReports(
                               accounts: Seq[AwsAccount],
                               cfnClients: AwsClients[CloudFormationAsyncClient],
                               iamClients: AwsClients[IamAsyncClient],
                               regions: List[Region]
  )(implicit executionContext: ExecutionContext): Attempt[Seq[(AwsAccount, Either[FailedAttempt, CredentialReportDisplay])]] = {
    Attempt.Async.Right {
      Future.traverse(accounts) { account =>
        getCredentialReportDisplay(account, cfnClients, iamClients, regions).asFuture.map(account -> _)
      }
    }
  }
}