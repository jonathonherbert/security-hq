package aws.iam

import aws.AwsAsyncHandler._
import aws.cloudformation.CloudFormation
import com.amazonaws.regions.Regions
import com.amazonaws.services.cloudformation.AmazonCloudFormationAsync
import com.amazonaws.services.ec2.AmazonEC2Async
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementAsync
import com.amazonaws.services.identitymanagement.model.{GenerateCredentialReportRequest, GenerateCredentialReportResult, GetCredentialReportRequest}
import logic.{ReportDisplay, Retry}
import model.{AwsAccount, CredentialReportDisplay, IAMCredentialsReport}
import utils.attempt.{Attempt, FailedAttempt, Failure}

import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}


object IAMClient {

  def client(iamClients: Map[(String, Regions),  AmazonIdentityManagementAsync], awsAccount: AwsAccount): Attempt[ AmazonIdentityManagementAsync] = {
    val region = Regions.US_EAST_1
    Attempt.fromOption(iamClients.get((awsAccount.id, region)), FailedAttempt(Failure(
      s"No AWS Trusted Advisor Client exists for ${awsAccount.id} and $region",
      s"Cannot find Trusted Advisor Client",
      500
    )))
  }


  private def generateCredentialsReport(client: AmazonIdentityManagementAsync)(implicit ec: ExecutionContext): Attempt[GenerateCredentialReportResult] = {
    val request = new GenerateCredentialReportRequest()
    handleAWSErrs(awsToScala(client.generateCredentialReportAsync)(request))
  }

  private def getCredentialsReport(client: AmazonIdentityManagementAsync)(implicit ec: ExecutionContext): Attempt[IAMCredentialsReport] = {
    val request = new GetCredentialReportRequest()
    handleAWSErrs(awsToScala(client.getCredentialReportAsync)(request)).flatMap(CredentialsReport.extractReport)
  }

  def getCredentialReportDisplay(
    account: AwsAccount,
    cfnClients: Map[(String, Regions), AmazonCloudFormationAsync],
    ec2Clients: Map[(String, Regions), AmazonEC2Async],
    iamClients: Map[(String, Regions),  AmazonIdentityManagementAsync]
  )(implicit ec: ExecutionContext): Attempt[CredentialReportDisplay] = {
    val delay = 3.seconds

    for {
      client <- IAMClient.client(iamClients, account)
      _ <- Retry.until(generateCredentialsReport(client), CredentialsReport.isComplete, "Failed to generate credentials report", delay)
      report <- getCredentialsReport(client)
      stacks <- CloudFormation.getStacksFromAllRegions(account, cfnClients, ec2Clients)
      enrichedReport = CredentialsReport.enrichReportWithStackDetails(report, stacks)
    } yield ReportDisplay.toCredentialReportDisplay(enrichedReport)
  }

  def getAllCredentialReports(
    accounts: Seq[AwsAccount],
    cfnClients: Map[(String, Regions), AmazonCloudFormationAsync],
    ec2Clients: Map[(String, Regions), AmazonEC2Async],
    iamClients: Map[(String, Regions),  AmazonIdentityManagementAsync]
  )(implicit executionContext: ExecutionContext): Attempt[Seq[(AwsAccount, Either[FailedAttempt, CredentialReportDisplay])]] = {
    Attempt.Async.Right {
      Future.traverse(accounts) { account =>
        getCredentialReportDisplay(account, cfnClients, ec2Clients, iamClients).asFuture.map(account -> _)
      }
    }
  }
}