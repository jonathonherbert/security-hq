package services

import aws.ec2.EC2
import aws.iam.IAMClient
import aws.inspector.Inspector
import aws.support.TrustedAdvisorExposedIAMKeys
import com.amazonaws.regions.Regions
import com.amazonaws.services.cloudformation.AmazonCloudFormationAsync
import com.amazonaws.services.ec2.AmazonEC2Async
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementAsync
import com.amazonaws.services.inspector.AmazonInspectorAsync
import com.amazonaws.services.support.AWSSupportAsync
import com.gu.Box
import config.Config
import model._
import play.api.inject.ApplicationLifecycle
import play.api.{Configuration, Environment, Logger, Mode}
import rx.lang.scala.Observable
import utils.attempt.{FailedAttempt, Failure}

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._

class CacheService(
    config: Configuration,
    lifecycle: ApplicationLifecycle,
    environment: Environment,
    inspectorClients: Map[(String, Regions), AmazonInspectorAsync],
    ec2Clients: Map[(String, Regions), AmazonEC2Async],
    cfnClients: Map[(String, Regions), AmazonCloudFormationAsync],
    taClients: Map[(String, Regions), AWSSupportAsync],
    iamClients: Map[(String, Regions),  AmazonIdentityManagementAsync]
  )(implicit ec: ExecutionContext) {
  private val accounts = Config.getAwsAccounts(config)
  private val startingCache = accounts.map(acc => (acc, Left(Failure.cacheServiceError(acc.id, "cache").attempt))).toMap
  private val credentialsBox: Box[Map[AwsAccount, Either[FailedAttempt, CredentialReportDisplay]]] = Box(startingCache)
  private val exposedKeysBox: Box[Map[AwsAccount, Either[FailedAttempt, List[ExposedIAMKeyDetail]]]] = Box(startingCache)
  private val sgsBox: Box[Map[AwsAccount, Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]]]] = Box(startingCache)
  private val inspectorBox: Box[Map[AwsAccount, Either[FailedAttempt, List[InspectorAssessmentRun]]]] = Box(startingCache)

  def getAllCredentials: Map[AwsAccount, Either[FailedAttempt, CredentialReportDisplay]] = credentialsBox.get()

  def getCredentialsForAccount(awsAccount: AwsAccount): Either[FailedAttempt, CredentialReportDisplay] = {
    credentialsBox.get().getOrElse(
      awsAccount,
      Left(Failure.cacheServiceError(awsAccount.id, "credentials").attempt)
    )
  }

  def getAllExposedKeys: Map[AwsAccount, Either[FailedAttempt, List[ExposedIAMKeyDetail]]] = exposedKeysBox.get()

  def getExposedKeysForAccount(awsAccount: AwsAccount): Either[FailedAttempt, List[ExposedIAMKeyDetail]] = {
    exposedKeysBox.get().getOrElse(
      awsAccount,
      Left(Failure.cacheServiceError(awsAccount.id, "exposed keys").attempt)
    )
  }

  def getAllSgs: Map[AwsAccount, Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]]] = sgsBox.get()

  def getSgsForAccount(awsAccount: AwsAccount): Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]] = {
    sgsBox.get().getOrElse(
      awsAccount,
      Left(Failure.cacheServiceError(awsAccount.id, "security group").attempt)
    )
  }

  def getAllInspectorResults: Map[AwsAccount, Either[FailedAttempt, List[InspectorAssessmentRun]]] = inspectorBox.get()

  def getInspectorResultsForAccount(awsAccount: AwsAccount): Either[FailedAttempt, List[InspectorAssessmentRun]] = {
    inspectorBox.get().getOrElse(
      awsAccount,
      Left(Failure.cacheServiceError(awsAccount.id, "AWS Inspector results").attempt)
    )
  }

  private def refreshCredentialsBox(): Unit = {
    Logger.info("Started refresh of the Credentials data")
    for {
      allCredentialReports <- IAMClient.getAllCredentialReports(accounts, cfnClients, ec2Clients, iamClients)
    } yield {
      Logger.info("Sending the refreshed data to the Credentials Box")
      credentialsBox.send(allCredentialReports.toMap)
    }
  }

  private def refreshExposedKeysBox(): Unit = {
    Logger.info("Started refresh of the Exposed Keys data")
    for {
      allExposedKeys <- TrustedAdvisorExposedIAMKeys.getAllExposedKeys(accounts, taClients)
    } yield {
      Logger.info("Sending the refreshed data to the Exposed Keys Box")
      exposedKeysBox.send(allExposedKeys.toMap)
    }
  }

  private def refreshSgsBox(): Unit = {
    Logger.info("Started refresh of the Security Groups data")
    for {
      _ <- EC2.refreshSGSReports(accounts, taClients)
      allFlaggedSgs <- EC2.allFlaggedSgs(accounts, ec2Clients, taClients)
    } yield {
      Logger.info("Sending the refreshed data to the Security Groups Box")
      sgsBox.send(allFlaggedSgs.toMap)
    }
  }

  def refreshInspectorBox(): Unit = {
    Logger.info("Started refresh of the AWS Inspector data")
    for {
      allInspectorRuns <- Inspector.allInspectorRuns(accounts, inspectorClients)
    } yield {
      Logger.info("Sending the refreshed data to the AWS Inspector Box")
      inspectorBox.send(allInspectorRuns.toMap)
    }
  }

  if (environment.mode != Mode.Test) {
    val initialDelay =
      if (environment.mode == Mode.Prod) 10.seconds
      else Duration.Zero

    val exposedKeysSubscription = Observable.interval(initialDelay + 2000.millis, 5.minutes).subscribe { _ =>
      refreshExposedKeysBox()
    }

    val sgSubscription = Observable.interval(initialDelay + 3000.millis, 5.minutes).subscribe { _ =>
      refreshSgsBox()
    }

    val credentialsSubscription = Observable.interval(initialDelay + 4000.millis, 15.minutes).subscribe { _ =>
      refreshCredentialsBox()
    }

    val inspectorSubscription = Observable.interval(initialDelay + 5000.millis, 6.hours).subscribe { _ =>
      refreshInspectorBox()
    }

    lifecycle.addStopHook { () =>
      exposedKeysSubscription.unsubscribe()
      sgSubscription.unsubscribe()
      credentialsSubscription.unsubscribe()
      inspectorSubscription.unsubscribe()
      Future.successful(())
    }
  }
}
