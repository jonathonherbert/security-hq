package controllers

import auth.SecurityHQAuthActions
import com.gu.googleauth.GoogleAuthConfig
import config.Config
import logic.{CredentialsReportDisplay, DocumentUtil}
import model.AwsAccount
import org.joda.time.DateTime
import play.api._
import play.api.libs.ws.WSClient
import play.api.mvc._
import services.CacheService

import scala.collection.immutable
import scala.concurrent.ExecutionContext

case class DataPoint(time: DateTime, value: Int)

case class DataCategory(name: String, data: List[DataPoint])


class ReportController(val config: Configuration, cacheService: CacheService, val authConfig: GoogleAuthConfig)
  (implicit val ec: ExecutionContext, val wsClient: WSClient, val bodyParser: BodyParser[AnyContent], val controllerComponents: ControllerComponents, val assetsFinder: AssetsFinder)
  extends BaseController with SecurityHQAuthActions {

  private val accounts = Config.getAwsAccounts(config)

  def getIamSummary: Seq[(AwsAccount, CredentialsReportDisplay.ReportSummary)] = {
    val credentialSummary: immutable.Seq[(AwsAccount, CredentialsReportDisplay.ReportSummary)] = cacheService.getAllCredentials.toList.filter{
      case (_, report) => report.isRight
    }.map{
      case (awsAccount, report) => (awsAccount, CredentialsReportDisplay.reportStatusSummary(report.right.get))
    }
    credentialSummary
  }

  def getIamErrorCount(credentialSummary: Seq[(AwsAccount, CredentialsReportDisplay.ReportSummary)]) = {
    credentialSummary.map(_._2.errors).sum
  }

  def getIamWarningCount(credentialSummary: Seq[(AwsAccount, CredentialsReportDisplay.ReportSummary)]) = {
    credentialSummary.map(_._2.warnings).sum
  }

  def report = authAction {
    val summary = getIamSummary
    val errorCount = getIamErrorCount(summary)
    val warningCount = getIamWarningCount(summary)

    val criticalIam = DataCategory("Critical IAM Vulnerabilities", List(DataPoint(DateTime.now, errorCount)))
    val warnIam = DataCategory("IAM warnings", List(DataPoint(DateTime.now, warningCount)))

    Ok(views.html.report(List(criticalIam, warnIam)))
  }

}
