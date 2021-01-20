package aws.support

import aws.support.TrustedAdvisor.{getTrustedAdvisorCheckDetails, parseTrustedAdvisorCheckResult}
import aws.AwsClient
import software.amazon.awssdk.services.support.SupportAsyncClient
import software.amazon.awssdk.services.support.model.TrustedAdvisorResourceDetail
import model.{RDSSGsDetail, TrustedAdvisorDetailsResult}
import utils.attempt.{Attempt, Failure}

import scala.collection.JavaConverters._
import scala.concurrent.ExecutionContext


object TrustedAdvisorRDSSGs {
  val AWS_RDS_SECURITY_GROUP_ACCESS_RISK_IDENTIFIER = "nNauJisYIT"

  def getRDSSecurityGroupDetail(client: AwsClient[SupportAsyncClient])(implicit ec: ExecutionContext): Attempt[TrustedAdvisorDetailsResult[RDSSGsDetail]] = {
    getTrustedAdvisorCheckDetails(client, AWS_RDS_SECURITY_GROUP_ACCESS_RISK_IDENTIFIER)
      .flatMap(parseTrustedAdvisorCheckResult(parseRDSSGDetail, ec))
  }


  private[support] def parseRDSSGDetail(detail: TrustedAdvisorResourceDetail): Attempt[RDSSGsDetail] = {
    detail.metadata.asScala.toList match {
      case region :: rdsSgId :: ec2SGId :: alertLevel :: _ =>
        Attempt.Right {
          RDSSGsDetail(
            region = detail.region,
            rdsSgId = rdsSgId,
            ec2SGId = ec2SGId,
            alertLevel = alertLevel,
            isSuppressed = detail.isSuppressed
          )
        }
      case metadata =>
        Attempt.Left {
          Failure(s"Could not parse RDSSGs from TrustedAdvisorResourceDetail with metadata $metadata", "Could not parse RDS Security group information", 500).attempt
        }
    }
  }
}
