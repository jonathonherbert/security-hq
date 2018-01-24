package services

import java.util.concurrent.Executors

import aws.ec2.EC2
import com.gu.Box
import config.Config
import model.{AwsAccount, SGInUse, SGOpenPortsDetail}
import play.api.inject.ApplicationLifecycle
import play.api.{Configuration, Environment, Logger, Mode}
import rx.lang.scala.Observable
import utils.attempt.{FailedAttempt, Failure}

import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration._
import scala.collection.concurrent.{TrieMap => ConcurrentMap}


class CacheService(config: Configuration, lifecycle: ApplicationLifecycle, environment: Environment) {
  type SGResult = Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]]
  private val sgsCacheData: ConcurrentMap[AwsAccount, SGResult] = ConcurrentMap.empty
  private val accounts = Config.getAwsAccounts(config)

  implicit val ec: ExecutionContext = ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(50))

  Logger.info("Cache service constructor")

  def getAllSgs(): Map[AwsAccount, Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]]] = {
    Logger.info("getting all results from security groups cache")
    sgsCacheData.toMap
  }

  def getSgsForAccount(awsAccount: AwsAccount): Either[FailedAttempt, List[(SGOpenPortsDetail, Set[SGInUse])]] = {
    Logger.info(s"getting ${awsAccount.name} from security groups cache service")
    sgsCacheData.getOrElse(
      awsAccount,
      Left(Failure("unable to find account data in the cache", "No security group data available", 500, Some(awsAccount.id)).attempt)
    )
  }

  if (environment.mode != Mode.Test) {
    val refreshTick = Observable.interval(500.millis, 5.minutes)
    val sgRefreshData = refreshTick.flatMap { _ =>
      accounts.map { account =>
        Observable.from(
          EC2.flaggedSgsForAccount(account).asFuture.map(account -> _)
        )
      }.foldLeft[Observable[(AwsAccount, SGResult)]](Observable.empty)(_.merge(_))
    }
    val updateEvents = sgRefreshData.map { case (account, result) =>
      sgsCacheData.put(account, result)
      account -> result
    }

    val sgSubscription = updateEvents.subscribe { event =>
      event match {
        case (account, Left(fa)) =>
          Logger.warn(s"Failed to refresh SG data for ${account.name}, ${fa.failures.map(_.message).mkString(", ")}", fa.throwable.orNull)
        case (account, Right(result)) =>
          Logger.info(s"Updated ${account.name} cache, ${result.size} items")
      }
    }

    lifecycle.addStopHook { () =>
      Logger.info("unsubscribe cache service during application stop")
      sgSubscription.unsubscribe()
      Future.successful(())
    }
  }
}
