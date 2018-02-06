package logic

import model.{SnykIssue, _}
import org.scalatest.{FreeSpec, Matchers}
import utils.attempt.AttemptValues

import scala.concurrent.ExecutionContext.Implicits.global

class SnykDisplayTest extends FreeSpec with Matchers with AttemptValues {

  private val mockBadResponseWithMessage = s"""{"error": "some nice error"}"""

  private val mockBadResponseWithoutMessage =
    s"""{"toughluck": "no use"}"""

  "find organisation" in {
    val mockGoodOrganisationResponse = s"""
      |{"orgs":
      |[
      |  {"name": "guardian", "id": "1111111111" },
      |  {"name": "nottheguardian", "id": "9999999999"}
      |]
      |}""".stripMargin
    val organisation = SnykDisplay.getOrganisation(mockGoodOrganisationResponse, SnykOrganisationName("guardian"))
    organisation.value shouldBe SnykOrganisation("guardian", "1111111111")
  }

  "fail to find organisation" - {
    "bad response" in {
      val organisationId = SnykDisplay.getOrganisation(s"""response is not json!""", SnykOrganisationName("guardian"))
      organisationId.isFailedAttempt shouldBe true
      organisationId.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (response is not json!)"
    }
    "message received in response" in {
      val organisationId = SnykDisplay.getOrganisation(mockBadResponseWithMessage, SnykOrganisationName("guardian"))
      organisationId.isFailedAttempt shouldBe true
      organisationId.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (some nice error)"
    }
    "message not received in response" in {
      val organisationId = SnykDisplay.getOrganisation(mockBadResponseWithoutMessage, SnykOrganisationName("guardian"))
      organisationId.isFailedAttempt shouldBe true
      organisationId.getFailedAttempt.failures.head.friendlyMessage shouldBe """Could not read Snyk response ({"toughluck": "no use"})"""
    }
  }

  "find projects" - {
    val mockGoodProjectResponse =
      s"""
         |{
         |  "org": {
         |    "name": "guardian",
         |    "id": "1111111111"
         |  },
         |  "projects": [
         |    {
         |      "name": "project1",
         |      "id": "2222222222"
         |    },
         |    {
         |      "name": "project2",
         |      "id": "3333333333"
         |    }
         |  ]
         |}
     """.stripMargin
    "find project 1 in project list" in {
      val projects = SnykDisplay.getProjectIdList(mockGoodProjectResponse)
      projects.value().exists(p => p.name == "project1") shouldBe true
    }
    "find project 2 in project list" in {
      val projects = SnykDisplay.getProjectIdList(mockGoodProjectResponse)
      projects.value().exists(p => p.name == "project2") shouldBe true
    }
  }

  "fail to find project list" - {
    "bad response" in {
      val projects = SnykDisplay.getProjectIdList(s"""response is not json!""")
      projects.isFailedAttempt shouldBe true
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (response is not json!)"
    }
    "fail to find project id list (nice) - fails" in {
      val projects = SnykDisplay.getProjectIdList(mockBadResponseWithMessage)
      projects.isFailedAttempt shouldBe true
    }
    "fail to find project id list (nice) - has message" in {
      val projects = SnykDisplay.getProjectIdList(mockBadResponseWithMessage)
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (some nice error)"
    }
    "fail to find project id list (not nice) - fails" in {
      val projects = SnykDisplay.getProjectIdList(mockBadResponseWithoutMessage)
      projects.isFailedAttempt shouldBe true
    }
    "fail to find project id list (not nice) - has message" in {
      val projects = SnykDisplay.getProjectIdList(mockBadResponseWithoutMessage)
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe """Could not read Snyk response ({"toughluck": "no use"})"""
    }
  }

  "find vulnerability list" - {
    "find ok for empty list" in {
      val mockGoodAndNotVulnerableResponse = s"""
         |{
         |  "ok": true,
         |  "issues": {
         |    "vulnerabilities": [],
         |    "licenses": []
         |  },
         |  "dependencyCount": 0,
         |  "packageManager": "sbt"
         |}
     """.stripMargin
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockGoodAndNotVulnerableResponse))
      projects.value().head.ok shouldBe true
    }

    val mockGoodButVulnerableResponse = s"""
       |{
       |  "ok": false,
       |  "issues": {
       |    "vulnerabilities": [
       |      {
       |        "id": "4444444444",
       |        "url": "https://snyk.io/vuln/4444444444",
       |        "title": "The Title",
       |        "type": "vuln",
       |        "description": "The description",
       |        "from": [
       |          "from1",
       |          "from2",
       |          "from3"
       |        ],
       |        "package": "The package",
       |        "version": "The version",
       |        "severity": "high",
       |        "language": "The language",
       |        "packageManager": "the package manager",
       |        "semver": {
       |          "unaffected": ">=the version",
       |          "vulnerable": "<the version"
       |        },
       |        "publicationTime": "2015-11-06T02:09:36.182Z",
       |        "disclosureTime": "2015-11-03T07:15:12.900Z",
       |        "isUpgradable": true,
       |        "isPatchable": true,
       |        "identifiers": {
       |          "CVE": [],
       |          "CWE": [],
       |          "NSP": 57,
       |          "ALTERNATIVE": [
       |            "5555555555"
       |          ]
       |        },
       |        "credit": [
       |          "Mickey Mouse"
       |        ],
       |        "CVSSv3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
       |        "cvssScore": 7.5,
       |        "patches": [
       |          {
       |            "id": "6666666666",
       |            "urls": [
       |              "https://example.com/6666666666.patch"
       |            ],
       |            "version": "<the version >=minversion",
       |            "comments": [
       |              "https://example.com/7777777777.patch"
       |            ],
       |            "modificationTime": "2015-11-17T09:29:10.000Z"
       |          }
       |        ],
       |        "upgradePath": [
       |          true,
       |          "the first upgrade",
       |          "the second upgrade"
       |        ]
       |      }
       |    ],
       |    "licenses": []
       |  },
       |  "dependencyCount": 0,
       |  "packageManager": "the package manager"
       |}
     """.stripMargin


    "find ok for non-empty list" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockGoodButVulnerableResponse))
      projects.value().head.ok shouldBe false
    }
    "find high count for non-empty list" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockGoodButVulnerableResponse))
      projects.value().head.high shouldBe 1
    }
    "find medium count for non-empty list" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockGoodButVulnerableResponse))
      projects.value().head.medium shouldBe 0
    }
    "find low count for non-empty list" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockGoodButVulnerableResponse))
      projects.value().head.low shouldBe 0
    }
  }

  "fail to find vulnerability list" - {
    "bad response" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(s"""response is not json!"""))
      projects.isFailedAttempt shouldBe true
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (response is not json!)"
    }
    "fail to find vulnerability list with error message - fails" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockBadResponseWithMessage))
      projects.isFailedAttempt() shouldBe true
    }
    "fail to find vulnerability list with error message - has message" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockBadResponseWithMessage))
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe "Could not read Snyk response (some nice error)"
    }
    "fail to find vulnerability list without error message - fails" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockBadResponseWithoutMessage))
      projects.isFailedAttempt() shouldBe true
    }
    "fail to find vulnerability list without error message - has message" in {
      val projects = SnykDisplay.parseProjectVulnerabilities(List(mockBadResponseWithoutMessage))
      projects.getFailedAttempt.failures.head.friendlyMessage shouldBe """Could not read Snyk response ({"toughluck": "no use"})"""
    }
  }

  "label organisation" - {
    val goodOrganisation = SnykOrganisation("name0", "id0")
    val goodProjects = List(
      SnykProject("name1", "id1", None),
      SnykProject("name2", "id2", None)
    )

    "label organisation - first id" in {
      val results = SnykDisplay.labelOrganisations(goodProjects, goodOrganisation)
      results.head.organisation.get.id shouldBe "id0"
    }
    "label organisation - first name" in {
      val results = SnykDisplay.labelOrganisations(goodProjects, goodOrganisation)
      results.head.organisation.get.name shouldBe "name0"
    }
    "label organisation - second id" in {
      val results = SnykDisplay.labelOrganisations(goodProjects, goodOrganisation)
      results.tail.head.organisation.get.id shouldBe "id0"
    }
    "label organisation - second name" in {
      val results = SnykDisplay.labelOrganisations(goodProjects, goodOrganisation)
      results.tail.head.organisation.get.name shouldBe "name0"
    }
  }

  "label projects" - {
    val goodProjects = List(
      SnykProject("name1", "id1", None),
      SnykProject("name2", "id2", None)
    )

    val goodVulnerabilities = List(
      SnykProjectIssues(None, ok = false, Set[SnykIssue]()),
      SnykProjectIssues(None, ok = false, Set[SnykIssue]())
    )

    "label projects - first id" - {
      val results = SnykDisplay.labelProjects(goodProjects, goodVulnerabilities)
      results.head.project.get.id shouldBe "id1"
    }

    "label projects - first name" in {
      val results = SnykDisplay.labelProjects(goodProjects, goodVulnerabilities)
      results.head.project.get.name shouldBe "name1"
    }

    "label projects - second id" in {
      val results = SnykDisplay.labelProjects(goodProjects, goodVulnerabilities)
      results.tail.head.project.get.id shouldBe "id2"
    }

    "label projects - second name" in {
      val results = SnykDisplay.labelProjects(goodProjects, goodVulnerabilities)
      results.tail.head.project.get.name shouldBe "name2"
    }
  }

  "sort projects" - {
    "All equal except number of high risk issues" in {
      val sortedProjects = SnykDisplay.sortProjects(
        List(
          SnykProjectIssues(
            Some(SnykProject("X", "b", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue2", "3", "low")
            )
          ),
          SnykProjectIssues(
            Some(SnykProject("X", "a", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "high"),
              SnykIssue("Issue2", "3", "medium"),
              SnykIssue("Issue2", "3", "low")
            )
          )
        )
      ).map(spi => spi.project.get.id) shouldBe List[String]("a", "b")
    }
    "All equal except number of medium risk issues" in {
      val sortedProjects = SnykDisplay.sortProjects(
        List(
          SnykProjectIssues(
            Some(SnykProject("X", "b", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "low")
            )
          ),
          SnykProjectIssues(
            Some(SnykProject("X", "a", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "medium"),
              SnykIssue("Issue4", "4", "low")
            )
          )
        )
      ).map(spi => spi.project.get.id) shouldBe List[String]("a", "b")
    }
    "All equal except number of low risk issues" in {
      val sortedProjects = SnykDisplay.sortProjects(
        List(
          SnykProjectIssues(
            Some(SnykProject("X", "b", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "low")
            )
          ),
          SnykProjectIssues(
            Some(SnykProject("X", "a", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "low"),
              SnykIssue("Issue4", "4", "low")
            )
          )
        )
      ).map(spi => spi.project.get.id) shouldBe List[String]("a", "b")
    }
    "All equal except name" in {
      val sortedProjects = SnykDisplay.sortProjects(
        List(
          SnykProjectIssues(
            Some(SnykProject("Y", "b", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "low")
            )
          ),
          SnykProjectIssues(
            Some(SnykProject("X", "a", Some(SnykOrganisation("guardian", "guardian")))),
            ok = true,
            Set(
              SnykIssue("Issue1", "1", "high"),
              SnykIssue("Issue2", "2", "medium"),
              SnykIssue("Issue3", "3", "low")
            )
          )
        )
      ).map(spi => spi.project.get.id) shouldBe List[String]("a", "b")
    }
  }

}