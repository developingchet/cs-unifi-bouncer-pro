# Support

## Usage questions and setup help

Start with [docs/SETUP.md](docs/SETUP.md), the [configuration reference](docs/CONFIGURATION.md) and [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). If those do not answer the question, open a [Question / Support issue](https://github.com/developingchet/cs-unifi-bouncer-pro/issues/new?template=question.yml) with the release version, install mode, UniFi Network version, CrowdSec version and what has already been tried.

Remove API keys, controller addresses and private network details from any configuration or logs before posting them. The daemon masks known secrets in its own output, but a pasted `.env` file or a raw controller response is not masked.

## Bugs and feature requests

Use the [Bug Report](https://github.com/developingchet/cs-unifi-bouncer-pro/issues/new?template=bug_report.yml) form for wrong behaviour, the [Bouncer / CrowdSec Integration Issue](https://github.com/developingchet/cs-unifi-bouncer-pro/issues/new?template=bouncer_issue.yml) form for LAPI, decision stream or firewall-mode problems, and the [Feature Request](https://github.com/developingchet/cs-unifi-bouncer-pro/issues/new?template=feature_request.yml) form for proposed changes. Issue forms are the public intake; this repository does not use GitHub Discussions.

## Security reports

Do not report a vulnerability in a public issue. Use [private vulnerability reporting](https://github.com/developingchet/cs-unifi-bouncer-pro/security/advisories/new) and follow [SECURITY.md](SECURITY.md) for scope, reproduction limits and response targets.

## Upstream problems

Problems in CrowdSec LAPI itself, in UniFi firmware or in the UniFi Network API belong with CrowdSec and Ubiquiti respectively. The bouncer's own scope is described in [SECURITY.md](SECURITY.md#vulnerability-scope). Third-party blocklists and their contents are governed by their own providers.

## Responses

Issues are reviewed as time allows. Include the output of `cs-unifi-bouncer-pro version` and the relevant sanitized logs so a question can be answered without a second round of requests.
