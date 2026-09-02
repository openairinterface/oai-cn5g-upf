<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| develop | :white_check_mark: |

## Reporting a Vulnerability

We strongly encourage you to report security vulnerabilities first to our
contact address,
[oaicicd@openairinterface.org](mailto:oaicicd@openairinterface.org), before
disclosing them in any public forum. This email address is shared by all OAI
CN5G components, so make sure to keep the network function name in the
subject.

Reports sent to this address are handled confidentially by members of
the OAI security team and are treated as a top priority.

- **Email subject**: `[SEC-VUL-OAI-CN5G-UPF]: "Mention the affected
  functionality here"`.
- **Affected commit**: provide the commit SHA where the vulnerability was
  observed. This should normally be the latest commit or a recent commit at the
  time of the report. If a shared submodule is affected, mention its commit SHA
  as well.
- **Vulnerability description**: please keep it concise and avoid unnecessary
  detail. Present a clear summary of the vulnerability and its impact first,
  followed by the affected files, versions, and other relevant details.
- **Affected functionality and file paths**.
- **Discovery and reproduction information**: how did you discover the problem,
  and how can it be reproduced?
- **AI tool disclosure**: please mention and explain whether you have used any
  AI tool to generate this report or to find the vulnerability. If you used one
  to find the vulnerability, please see the next section. The tool should be
  reported as `TOOL-NAME: LLM-MODEL-VERSION`, for example
  `Claude:claude-5-opus`.
- **Relevant environment details**: CPU, RAM, hard disk, kernel command-line
  parameters, operating system name, and kernel version.
- **Relevant log excerpts**: do not attach any large files, just an extract of
  the logs if needed. We may request the full logs later.
- **Proposed patch, if available**: we encourage you to share a tentative patch
  if you have one.

### Use of AI to find a vulnerability

If an AI tool was used to identify or discover the vulnerability, do not submit
the vulnerability through the email. Instead, report it as a public GitHub issue
in the
[GitHub Issue Tracker](https://github.com/openairinterface/oai-cn5g-upf/issues),
because multiple researchers using the same or different AI tools can find the
same vulnerability.

In this case, please follow the format below to open the issue:

- **Issue title**: `[AI-SEC-VUL-OAI-CN5G-UPF]: "Mention the affected
  functionality here"`.
- **Issue label**: apply the
  https://github.com/openairinterface/oai-cn5g-upf/labels/security
  label when opening the issue.
- **Affected commit**: provide the commit SHA where the vulnerability was
  observed. This should normally be the latest commit or a recent commit at the
  time of the report. If a shared submodule is affected, mention its commit SHA
  as well.
- **Vulnerability description**: please keep it concise. Reports generated or
  assisted by AI tools often contain excessive detail or too many sections,
  which makes the important information hard to identify. Present a clear
  summary of the vulnerability and its impact first, followed by the affected
  files, versions, and other relevant details.
- **Affected functionality and file paths**.
- **Reproduction information**: do not mention how to reproduce the problem in
  the issue description. The security team will contact you about it.
- **AI tool disclosure**: please mention and explain whether you have used any
  AI tool to find the vulnerability. It should be reported as
  `TOOL-NAME: LLM-MODEL-VERSION`, for example `Claude:claude-5-opus`.
- **Relevant environment details**: CPU, RAM, hard disk, kernel command-line
  parameters, operating system name, and kernel version.
- **Relevant log excerpts**: do not attach any large files, just an extract of
  the logs if needed. We may request the full logs later.
- **Proposed patch, if available**: AI tools are good at fixing vulnerabilities;
  you can ask your AI tool to provide a patch.

## Scope

The [openairinterface/oai-cn5g-upf](https://github.com/openairinterface/oai-cn5g-upf)
repository contains the OAI implementation of the 5G Core **User Plane
Function (UPF)**, together with its eBPF/XDP datapath, configuration templates,
container images, deployment artifacts, and CI tooling. Only the 5G Core is in
scope in this repository.

Issues in the other OAI CN5G network functions (AMF, SMF, AUSF, UDM, UDR, NRF,
PCF, NSSF, NEF, LMF, NWDAF), in the federation repository
[openairinterface/oai-cn5g-fed](https://github.com/openairinterface/oai-cn5g-fed),
or in the Duranta OAI codebase
[duranta-project/openairinterface5g](https://github.com/duranta-project/openairinterface5g)
must be reported against those repositories.

Issues in the shared submodules
([oai-cn5g-common-src](https://github.com/openairinterface/oai-cn5g-common-src),
[oai-cn5g-common-build](https://github.com/openairinterface/oai-cn5g-common-build)
and [oai-cn5g-common-ci](https://github.com/openairinterface/oai-cn5g-common-ci))
can be reported here if they are reachable through the UPF. In that case, please
state clearly which component is affected and give the commit ID of the affected
submodule in addition to the UPF commit.

Security reports are in scope when they affect the confidentiality, integrity,
or availability of the UPF running in a documented or reasonably expected
deployment.

In-scope examples include:

- Memory corruption, out-of-bounds access, verifier bypasses, kernel panics, or
  denial of service in the eBPF/XDP datapath. The programs in
  [src/upf_app/kernel/](./src/upf_app/kernel) parse Ethernet, IP, UDP, and
  GTP-U headers in kernel space on the N3 and N6 entry paths and apply the
  matched PFCP rules, so a defect there affects the host kernel and not only
  the UPF process. This is the most severe class of issue in this repository.
- Memory corruption, crashes, or denial of service triggered by malformed or
  unexpected GTP-U packets on N3 (UDP port 2152, 3GPP TS 29.281), including the
  outer headers, the GTP-U header and its extensions, and the inner user packet.
  These arrive from the gNB and carry UE-controlled content, so both a malicious
  gNB and a malicious UE are realistic sources.
- Defects that break user plane isolation, such as TEID or SEID confusion,
  session lookup collisions, or packet detection rule matching errors that let
  traffic cross between PDU sessions or subscribers, reach the data network
  when it should not, or be delivered to a tunnel belonging to another UE.
- Memory corruption, crashes, or denial of service triggered by malformed or
  unexpected PFCP messages on N4 (UDP port 8805, 3GPP TS 29.244), and defects
  in session establishment, modification, or deletion that let forwarding
  rules be installed so that subscriber traffic is duplicated, redirected, or
  intercepted.
- Bypass of the QoS enforcement rules implemented through TC-BPF, where a
  subscriber can exceed a configured maximum bit rate or obtain a QoS flow
  treatment it was not granted.
- Exposure of subscriber traffic content, allocated UE IP addresses, TEIDs,
  SEIDs, or session state through logs, statistics, or error paths, and
  defects in parsing the NRF responses the UPF consumes when registering.
- Remote code execution, privilege escalation, or arbitrary file access,
  including any path where externally influenced input reaches the loading or
  configuration of the datapath programs, which requires elevated privileges on
  the host.
- Container image or default-configuration issues in [docker/](./docker),
  [etc/](./etc), and [openshift/](./openshift) that expose sensitive services or
  secrets, disable important security controls, or grant unsafe privileges in
  documented or reasonably expected deployments.
- CI, build, or release-pipeline issues that could compromise official OAI
  release artifacts, published container images, or the trusted source
  distribution.

Out-of-scope examples include:

- Performance issues without a security impact.
- Bugs requiring local admin/root access on the UPF host with no privilege
  boundary crossed.
- Reports against unsupported forks, private deployments, local lab
  misconfiguration, or modified code not present in this repository.
- Vulnerabilities solely caused by third-party projects or dependencies should
  generally be reported upstream. If the vulnerability affects the security of
  the UPF deployment or requires a change in this repository, please report it
  here as well.
- Attacks that require a trusted operator role, such as an already-authorised
  SMF deliberately misconfigured by the deployment owner, unless a documented
  trust boundary is crossed.
- Denial of service that only depends on flooding a plaintext, unprotected
  transport (for example, running N3 or N4 without IPsec) as permitted by the
  deployment, rather than on a UPF software defect.
- Features documented as not supported in
  [FEATURE_SET.md](./docs/FEATURE_SET.md), or issues in experimental or
  incomplete functionality, unless they demonstrate a realistic impact on
  supported deployments.
- Issues only affecting contributor CI jobs, temporary development artifacts, or
  untrusted test images, unless they can affect official releases.

## Disclosure

The project aims to acknowledge all contributors for valid reports of security
vulnerabilities. Each vulnerability sent to the security contact address will,
after review and if accepted, be handled through a draft GitHub Security
Advisory, and a CVE ID may be assigned as part of that process. Reporters will
be credited by name or GitHub handle in the advisory. Disclosure will typically
be made at or shortly after the release of the fix.

The security team will decide whether a report meets the requirements for a
GitHub advisory and CVE ID on a case-by-case basis.

Some reports may lead to changes in the OAI CN5G codebase even if they do not
result in an associated advisory. Examples of reports that may fall into this
category include (but are not limited to):

- Reports of vulnerabilities in unstable functionality or incomplete features.
- Reports of vulnerabilities where there is no evidence that a recent OAI CN5G
  release tag has been affected.

In such cases, the project aims to credit reporters with an acknowledgement in
the relevant fix commit via a `Reported-by:` trailer in the commit message.

**NOTE**: The OAI project manages CVEs only via the
[GitHub security advisory database](https://github.com/advisories).
If you have already requested or obtained a CVE identifier from
[CVE.org](https://www.cve.org/ReportRequest/ReportRequestForNonCNAs) or another
CVE Numbering Authority, please provide it to the security team so that the
project can coordinate the affected advisory and ensure that the published
information accurately reflects the final fix and impact.

### Timeline

After receiving the report, the team will validate the vulnerability and will
respond to the reporter within 10 days. The project aims to publish the advisory
with the fix within 90 days of receiving the report, where reasonably
practicable.
