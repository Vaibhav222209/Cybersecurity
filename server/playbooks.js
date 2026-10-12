// Guidance for the authorized local lab. Production response requires the
// organization's incident commander, change process, and evidence procedures.
const step = (id, phase, title, description) => ({
  id,
  phase,
  title,
  description,
  completed: false,
});

export const playbooks = [
  {
    id: 'pb-brute-force',
    title: 'Credential attack response',
    description: 'Investigate repeated authentication failures, contain the source, and verify that legitimate access still works.',
    standard: 'NIST SP 800-61 Rev. 3 / CSF 2.0; MITRE ATT&CK T1110 (Brute Force), T1078 (Valid Accounts)',
    steps: [
      step('bf-prepare', 'Prepare', 'Confirm scope and access owners', 'Record the authorized lab workstation, authentication baseline, responder roles, and rollback plan. For production, confirm identity-service ownership and approved emergency access before changing account or firewall policy.'),
      step('bf-detect', 'Detect', 'Correlate failed and successful logins', 'Review live authentication events for a burst of failures from one source or against many accounts. Correlate threat-intelligence matches, timestamps, and a subsequent successful login; an IOC match alone is not proof of compromise.'),
      step('bf-triage', 'Triage', 'Preserve evidence and assess impact', 'Record incident time, source, affected workstation, user, and supporting event IDs. Preserve the original logs, determine whether any login succeeded, and assign severity using business impact. Escalate suspected account compromise to the incident commander.'),
      step('bf-contain', 'Containment', 'Block the source and protect access', 'Apply the lab source-block action and confirm that new matching authentication attempts are denied while their evidence remains visible. Quarantine a lab workstation if compromise is supported by evidence. In production, obtain response approval, restrict the smallest necessary scope, and preserve an emergency management path.'),
      step('bf-eradicate', 'Eradication', 'Remove compromised access', 'For confirmed compromise, revoke affected sessions, rotate the account credentials, review persistence and unauthorized accounts, and enforce MFA and rate limiting through the identity owner. Do not reset unrelated accounts based only on failed-login noise.'),
      step('bf-recover', 'Recovery', 'Verify denial and legitimate login', 'Generate another authentication attempt in the lab and verify that the blocked source cannot proceed; verify permitted activity still works. Review the successful-login trail, monitor for recurrence, and restore access only after the owner approves and recovery criteria are met.'),
      step('bf-lessons', 'Lessons learned', 'Record findings and improve controls', 'Document the timeline, evidence, decisions, response latency, and rollback outcome. Tune the correlation threshold, rate limiting, and account protections. Assign owners and due dates, and review the playbook after the incident.'),
    ],
  },
  {
    id: 'pb-malware',
    title: 'Malware and workstation containment',
    description: 'Validate a suspicious execution or malicious indicator, isolate the affected workstation, and recover from a trusted state.',
    standard: 'NIST SP 800-61 Rev. 3 / CSF 2.0; MITRE ATT&CK T1059 (Command and Scripting Interpreter), T1105 (Ingress Tool Transfer)',
    steps: [
      step('mal-prepare', 'Prepare', 'Prepare isolation and trusted recovery', 'Confirm the authorized lab workstation, evidence location, recovery baseline, and release criteria. For production, test endpoint isolation and backup restoration with the endpoint owner; establish responder roles and an approved communication channel.'),
      step('mal-detect', 'Detect', 'Validate the suspicious indicator', 'Correlate suspicious execution, file hashes, destination indicators, and workstation activity. Check indicator provenance, confidence, and expiry. Preserve the original event and distinguish a simulated lab indicator from independently confirmed malware.'),
      step('mal-triage', 'Triage', 'Scope the incident and preserve evidence', 'Capture the affected host, event IDs, time window, process context, and observable indicators. Assess whether other hosts or credentials are affected. Use approved evidence collection procedures; do not execute the suspicious file to investigate it.'),
      step('mal-contain', 'Containment', 'Quarantine the affected workstation', 'Use the lab quarantine action to stop workload traffic and retain incident records; verify that blocked activity is still logged. For production, obtain response authorization, isolate with the endpoint platform, preserve the management channel when safe, and evaluate operational impact before isolating critical systems.'),
      step('mal-eradicate', 'Eradication', 'Remove the cause from a trusted state', 'In the lab, remove the identified suspicious fixture or insecure configuration and recheck the finding. For confirmed production compromise, remove persistence through approved tooling or rebuild from a trusted image, patch the entry point, and rotate credentials exposed on the host.'),
      step('mal-recover', 'Recovery', 'Verify health before releasing isolation', 'Repeat the relevant lab check and confirm the suspicious activity no longer occurs. Validate trusted application behavior and continued telemetry before releasing the lab workstation. Production release requires endpoint-owner approval, restored controls, and a period of heightened monitoring.'),
      step('mal-lessons', 'Lessons learned', 'Capture containment and recovery evidence', 'Record the timeline, evidence references, isolation and release decisions, verification results, and any remaining uncertainty. Improve detections and endpoint controls, assign corrective work, and revise backup and recovery procedures.'),
    ],
  },
  {
    id: 'pb-recon',
    title: 'Reconnaissance and exposure remediation',
    description: 'Investigate service probing, verify authorized vulnerability findings, and validate a practical mitigation in the local lab.',
    standard: 'NIST SP 800-61 Rev. 3 / CSF 2.0; MITRE ATT&CK T1046 (Network Service Discovery)',
    steps: [
      step('recon-prepare', 'Prepare', 'Define authorized assessment scope', 'Record the local lab target, allowed checks, assessment window, owner, and rollback plan. Production VAPT requires written authorization, named assets, exclusions, and rules of engagement; do not scan arbitrary systems or infer permission from network reachability.'),
      step('recon-detect', 'Detect', 'Identify probing and exposed services', 'Review service-discovery or repeated connection events and correlate the source with authorized assessment activity. Run the supported local vulnerability checks against the lab only, and retain the observed evidence for each finding.'),
      step('recon-triage', 'Triage', 'Verify findings and prioritize impact', 'Distinguish configuration observations from confirmed vulnerabilities; a version banner alone does not establish exploitability. Record the affected service, evidence, exposure, severity, and applicable advisory or control reference. Prioritize using asset importance and actual exposure.'),
      step('recon-contain', 'Containment', 'Reduce immediate exposure', 'Block the suspicious source in the lab and verify subsequent connection attempts are denied and logged. If exploitation is supported by evidence, isolate the lab workstation. Production restrictions require the service owner, approved change scope, dependency review, and a rollback path.'),
      step('recon-eradicate', 'Eradication', 'Apply the verified mitigation', 'Use the supported lab mitigation for the selected finding, such as removing a sensitive exposed fixture or adding the missing security control. For production, deploy the vendor-supported patch or configuration fix through change control; preserve a rollback plan and test dependent applications.'),
      step('recon-recover', 'Recovery', 'Rescan and prove the fix', 'Rerun the same authorized local check and retain the before-and-after evidence. Confirm that the finding is resolved and legitimate service behavior still works. Release temporary restrictions only when recovery criteria and owner approval are satisfied.'),
      step('recon-lessons', 'Lessons learned', 'Close the exposure and track residual risk', 'Record the assessment scope, finding evidence, mitigation, validation result, and unresolved exposure. Assign an owner and due date to residual risk, update hardening baselines, and improve detection of repeated probing.'),
    ],
  },
];
