# Validation

The current local instance was checked using Node.js 24, SQLite, and Chromium. Installation with the frozen npm lockfile and the production Vite build both completed successfully.

## Backend integration suite

`npm test` ran eight tests: **8 passed, 0 failed, 0 skipped**.

- Imported intelligence matching and evidence provenance.
- Five failed authentications correlated into an incident.
- Source block/unblock, isolation, quarantine, and restoration verified with real workload requests.
- Actual HTTP scanning, three practical mitigations, and independent repeat scans.
- Lab scenarios issuing real localhost requests and observing deny rules.
- SQLite persistence across server restarts.
- Input validation, atomic batch rejection, token checks, Origin checks, and rejection of arbitrary scan targets.
- Server-sent events transmitting newly ingested telemetry.

## Browser and collector checks

Chromium exercised the built application through a separate test database. It verified live event growth, log filtering and evidence inspection, pause/resume, application of security headers and repeat assessment, reversible asset containment, indicator import, real Python collector forwarding and live IOC detection, source blocking/unblocking, incident investigation, playbook checkbox persistence and reopening, and operation audit visibility.

All eight navigation destinations were checked at desktop and mobile sizes. No JavaScript errors or horizontal page overflow remained. Opened detail panels, the indicator form, and containment confirmations were also checked. Playbook controls were checked for immediate feedback and rollback on a failed save.

The production build serves the dashboard through the Node API. The main development instance was checked again after repeatable installation: its frontend, proxied health/state API, four lab assets, three playbooks, and actual workload response remained available.

These checks demonstrate the local security lab and collection workflow. They do not validate external endpoint/firewall enforcement, a commercial threat feed, arbitrary target scanning, or an enterprise deployment.
