# Tuning lessons: noise, suppressions and what to protect

These notes come from tuning a real Wazuh 4.x deployment over several months. They explain why NoiseLens measures what it measures. Examples use invented values. Where something was not confirmed, it says so.

## Measure first, then suppress

The most useful step was replaying several days of alerts through a candidate suppression and counting exactly what it would remove and what would survive. That turned a guess into a number. In one case it also showed that a tempting pattern would have hidden a real detection path. That is what a proposed policy and the protected-alert guard are for.

## Where noise usually comes from

**A short list of directories.** In one analysis, file integrity alerts were about a third of everything the SIEM wrote, and roughly ninety percent of those came from three machines, all of it tool and developer churn in a handful of working directories. About eight ignore entries removed over ninety nine percent of it without touching a security relevant path.

Use that shape on your own data:

```sh
noiselens alerts.jsonl --json out.json --breakdown 100500:syscheck.path --path-depth 3
```

The running share column shows how few directories carry most of the volume. The rule groups table in the report shows how much of your total is file integrity versus authentication, so you do not suppress one while thinking about the other.

**One machine, not the whole fleet.** When a single agent produces most of a category, a fix scoped to that agent beats a fleet wide suppression.

## Choose the narrowest thing that works

- **Narrow beats broad, and lowering a level beats deleting.** A level of 0 keeps the event in the archive and keeps the tuning visible later. Deleting leaves no trace that anyone made a decision.
- **Prefer narrowing what is watched over listing what to ignore.** A broad watch plus a long ignore list creates a new ignore entry every time a tool is installed. An explicit list of paths that signal compromise (accounts, privilege files, remote access configuration, persistence locations, binary drop directories) was shorter and more stable.
- **Ignore wins over watch.** If a parent directory is ignored, nothing under it is monitored, even with a more specific watch entry. Scope the ignore to the noisy subdirectory.

## Things that look safe and are not

**Numeric account IDs.** A suppression on a user ID looked clean until the ID was checked host by host. It was a different account on nearly every machine, including the monitoring agent's own account and the web server's. A fleet wide suppression would have hidden real activity. Check what an identifier means on every host first. NoiseLens matches exact values, so a policy keyed to an ID needs this check from you.

**Tuning pinned to an address or hostname.** A rule that downgraded expected findings from one authorised source was keyed to that machine's address. The machine was rebuilt on a new address and the rule quietly stopped matching. Nothing alerted. Re-run the analysis now and then and check that every suppression still matches something.

**Your own tooling.** A high severity rule fired on every host within two minutes, and the cause was the team's own scanning script. Check whether a fleet wide simultaneous hit lines up with your own activity before raising an alarm. Exclude that window from the export you analyze, so self inflicted alerts do not look like findings.

## Reading the export honestly

- **Which file did you read?** The live `alerts.json` rotates when the manager restarts, so an analysis right after a restart looks almost empty because the day's data moved to the rotated archive. NoiseLens prints the time range it actually found, in UTC, so you can see what window the numbers describe. Decompress rotated `.gz` archives first (reading them directly is an [open issue](https://github.com/farhan6667/wazuh-noiselens/issues/1) if you would like to help).
- **Timezones.** One incident carried a local timestamp on the alert, UTC inside the raw log text, and an explicit offset in a web server log. NoiseLens reads the alert `timestamp` with any offset and reports its range in UTC.
- **Source addresses are often missing.** A large share of successful authentication alerts had no source address, depending on the decoder. Do not build a suppression that assumes one.
- **Count, do not sample.** Dashboard summary endpoints can report numbers from a capped sample of documents. NoiseLens counts every alert in the file you give it.

## What to protect

A starting list for `protect_rule_ids` and `protected_level`, to adapt to your estate: remote access configuration changes, account and privilege file changes, new keys in an authorised keys file, persistence locations, binary drop directories, and rule groups for authentication success after repeated failures. The guard exits with 1 when a proposed suppression would hide one of these in your data.

A pass only means no protected alert matched in this dataset. It is not proof that an exception is safe on traffic you have not seen.
