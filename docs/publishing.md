# Publishing the source repository

The repository uses Apache-2.0 for its original files. The GitHub workflows validate source and deployment behavior; they do not push images or provision external servers. Keep local runtime state outside Git.

## Local review

```sh
git status --short
git diff --cached --stat
git diff --cached --check
python3 scripts/check-publication.py
```

The publication checker reads the complete Git index, so stage intended changes before running it. It rejects private state/inventories, oversized artifacts and several high-confidence credential patterns without printing matching values. It does not scan previous history or detect every possible credential. This project starts with a new local repository; inspect history separately if importing it into an older repository.

`.gitignore` excludes `.local/`, private keys, databases, logs and production inventory overrides. `.dockerignore` permits only the required CMake, C++ and image recipe inputs. Review newly added files even when these guards pass. Synthetic UUIDs and example.com/documentation IP addresses in tests and examples are intentional.

## First push

Check the Git author identity you want to make public before creating the initial commit:

```sh
git var GIT_AUTHOR_IDENT
git commit -m "Initial VLESS mesh implementation and deployment tooling"
```

Create an empty repository on GitHub using the visibility you intend. Do not initialize a second README or license there. Then use the repository's actual SSH URL:

```sh
git remote add origin git@github.com:OWNER/REPOSITORY.git
git push -u origin main
```

`OWNER/REPOSITORY` is a placeholder. Repository creation, visibility selection, remote configuration and the push are operator steps; local preparation does not publish anything.

After the first push, inspect the CI results and run the manual integration workflow from Actions. Configure branch protection against the checks that actually appear, and enable [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository) so the reporting path in SECURITY.md is available. No hosted CI result is claimed until those workflows run on GitHub.

## Container releases

Source publication and container distribution have different packaging requirements. Before pushing built images to a registry, complete the exact-artifact license/notice and corresponding-source work described in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Record immutable image digests and architecture-specific test results. The local verification reports are evidence for their stated environment, not a production support promise.
