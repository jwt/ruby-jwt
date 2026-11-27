# Contributing to [ruby-jwt](https://github.com/jwt/ruby-jwt)

## Forking the project

Fork the project on GitHub and clone your own fork. Instructions on forking can be found from the [GitHub Docs](https://docs.github.com/en/get-started/quickstart/fork-a-repo)

```bash
git clone git@github.com:you/ruby-jwt.git
cd ruby-jwt
git remote add upstream https://github.com/jwt/ruby-jwt
```

## Create a branch for your implementation

Make sure you have the latest upstream main branch of the project.

```bash
git fetch --all
git checkout main
git rebase upstream/main
git push origin main
git checkout -b fix-a-little-problem
```

## Running the tests and linter

Before you start with your implementation make sure you are able to get a successful test run with the current revision.

The tests are written with rspec and [Appraisal](https://github.com/thoughtbot/appraisal) is used to ensure compatibility with 3rd party dependencies providing cryptographic features.

[RuboCop](https://github.com/rubocop/rubocop) is used to enforce the Ruby style.

To run the complete set of tests and linter run the following

```bash
bundle install
bundle exec appraisal rake test
bundle exec rubocop
```

## Implement your feature

Implement tests and your change. Don't be shy adding a little something in the [README](README.md).

Don't edit the [CHANGELOG](CHANGELOG.md). It's generated from the pull request titles when a release is made.

## Push your branch and create a pull request

Before pushing make sure the tests pass and RuboCop is happy.

```bash
bundle exec appraisal rake test
bundle exec rubocop
git push origin fix-a-little-problem
```

Make a new pull request on the [ruby-jwt project](https://github.com/jwt/ruby-jwt/pulls) with a description what the change is about.

Title the pull request in the [Conventional Commits](https://www.conventionalcommits.org/) format, for example `fix: Reject tokens with too many segments`. Pull requests are squash merged, so the title becomes the commit message, and the changelog is generated from it. Write the description as it should read in the changelog. Use one of these types:

- `feat` for a new feature, which leads to a minor release
- `fix` for a bug fix, which leads to a patch release
- `perf`, `refactor`, `docs`, `test`, `ci`, `build`, `chore` or `revert` for everything else

Add `!` after the type, as in `feat!:`, for a breaking change, which leads to a major release. A check on the pull request verifies the format, and maintainers may adjust the title before merging.

## Keep an eye on your pull request

A maintainer will review and probably merge you changes when time allows, be patient.

## Keeping your branch up-to-date

It's recommended that you keep your branch up-to-date by rebasing to the upstream main.

```bash
git fetch upstream
git checkout fix-a-little-problem
git rebase upstream/main
git push origin fix-a-little-problem -f
```

## Releasing a new version

Releases are made with [release-please](https://github.com/googleapis/release-please). The version follows [Semantic Versioning](http://semver.org/) and is picked from the pull request titles merged since the last release: `fix` and `perf` lead to a patch release, `feat` to a minor release, and a `!` after the type to a major release.

After each merge to main, the [release-please.yml](.github/workflows/release-please.yml) workflow opens or updates a release pull request. It bumps the version in [version.rb](lib/jwt/version.rb) and adds a section to the [CHANGELOG](CHANGELOG.md) with an entry for each `feat`, `fix`, `perf` and `revert` pull request. Other types are left out. Edit a pull request's title before merging it if the changelog entry should read differently.

To release, merge the release pull request. The workflow then tags the merge commit, creates the GitHub release, and calls [push_gem.yml](.github/workflows/push_gem.yml), which verifies that the tag matches `JWT.gem_version`, builds the gem, pushes it to RubyGems using trusted publishing and waits for it to propagate. No RubyGems credentials are needed on your machine.

If publishing fails, fix the cause and run the **Push Gem** workflow manually with the tag as input to publish it again.

Do not use `rake release`. It builds and pushes the gem from your machine, which bypasses trusted publishing.

### Releasing 2.x

The `2-10-stable` branch is released by hand. Bump the version in [version.rb](lib/jwt/version.rb), add a section to the [CHANGELOG](CHANGELOG.md) and merge it, then tag the merged commit and push the tag:

```bash
git tag -a v2.10.4 -m "Version 2.10.4"
git push upstream v2.10.4
```

Pushing the tag runs [push_gem.yml](.github/workflows/push_gem.yml) on the branch. Then [create a GitHub release](https://github.com/jwt/ruby-jwt/releases/new) for the tag.
