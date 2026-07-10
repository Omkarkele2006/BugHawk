# GitHub Actions Workflows

This folder is a placeholder for GitHub Actions CI/CD workflow configurations.

## Future Scope

Planned workflows for this folder include:
* **`ci.yml` (Continuous Integration):**
  * Triggered on every pull request to `main`.
  * Installs dependencies for Frontend and Backend.
  * Runs pre-commit checks (`black` formatting, `flake8` lint checks, YAML verification).
  * Executes Python test suites (via `pytest`).
* **`docker-publish.yml` (Continuous Deployment):**
  * Triggered on new version tag releases.
  * Builds Frontend and Backend docker images.
  * Pushes images to GitHub Container Registry (GHCR) or Docker Hub.
