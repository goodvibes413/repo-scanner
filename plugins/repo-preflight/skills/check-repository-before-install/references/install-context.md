# Install Context

Collect only names and categories, never secret values.

Recommended fields:

```yaml
intended_command: "npm install"
runtime: "local-development"
operating_system: "macos"
credential_names:
  - GITHUB_TOKEN
  - NPM_TOKEN
  - OPENAI_API_KEY
local_resources:
  - project_directory
  - home_directory
  - docker_socket
  - github_cli
  - cloud_cli
```

Common local resources:

- `project_directory`
- `home_directory`
- `docker_socket`
- `github_cli`
- `cloud_cli`
- `ssh_keys`
- `npm_token`
- `browser_profile`

If the user does not know which credentials are available, ask for the names they commonly keep in `.env`, shell profiles, cloud CLIs, package-manager auth, and agent configuration.
