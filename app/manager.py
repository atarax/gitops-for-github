import logging
import math
import os
import re
import time

import yaml
from deepdiff import DeepDiff
from tqdm import tqdm

loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=loglevel,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gg")

tqdm_disable = False if logging.root.level <= logging.INFO else True


class PermissionManager:
    escalations = ["admin", "maintain", "push", "triage", "pull"]

    def __init__(self, g, org):
        self.g = g
        self.org = org

    def rate_limited(self, fn, *args, **kwargs):
        requests_left = self.g.rate_limiting[0]

        if requests_left < 10:
            rl_reset_time = self.g.rate_limiting_resettime
            cur_time = time.time()
            sleep_time = math.floor(rl_reset_time - cur_time)

            logger.info(f"Sleeing {sleep_time} seconds to wait for rate-limit reset...")
            time.sleep(sleep_time)

        return fn(*args, **kwargs)

    def validate_item(self, item):
        if item not in self.escalations:
            raise InvalidPermissionException(
                f"{item} should be one of: {self.escalations}"
            )

    def parse_permissions(self, permissions):
        for level in self.escalations:
            if getattr(permissions, level):
                return level

        raise Exception("Illegal permissions-object")

    def get_user_collaborators(self, repos, tqdm_disable=tqdm_disable):
        return {
            repo: permissions
            for repo, permissions in {
                r.name: {
                    c.login: self.parse_permissions(c.permissions)
                    for c in self.rate_limited(
                        r.get_collaborators, affiliation="direct"
                    )
                }
                for r in tqdm(repos, disable=tqdm_disable)
            }.items()
            if permissions
        }

    def get_team_collaborators(self, repos, tqdm_disable=tqdm_disable):
        return {
            repo: permissions
            for repo, permissions in {
                r.name: {
                    c.name.lower(): c.permission for c in self.rate_limited(r.get_teams)
                }
                for r in tqdm(repos, disable=tqdm_disable)
            }.items()
            if permissions
        }

    def get_existing_permissions(self, repo_whitelist=[]):
        logger.info("Initializing repositories")
        repos = [
            r
            for r in tqdm(self.rate_limited(self.org.get_repos), disable=tqdm_disable)
            if r.name in repo_whitelist or len(repo_whitelist) == 0
        ]

        logger.info("Loading user permissions")
        user_collaborators = self.get_user_collaborators(repos)

        logger.info("Loading team permissions")
        team_collaborators = self.get_team_collaborators(repos)

        collaborators = {
            repo.name: {
                "users": user_collaborators[repo.name]
                if repo.name in user_collaborators
                else {},
                "teams": team_collaborators[repo.name]
                if repo.name in team_collaborators
                else {},
            }
            for repo in repos
        }

        return collaborators

    def get_desired_permissions_from_file(self, state_file, repo_whitelist=[]):
        with open(state_file, "r") as stream:
            res = yaml.safe_load(stream)

            return {
                repo: permissions
                for repo, permissions in res.items()
                if repo in repo_whitelist or len(repo_whitelist) == 0
            }

    def initial_export(self, repo_whitelist=[]):
        return yaml.dump(self.get_existing_permissions(repo_whitelist))

    def parse_diff(self, diff):
        """
        Parses DeepDiff output:
        root['repo']['teams']['DevOps'] => 'repo', 'teams', 'DevOps'
        root['repo']['teams'] => 'repo', 'teams', None
        root['repo'] => 'repo', None, None
        """
        matches = re.search("^root\['(.+)'\]\['(.+)'\]\['(.+)'\]$", diff)  # noqa

        if matches is not None:
            return matches.group(1), matches.group(2), matches.group(3)

        matches = re.search("^root\['(.+)'\]\['(.+)'\]$", diff)  # noqa

        if matches is not None:
            return matches.group(1), matches.group(2), None

        matches = re.search("^root\['(.+)'\]$", diff)  # noqa

        return matches.group(1), None, None

    def upsert_item(self, item, entity, category, repo_name):
        self.validate_item(item)

        if category == "teams":
            team = self.rate_limited(self.org.get_team_by_slug, entity)
            self.rate_limited(
                team.update_team_repository, f"{self.org.name}/{repo_name}", item
            )
        elif category == "users":
            repo = self.rate_limited(self.org.get_repo, repo_name)
            user = self.rate_limited(self.g.get_user, entity)
            self.rate_limited(repo.add_to_collaborators, user, item)
        else:
            raise Exception(f"Invalid category {category}!")

    def delete_item(self, entity, category, repo_name):
        repo = self.rate_limited(self.org.get_repo, repo_name)

        if category == "teams":
            team = self.rate_limited(self.org.get_team_by_slug, entity)
            self.rate_limited(team.remove_from_repos, repo)
        elif category == "users":
            user = self.rate_limited(self.g.get_user, entity)
            self.rate_limited(repo.remove_from_collaborators, user)
        else:
            raise Exception(f"Invalid category {category}!")

    def truncate_all_permissions(self, repo_name, categories=["teams", "users"]):
        repo = self.rate_limited(self.g.get_repo, f"{self.org.login}/{repo_name}")

        if "teams" in categories:
            try:
                team_collaborators = self.get_team_collaborators(
                    [repo], tqdm_disable=True
                )[repo_name]
                for collaborator_name, collaborator in team_collaborators.items():
                    logger.info(
                        f"[{repo_name}] Purgin access for `{collaborator_name}` (teams)"
                    )
                    self.delete_item(collaborator_name, "teams", repo_name)
            except KeyError:
                # we get here when team collaborators for current repo are already empty
                pass

        if "users" in categories:
            try:
                user_collaborators = self.get_user_collaborators(
                    [repo], tqdm_disable=True
                )[repo_name]
                for collaborator_name, collaborator in user_collaborators.items():
                    logger.info(
                        f"[{repo_name}] Purgin access for `{collaborator_name}` (users)"
                    )
                    self.delete_item(collaborator_name, "users", repo_name)
            except KeyError:
                # we get here when user collaborators for current repo are already empty
                pass

    def reconcile(self, desired_permissions, dry_run=False, repo_whitelist=[]):
        existing_permissions = self.get_existing_permissions(
            repo_whitelist=repo_whitelist
        )
        diff = DeepDiff(existing_permissions, desired_permissions, ignore_order=True)

        dry_run_suffix = " (dry-run)" if dry_run else ""

        if "dictionary_item_added" in diff:
            for to_add in diff["dictionary_item_added"]:
                repo, category, entity = self.parse_diff(to_add)

                if category is None:
                    raise RepositoryNotFoundException(
                        f"Repository: {repo} does not exist!"
                    )

                item = desired_permissions[repo][category][entity]

                logger.info(
                    f"[{repo}] Adding `{item}` for {entity} ({category}){dry_run_suffix}"
                )
                if not dry_run:
                    self.upsert_item(item, entity, category, repo)

        if "values_changed" in diff:
            for to_change in diff["values_changed"]:
                repo, category, entity = self.parse_diff(to_change)
                item = desired_permissions[repo][category][entity]
                current = existing_permissions[repo][category][entity]

                logger.info(
                    f"[{repo}] Updating `{item}` - Current: `{current}`{dry_run_suffix}"
                )
                if not dry_run:
                    self.upsert_item(item, entity, category, repo)

        if "dictionary_item_removed" in diff:
            for to_delete in diff["dictionary_item_removed"]:
                repo, category, entity = self.parse_diff(to_delete)

                # one specific item was removed
                if category is not None and entity is not None:
                    logger.info(
                        f"[{repo} - {category} - {entity}] Delete{dry_run_suffix}"
                    )
                    if not dry_run:
                        self.delete_item(entity, category, repo)

                # one category was remove (teams/users)
                elif category is not None:
                    logger.info(f"[{repo}] Truncate ({category}){dry_run_suffix}")
                    if not dry_run:
                        self.truncate_all_permissions(repo, categories=[category])

                # whole repo was removed
                else:
                    logger.info(f"[{repo}] Truncate (all){dry_run_suffix}")
                    if not dry_run:
                        self.truncate_all_permissions(repo)


class RepositoryNotFoundException(Exception):
    pass


class InvalidPermissionException(Exception):
    pass
