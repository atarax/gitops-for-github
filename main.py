from github import Github

from deepdiff import DeepDiff
import yaml
import kopf
import math
import json
import os
import time
import logging
import re
from tqdm import tqdm

loglevel = os.environ.get('LOGLEVEL', 'INFO').upper()
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=loglevel,
    datefmt='%Y-%m-%d %H:%M:%S'\
)
logger = logging.getLogger("gpm")

tqdm_disable = False if logging.root.level <= logging.INFO else True

def rate_limited(g, fn, *args, **kwargs):
    requests_left = g.rate_limiting[0]

    if requests_left < 10:
        rl_reset_time = g.rate_limiting_resettime
        cur_time = time.time()
        sleep_time = math.floor(rl_reset_time-cur_time)

        logger.info(f"Sleeing {sleep_time} seconds to wait for rate-limit reset...")
        time.sleep(sleep_time)

    return fn(*args, **kwargs)

def parse_permissions(permissions):
    escalation = [
        "admin", 
        "maintain",
        "push",
        "triage",
        "pull"
    ]

    for level in escalation:
        if getattr(permissions, level):
            return level

    raise Exception("Illegal permissions-object")

def get_user_collaborators(g, org, repos, tqdm_disable=tqdm_disable):
    return {
        repo: permissions for repo, permissions in {
            r.name: {
                c.login: parse_permissions(c.permissions)
                for c in rate_limited(g, r.get_collaborators, affiliation="direct")
            } for r in tqdm(repos, disable=tqdm_disable)
        }.items() if permissions
    }

def get_team_collaborators(g, org, repos, tqdm_disable=tqdm_disable):
    return {
        repo: permissions for repo, permissions in {
            r.name: {
                c.name: c.permission
                for c in rate_limited(g, r.get_teams)
            } for r in tqdm(repos, disable=tqdm_disable)
        }.items() if permissions
    }

def get_existing_permissions(g, org, repo_whitelist=[]):
    logger.info("Initializing repos")
    repos = [r for r in tqdm(rate_limited(g, org.get_repos), disable=tqdm_disable) if r.name in repo_whitelist or len(repo_whitelist) == 0]

    logger.info("Loading user permissions")
    user_collaborators = get_user_collaborators(g, org, repos)

    logger.info("Loading team permissions")
    team_collaborators = get_team_collaborators(g, org, repos)

    collaborators = {
        repo.name: {
            "users": user_collaborators[repo.name] if repo.name in user_collaborators else {},
            "teams": team_collaborators[repo.name] if repo.name in team_collaborators else {}
        } for repo in repos
    }

    return collaborators

def get_desired_permissions_from_file(state_file, repo_whitelist=[]):
    with open(state_file, "r") as stream:
        res = yaml.safe_load(stream)

        return { repo: permissions
            for repo, permissions in res.items() if repo in repo_whitelist or len(repo_whitelist) == 0
        }

def parse_diff(diff):
    """
    Parses DeepDiff output:
    root['repo']['teams']['DevOps'] => 'repo', 'teams', 'DevOps'
    root['repo']['teams'] => 'repo', 'teams', None
    root['repo'] => 'repo', None, None
    """
    matches = re.search("^root\['(.+)'\]\['(.+)'\]\['(.+)'\]$", diff)

    if matches is not None:
        return matches.group(1), matches.group(2), matches.group(3)

    matches = re.search("^root\['(.+)'\]\['(.+)'\]$", diff)

    if matches is not None:
        return matches.group(1), matches.group(2), None

    matches = re.search("^root\['(.+)'\]$", diff)

    return matches.group(1), None, None



def upsert_item(g, org, item, entity, category, repo_name):
    if category == "teams":
        team = rate_limited(g, org.get_team_by_slug, entity)
        rate_limited(g, team.update_team_repository, f"{org.name}/{repo_name}", item)
    elif category == "users":
        repo = rate_limited(g, org.get_repo, repo_name)
        user = rate_limited(g, g.get_user, entity)
        rate_limited(g, repo.add_to_collaborators , user, item)
    else:
        raise Exception(f"Invalid category {category}!")


def delete_item(g, org, entity, category, repo_name):
    repo = rate_limited(g, org.get_repo, repo_name)

    if category == "teams":
        team = rate_limited(g, org.get_team_by_slug, entity)
        rate_limited(g, team.remove_from_repos, repo)
    elif category == "users":
        user = rate_limited(g, g.get_user, entity)
        rate_limited(g, repo.remove_from_collaborators, user)
    else:
        raise Exception(f"Invalid category {category}!")

def truncate_all_permissions(g, org, repo_name, categories=["teams", "users"]):
    repo = rate_limited(g, g.get_repo, f"{org.login}/{repo_name}")

    if "teams" in categories:
        try:
            team_collaborators = get_team_collaborators(g, org, [repo], tqdm_disable=True)[repo_name]
            for collaborator_name, collaborator in team_collaborators.items():
                logger.info(f"[{repo_name}] Purgin access for `{collaborator_name}` (teams)")
                delete_item(g, org, collaborator_name, "teams", repo_name)
        except KeyError:
            # we get here when team collaborators for current repo are already empty
            pass
    
    if "users" in categories:
        try:
            user_collaborators = get_user_collaborators(g, org, [repo], tqdm_disable=True)[repo_name]
            for collaborator_name, collaborator in user_collaborators.items():
                logger.info(f"[{repo_name}] Purgin access for `{collaborator_name}` (users)")
                delete_item(g, org, collaborator_name, "users", repo_name)
        except KeyError:
            # we get here when user collaborators for current repo are already empty
            pass


def reconcile(g, org, existing_permissions, desired_permissions, dry_run=False):
    diff = DeepDiff(existing_permissions, desired_permissions, ignore_order=True)

    dry_run_suffix = " (dry-run)" if dry_run else ""

    if 'dictionary_item_added' in diff:
        for to_add in diff['dictionary_item_added']:
            repo, category, entity = parse_diff(to_add)
            item = desired_permissions[repo][category][entity]

            logger.info(f"[{repo}] Adding `{item}` for {entity} ({category}){dry_run_suffix}")
            if not dry_run:
                upsert_item(g, org, item, entity, category, repo)

    if 'values_changed' in diff:
        for to_change in diff['values_changed']:
            repo, category, entity = parse_diff(to_change)
            item = desired_permissions[repo][category][entity]
            current = existing_permissions[repo][category][entity]

            logger.info(f"[{repo}] Updating `{item}` - Current: `{current}`{dry_run_suffix}")
            if not dry_run:
                upsert_item(g, org, item, entity, category, repo)

    if 'dictionary_item_removed' in diff:
        for to_delete in diff['dictionary_item_removed']:
            repo, category, entity = parse_diff(to_delete)

            # one specific item was removed
            if category is not None and entity is not None:
                logger.info(f"[{repo} - {category} - {entity}] Delete{dry_run_suffix}")
                if not dry_run:
                    delete_item(g, org, entity, category, repo)

            # one category was remove (teams/users)
            elif category is not None:
                logger.info(f"[{repo}] Truncate ({category}){dry_run_suffix}")
                if not dry_run:
                    truncate_all_permissions(g, org, repo, categories=[category])

            # whole repo was removed
            else:
                logger.info(f"[{repo}] Truncate (all){dry_run_suffix}")
                if not dry_run:
                    truncate_all_permissions(g, org, repo)


def init_github(org_name):
    token = os.getenv("GITHUB_TOKEN", None)
    if token is None:
        raise Exception("`GITHUB_TOKEN` must be set in environment")

    # 100 results per page is max setting
    g = Github(token, per_page=100)
    org = g.get_organization(org_name)

    return g, org


def parse_body(body):
    # org-name, permission-map, repo-whitelist, dry-run
    return (
        body["spec"]["org"], 
        body["spec"]["repos"], 
        body["spec"]["repoWhitelist"], 
        body["spec"]["dryRun"]
    )


@kopf.on.create('githubpermissionmaps')
def on_create(body, **kwargs):
    logging.info(f"A handler is called with body: {body}")


@kopf.on.update('githubpermissionmaps')
def on_update(body, **kwargs):
    org, desired_permissions, repo_whitelist, dry_run = parse_body(body)

    g, org = init_github(org)
    existing_permissions = get_existing_permissions(g, org, repo_whitelist=repo_whitelist)

    reconcile(g, org, existing_permissions, desired_permissions, dry_run)


if __name__ == "__main__":
    import argparse
    

    parser = argparse.ArgumentParser(
        description="Manage permissions to github-repositories in a gitops-fashion. "
                    "GITHUB_TOKEN must be set in env and requires org-admin privileges. "
                    "To get the initial state run with `--initial-expport`. "
                    "This will capture all existent permissions to repositories. "
                    "These permissions are then enforced on runs without the --initial-expport`. "
                    "Repositories not present in the state will have all their accesses purged! "
                    "Control loglevel with LOGLEVEL.")

    parser.add_argument("--initial-export", action="store_true", help="Export current state as yaml on stdout")
    parser.add_argument("--dry-run", action="store_true", help="Only notify about changes without applying them")
    parser.add_argument("--org", required=True, help="Github organization to manage")
    parser.add_argument("--repo-whitelist", required=False, default="", help="Comma-sepatared list of repositories to manage, defaults to all repositories")
    parser.add_argument("--state-file", required=False, default="state.yaml", help="Comma-sepatared list of repositories to manage, defaults to all repositories")

    args = vars(parser.parse_args())

    initial_export = args["initial_export"]
    dry_run = args["dry_run"]
    org_name = args["org"]
    state_file = args["state_file"]
    repo_whitelist = [] if args["repo_whitelist"] == '' else args["repo_whitelist"].split(",")

    logger.info(f"Running with settings: {args}")
    
    g, org = init_github(org_name)

    existing_permissions = get_existing_permissions(g, org, repo_whitelist=repo_whitelist)
    desired_permissions = get_desired_permissions_from_file(state_file, repo_whitelist=repo_whitelist)

    if initial_export:
        print(yaml.dump(existing_permissions))
        exit(0)

    reconcile(g, org, existing_permissions, desired_permissions, dry_run)

