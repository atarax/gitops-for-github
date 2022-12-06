import logging
import os

from github import Github

from manager import PermissionManager

loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=loglevel,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gpm")

tqdm_disable = False if logging.root.level <= logging.INFO else True


def init_github(org_name):
    token = os.getenv("GITHUB_TOKEN", None)
    if token is None:
        raise Exception("`GITHUB_TOKEN` must be set in environment")

    # 100 results per page is max setting
    g = Github(token, per_page=100)
    org = g.get_organization(org_name)

    return g, org


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Manage permissions to github-repositories in a gitops-fashion. "
        "GITHUB_TOKEN must be set in env and requires org-admin privileges. "
        "To get the initial state run with `--initial-expport`. "
        "This will capture all existent permissions to repositories. "
        "These permissions are then enforced on runs without the --initial-expport`. "
        "Repositories not present in the state will have all their accesses purged! "
        "Control loglevel with LOGLEVEL."
    )

    parser.add_argument(
        "--initial-export",
        action="store_true",
        help="Export current state as yaml on stdout",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only notify about changes without applying them",
    )
    parser.add_argument("--org", required=True, help="Github organization to manage")
    parser.add_argument(
        "--repo-whitelist",
        required=False,
        default="",
        help="Comma-sepatared list of repositories to manage, defaults to all repositories",
    )
    parser.add_argument(
        "--state-file",
        required=False,
        default="desired.yaml",
        help="Comma-sepatared list of repositories to manage, defaults to all repositories",
    )

    args = vars(parser.parse_args())

    initial_export = args["initial_export"]
    dry_run = args["dry_run"]
    org_name = args["org"]
    state_file = args["state_file"]
    repo_whitelist = (
        [] if args["repo_whitelist"] == "" else args["repo_whitelist"].split(",")
    )

    logger.info(f"Running with settings: {args}")

    g, org = init_github(org_name)

    manager = PermissionManager(g, org)

    if initial_export:
        print(manager.initial_export(repo_whitelist))
        exit(0)

    desired_permissions = manager.get_desired_permissions_from_file(
        state_file, repo_whitelist=repo_whitelist
    )
    manager.reconcile(desired_permissions, dry_run, repo_whitelist)
