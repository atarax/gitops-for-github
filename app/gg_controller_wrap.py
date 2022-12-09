import logging
import os

import kopf
from github import Github
from kopf._core.reactor import running
from manager import PermissionManager

loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=loglevel,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("gg")

tqdm_disable = False if logging.root.level <= logging.INFO else True

MANAGER = None


def main():
    kopf.on.startup(id="startup")(startup)
    kopf.on.create("repositorypermission", id="create")(create)
    kopf.on.update("repositorypermission", id="update")(update)

    return running.run(clusterwide=True)


def init():
    token = os.getenv("GITHUB_TOKEN", None)
    if token is None:
        raise Exception("`GITHUB_TOKEN` must be set in environment")

    org_name = os.getenv("GITHUB_ORG", None)
    if org_name is None:
        raise Exception("`GITHUB_ORG` must be set in environment")

    # 100 results per page is max setting
    g = Github(token, per_page=100)
    org = g.get_organization(org_name)

    manager = PermissionManager(g, org)
    return manager


def parse_body(body):
    # permission-map, repo-whitelist, dry-run
    return (
        body["spec"]["repos"],
        body["spec"]["repoWhitelist"] if "repoWhitelist" in body["spec"] else [],
        body["spec"]["dryRun"] if "dryRun" in body["spec"] else False,
    )


def startup(logger, **kwargs):
    global MANAGER
    MANAGER = init()
    logging.info("Controller startup finished")


def create(body, **kwargs):
    desired_permissions, repo_whitelist, dry_run = parse_body(body)
    MANAGER.reconcile(desired_permissions, dry_run, repo_whitelist)


def update(body, **kwargs):
    desired_permissions, repo_whitelist, dry_run = parse_body(body)
    MANAGER.reconcile(desired_permissions, dry_run, repo_whitelist)
