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


class RepoNotFoundException(kopf.PermanentError):
    pass


def main():
    kopf.on.startup(id="startup")(startup)
    kopf.on.create("gg.dev", "v1", "repositories", id="create")(create)
    kopf.on.update("gg.dev", "v1", "repositories", id="update")(update)
    kopf.on.delete("gg.dev", "v1", "repositories", id="delete")(delete)

    return running.run(clusterwide=True)


def init():
    token = os.getenv("GITHUB_TOKEN", None)
    if token is None:
        raise Exception("`GITHUB_TOKEN` must be set in environment")

    org_name = os.getenv("GITHUB_ORG", None)
    if org_name is None:
        raise Exception("`GITHUB_ORG` must be set in environment")

    dry_run = os.getenv("GG_DRY_RUN", False)

    # 100 results per page is max setting
    g = Github(token, per_page=100)
    org = g.get_organization(org_name)

    manager = PermissionManager(g, org)
    return manager, dry_run


def parse_body(body):
    # repo, permissions, dry-run
    return (
        body["metadata"]["name"],
        {body["metadata"]["name"]: body["spec"]["permissions"]},
        body["spec"]["dryRun"] if "dryRun" in body["spec"] else False,
    )


def startup(**kwargs):
    global MANAGER, DRY_RUN
    MANAGER, DRY_RUN = init()
    logging.info(f"dry-run: {DRY_RUN}")
    logging.info("Controller startup finished")


def create(body, **kwargs):
    repo, desired_permissions, dry_run = parse_body(body)
    return reconcile(desired_permissions, dry_run, repo)


def update(body, **kwargs):
    repo, desired_permissions, dry_run = parse_body(body)
    return reconcile(desired_permissions, dry_run, repo)


def delete(body, **kwargs):
    repo, _, dry_run = parse_body(body)
    return reconcile({repo: {}}, dry_run, repo)


def reconcile(desired_permissions, dry_run, repo):
    try:
        MANAGER.reconcile(desired_permissions, DRY_RUN or dry_run, [repo])
        return {"success": True, "dryRun": DRY_RUN or dry_run, "reason": ""}
    except Exception as e:
        reason = e.__class__.__name__ + ": " + str(e)
        logging.info(f"Reconcile failed for '{repo}': {reason}")

        return {"success": False, "dryRun": DRY_RUN or dry_run, "reason": reason}
