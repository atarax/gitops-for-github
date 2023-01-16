import logging
import os
import time

import jwt
import kopf
import requests
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
SETTINGS = None


def main():
    kopf.on.startup(id="startup")(startup)
    kopf.on.create("gg.dev", "v1", "repositories", id="create")(create)
    kopf.on.update("gg.dev", "v1", "repositories", id="update")(update)
    kopf.on.delete("gg.dev", "v1", "repositories", id="delete")(delete)
    kopf.timer("gg.dev", "v1", "repositories", id="reconcile", interval=600)(timer)

    return running.run(clusterwide=True)


def startup(**kwargs):
    global SETTINGS

    SETTINGS = get_config()

    redacted = SETTINGS.copy()
    redacted["private_key"] = "..."

    logging.info(f"Running with settings: {redacted}")
    logging.info("Controller startup finished")


def require_env(name):
    value = os.getenv(name, None)
    if value is None:
        raise BootException(f"`{name}` must be set in environment")

    return value


def get_config():
    return {
        "app_id": int(require_env("GITHUB_APP_ID")),
        "installation_id": require_env("GITHUB_APP_INSTALLATION_ID"),
        "private_key": require_env("GITHUB_APP_PRIVATE_KEY"),
        "org_name": require_env("GITHUB_ORG"),
        "dry_run": os.getenv("GG_DRY_RUN", False),
    }


def create_jwt(app_id, private_key):
    now = int(time.time())
    exp = now + 10 * 60
    payload = {"iss": int(app_id), "iat": now, "exp": exp}
    token = jwt.encode(payload, private_key, algorithm="RS256")

    return token


def create_access_token(installation_id, jwt_token):
    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt_token}",
        },
    )

    return resp.json()


def get_manager():
    jwt_token = create_jwt(SETTINGS["app_id"], SETTINGS["private_key"])
    token_info = create_access_token(SETTINGS["installation_id"], jwt_token)

    # 100 results per page is max setting
    g = Github(token_info["token"], per_page=100, pool_size=100)
    org = g.get_organization(SETTINGS["org_name"])

    return PermissionManager(g, org, tqdm_disable=True)


def parse_body(body):
    # repo, permissions, dry-run
    return (
        body["metadata"]["name"],
        {body["metadata"]["name"]: body["spec"]["permissions"]},
        body["spec"]["dryRun"] if "dryRun" in body["spec"] else False,
    )


def create(body, **kwargs):
    repo, desired_permissions, dry_run = parse_body(body)
    return reconcile(desired_permissions, dry_run, repo)


def update(body, **kwargs):
    repo, desired_permissions, dry_run = parse_body(body)
    return reconcile(desired_permissions, dry_run, repo)


def delete(body, **kwargs):
    repo, _, dry_run = parse_body(body)

    # global dry-run settings overwrite resource-level setting
    dry_run = dry_run or SETTINGS["dry_run"]

    return reconcile({repo: {}}, dry_run, repo)


def timer(body, **kwargs):
    repo, desired_permissions, dry_run = parse_body(body)
    return reconcile(desired_permissions, dry_run, repo)


def reconcile(desired_permissions, dry_run, repo):
    # global dry-run settings overwrite resource-level setting
    dry_run = dry_run or SETTINGS["dry_run"]

    # rotate token if necessary
    manager = get_manager()

    try:
        manager.reconcile(desired_permissions, dry_run, [repo])
        return {"success": True, "dryRun": dry_run, "reason": ""}
    except Exception as e:
        reason = e.__class__.__name__ + ": " + str(e)
        logging.error(f"Reconcile failed for '{repo}': {reason}")

        return {"success": False, "dryRun": dry_run, "reason": reason}


class RepoNotFoundException(kopf.PermanentError):
    pass


class BootException(kopf.PermanentError):
    pass
