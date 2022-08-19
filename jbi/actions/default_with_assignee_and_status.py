"""
Extended action that provides some additional features over the default:
  * Updates the Jira assignee when the bug's assignee changes.
  * Optionally updates the Jira status when the bug's resolution or status changes.

`init` is required; and requires at minimum the `jira_project_key` parameter. `status_map` is optional.

`init` should return a __call__able
"""
import logging

from jbi import ActionResult, Operation
from jbi.actions.default import DefaultExecutor
from jbi.environment import get_settings
from jbi.models import BugzillaBug, BugzillaWebhookRequest

logger = logging.getLogger(__name__)

settings = get_settings()


def init(status_map=None, **kwargs):
    """Function that takes required and optional params and returns a callable object"""
    return AssigneeAndStatusExecutor(status_map=status_map or {}, **kwargs)


class AssigneeAndStatusExecutor(DefaultExecutor):
    """Callable class that encapsulates the default_with_assignee_and_status action."""

    def __init__(self, status_map, **kwargs):
        """Initialize AssigneeAndStatusExecutor Object"""
        super().__init__(**kwargs)
        self.status_map = status_map

    def __call__(self, payload: BugzillaWebhookRequest) -> ActionResult:
        target = payload.event.target  # type: ignore
        if target == "comment":
            return self.comment_create_or_noop(payload=payload)
        if target == "bug":
            bug_obj = payload.bugzilla_object
            linked_issue_key = bug_obj.extract_from_see_also()
            if linked_issue_key:
                action_result = self.update_issue(payload=payload, bug_obj=bug_obj)
                self.update_issue_assignee_and_status(
                    payload, bug_obj, linked_issue_key, is_new=False
                )
                return action_result
            else:
                action_result = self.create_and_link_issue(
                    payload=payload, bug_obj=bug_obj
                )
                _, context = action_result
                project_key = context["jira_create_issue_response"]["key"]
                self.update_issue_assignee_and_status(
                    payload, bug_obj, project_key, is_new=True
                )
                return action_result
        logger.debug(
            "Ignore event target %r",
            target,
            extra={
                "request": payload.dict(),
                "operation": Operation.IGNORE,
            },
        )
        return False, {}

    def update_issue_assignee_and_status(
        self,
        payload: BugzillaWebhookRequest,
        bug_obj: BugzillaBug,
        linked_issue_key: str,
        is_new: bool,
    ):
        changed_fields = payload.event.changed_fields() or []

        log_context = {
            "bug": {
                "id": bug_obj.id,
                "status": bug_obj.status,
                "resolution": bug_obj.resolution,
                "assigned_to": bug_obj.assigned_to,
            },
            "jira": {
                "issue": linked_issue_key,
                "project": self.jira_project_key,
            },
            "changed_fields": changed_fields,
            "operation": Operation.UPDATE,
        }

        def clear_assignee():
            # New tickets already have no assignee.
            if not is_new:
                logger.debug("Clearing assignee", extra=log_context)
                self.jira_client.update_issue_field(
                    key=linked_issue_key, fields={"assignee": None}
                )

        # If this is a new issue or if the bug's assignee has changed then
        # update the assignee.
        if is_new or "assigned_to" in changed_fields:
            if bug_obj.assigned_to == "nobody@mozilla.org":
                clear_assignee()
            else:
                logger.debug(
                    "Attempting to update assignee",
                    extra=log_context,
                )
                # Look up this user in Jira
                users = self.jira_client.user_find_by_user_string(
                    query=bug_obj.assigned_to
                )
                if len(users) == 1:
                    try:
                        # There doesn't appear to be an easy way to verify that
                        # this user can be assigned to this issue, so just try
                        # and do it.
                        self.jira_client.update_issue_field(
                            key=linked_issue_key,
                            fields={"assignee": {"accountId": users[0]["accountId"]}},
                        )
                    except IOError as exception:
                        logger.debug(
                            "Setting assignee failed: %s", exception, extra=log_context
                        )
                        # If that failed then just fall back to clearing the
                        # assignee.
                        clear_assignee()
                else:
                    logger.debug(
                        "No assignee found",
                        extra={**log_context, "operation": Operation.IGNORE},
                    )
                    clear_assignee()

        # If this is a new issue or if the bug's status or resolution has
        # changed then update the issue status.
        if is_new or "status" in changed_fields or "resolution" in changed_fields:
            # We use resolution if one exists or status otherwise.
            status = bug_obj.resolution or bug_obj.status

            if status in self.status_map:
                logger.debug(
                    "Updating Jira status to %s",
                    self.status_map[status],
                    extra=log_context,
                )
                self.jira_client.set_issue_status(
                    linked_issue_key, self.status_map[status]
                )
            else:
                logger.debug(
                    "Bug status was not in the status map.",
                    extra={
                        **log_context,
                        "status_map": self.status_map,
                        "operation": Operation.IGNORE,
                    },
                )
