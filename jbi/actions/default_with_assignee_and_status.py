"""
Extended action that provides some additional features over the default:
  * Updates the Jira assignee when the bug's assignee changes.
  * Optionally updates the Jira status when the bug's resolution or status changes.

`init` is required; and requires at minimum the `jira_project_key` parameter. `status_map` is optional.

`init` should return a __call__able
"""
import logging

from jbi import ActionResult, Operation
from jbi.actions.default import JIRA_DESCRIPTION_CHAR_LIMIT, DefaultExecutor
from jbi.environment import get_settings
from jbi.errors import ActionError
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

    def jira_comments_for_update(
        self,
        payload: BugzillaWebhookRequest,
    ):
        """Returns the comments to post to Jira for a changed bug"""
        return payload.map_as_comments(
            status_log_enabled=False, assignee_log_enabled=False
        )

    def create_and_link_issue(  # pylint: disable=too-many-locals
        self, payload, bug_obj
    ) -> ActionResult:
        """create jira issue and establish link between bug and issue; rollback/delete if required"""
        jira_response_create, log_context = self.create_jira_issue_from_bug(
            payload, bug_obj
        )

        jira_key_in_response = jira_response_create.get("key")

        log_context["jira"]["issue"] = jira_key_in_response

        # In the time taken to create the Jira issue the bug may have been updated so
        # re-retrieve it to ensure we have the latest data.
        bug_obj = payload.getbug_as_bugzilla_object()
        jira_key_in_bugzilla = bug_obj.extract_from_see_also()
        _duplicate_creation_event = (
            jira_key_in_bugzilla is not None
            and jira_key_in_response != jira_key_in_bugzilla
        )
        if _duplicate_creation_event:
            logger.warning(
                "Delete duplicated Jira issue %s from Bug %s",
                jira_key_in_response,
                bug_obj.id,
                extra={
                    **log_context,
                    "operation": Operation.DELETE,
                },
            )
            jira_response_delete = self.jira_client.delete_issue(
                issue_id_or_key=jira_key_in_response
            )
            return True, {"jira_response": jira_response_delete}

        jira_url = f"{settings.jira_base_url}browse/{jira_key_in_response}"
        logger.debug(
            "Link %r on Bug %s",
            jira_url,
            bug_obj.id,
            extra={
                **log_context,
                "operation": Operation.LINK,
            },
        )
        update = self.bugzilla_client.build_update(see_also_add=jira_url)
        bugzilla_response = self.bugzilla_client.update_bugs([bug_obj.id], update)

        bugzilla_url = f"{settings.bugzilla_base_url}/show_bug.cgi?id={bug_obj.id}"
        logger.debug(
            "Link %r on Jira issue %s",
            bugzilla_url,
            jira_key_in_response,
            extra={
                **log_context,
                "operation": Operation.LINK,
            },
        )
        jira_response = self.jira_client.create_or_update_issue_remote_links(
            issue_key=jira_key_in_response,
            link_url=bugzilla_url,
            title=f"Bugzilla Bug {bug_obj.id}",
        )

        self.update_issue(payload, bug_obj, jira_key_in_response, is_new=True)

        return True, {
            "bugzilla_response": bugzilla_response,
            "jira_response": jira_response,
        }

    def bug_create_or_update(
        self, payload: BugzillaWebhookRequest
    ) -> ActionResult:  # pylint: disable=too-many-locals
        """Create and link jira issue with bug, or update; rollback if multiple events fire"""
        bug_obj = payload.bugzilla_object
        linked_issue_key = bug_obj.extract_from_see_also()  # type: ignore
        if not linked_issue_key:
            return self.create_and_link_issue(payload, bug_obj)

        log_context = {
            "request": payload.dict(),
            "bug": bug_obj.dict(),
            "jira": {
                "issue": linked_issue_key,
                "project": self.jira_project_key,
            },
        }
        logger.debug(
            "Update fields of Jira issue %s for Bug %s",
            linked_issue_key,
            bug_obj.id,
            extra={
                **log_context,
                "operation": Operation.LINK,
            },
        )
        jira_response_update = self.jira_client.update_issue_field(
            key=linked_issue_key, fields=self.jira_fields(bug_obj)
        )

        comments = self.jira_comments_for_update(payload)
        jira_response_comments = []
        for i, comment in enumerate(comments):
            logger.debug(
                "Create comment #%s on Jira issue %s",
                i + 1,
                linked_issue_key,
                extra={
                    **log_context,
                    "operation": Operation.COMMENT,
                },
            )
            jira_response_comments.append(
                self.jira_client.issue_add_comment(
                    issue_key=linked_issue_key, comment=comment
                )
            )

        self.update_issue(payload, bug_obj, linked_issue_key, is_new=False)

        return True, {"jira_responses": [jira_response_update, jira_response_comments]}

    def update_issue(
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
