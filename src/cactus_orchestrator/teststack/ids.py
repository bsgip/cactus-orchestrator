import shortuuid

from cactus_orchestrator.model import User


def generate_static_test_stack_id(user: User) -> str:
    return f"static-{user.user_id}"


def generate_dynamic_test_stack_id(user: User) -> str:
    return f"{shortuuid.uuid().lower()}-{user.user_id}"
