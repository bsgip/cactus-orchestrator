from dataclasses import dataclass


@dataclass(frozen=True)
class TeststackImages:
    """Image references for the containers making up a single teststack pod, for one CSIP-Aus version.

    The taskiq-worker container reuses the envoy image, so it has no dedicated field here.
    """

    __test__ = False  # stops pytest trying to collect this as a test class

    postgres: str
    pubsub: str
    teststack_init: str
    envoy: str
    runner: str
