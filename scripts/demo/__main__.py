from __future__ import annotations

from . import final_demo_scenarios
from .schema_compatible_seed import (
    seed_machine_and_exposure,
)
from .tenant_scoped_lookup import (
    find_demo_exposure,
)


# Keep production/backend models unchanged. The final demo uses a real
# Log4Shell CVE but maps the Maven artifact to an application because
# inventory V1 only models package ecosystems for PyPI/npm.
final_demo_scenarios._seed_machine_and_exposure = (
    seed_machine_and_exposure
)

# Demo hostnames may exist in more than one local test organization.
# Always resolve the exposure inside TIP_DEMO_ORGANIZATION_SLUG.
final_demo_scenarios._find_demo_exposure = (
    find_demo_exposure
)


if __name__ == "__main__":
    final_demo_scenarios.main()
