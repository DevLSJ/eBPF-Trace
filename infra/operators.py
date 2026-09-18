"""Provision an individual operator, without placing a password in argv or logs.

Usage: python -m infra.operators --username alice --name Alice --role responder
"""

import argparse
import asyncio
import getpass

from backend.core.config import Settings
from backend.core.operator_auth import ROLES, provision_operator
from backend.db.database import Database


async def run(args, password):
    settings = Settings()
    if args.test_account and not settings.ops_test_account_mode:
        raise ValueError(
            "Enable OPS_TEST_ACCOUNT_MODE before provisioning the public test identity"
        )
    db = Database(settings.database_url)
    try:
        async with db.sessions() as session:
            row = await provision_operator(
                session,
                args.username,
                args.name,
                args.role,
                password,
                args.slack_user_id,
                test_account=args.test_account,
            )
            await session.commit()
            print(f"Operator {row.username} provisioned as {row.role}; old sessions revoked.")
    finally:
        await db.engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", required=True, choices=sorted(ROLES))
    parser.add_argument("--slack-user-id")
    parser.add_argument("--test-account", action="store_true")
    args = parser.parse_args()
    secret = "admin" if args.test_account else getpass.getpass("Password (12+ characters): ")
    if not args.test_account and secret != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match")
    asyncio.run(run(args, secret))
