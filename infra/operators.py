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
    db = Database(Settings().database_url)
    try:
        async with db.sessions() as session:
            row = await provision_operator(
                session, args.username, args.name, args.role, password, args.slack_user_id
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
    args = parser.parse_args()
    secret = getpass.getpass("Password (12+ characters): ")
    if secret != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match")
    asyncio.run(run(args, secret))
