"""Human-readable metadata for the public Monarch MCP tool surface.

FastMCP derives names, descriptions, and schemas from Python functions.  The
additional title and safety metadata here is kept in one catalog so the wire
contract is easy to audit and every registered tool is accounted for.
"""

from __future__ import annotations

from typing import Any

from mcp.types import ToolAnnotations


# title, read-only, destructive, idempotent, open-world
TOOL_METADATA: dict[str, tuple[str, bool, bool, bool | None, bool | None]] = {
    "setup_authentication": ("Show Authentication Setup", True, False, True, False),
    "monarch_login": ("Sign In to Monarch Money", False, False, False, True),
    "monarch_login_with_token": ("Connect with Session Token", False, False, False, True),
    "monarch_logout": ("Sign Out of Monarch Money", False, False, True, True),
    "check_auth_status": ("Check Monarch Connection", True, False, True, False),
    "debug_session_loading": ("Debug Session Loading", True, False, True, False),
    "get_accounts": ("List Financial Accounts", True, False, True, False),
    "refresh_accounts": ("Refresh Account Data", False, False, True, True),
    "get_account_holdings": ("List Account Holdings", True, False, True, False),
    "get_account_balance_history": ("Get Account Balance History", True, False, True, False),
    "upload_account_balance_history": ("Upload Balance Corrections", False, False, False, True),
    "get_transactions": ("List Transactions", True, False, True, False),
    "search_transactions": ("Search Transactions", True, False, True, False),
    "get_transaction_details": ("Get Transaction Details", True, False, True, False),
    "create_transaction": ("Create Transaction", False, False, False, True),
    "update_transaction": ("Update Transaction", False, False, False, True),
    "categorize_transaction": ("Categorize Transaction", False, False, False, True),
    "update_transaction_notes": ("Update Transaction Notes", False, False, False, True),
    "mark_transaction_reviewed": ("Mark Transaction Reviewed", False, False, True, True),
    "bulk_categorize_transactions": ("Bulk Categorize Transactions", False, False, False, True),
    "delete_transaction": ("Delete Transaction", False, True, False, True),
    "get_recurring_transactions": ("List Recurring Transactions", True, False, True, False),
    "get_transactions_needing_review": ("List Transactions Needing Review", True, False, True, False),
    "get_transactions_summary": ("Summarize Transactions", True, False, True, False),
    "get_spending_summary": ("Summarize Spending", True, False, True, False),
    "get_transaction_splits": ("Get Transaction Splits", True, False, True, False),
    "split_transaction": ("Split Transaction", False, False, False, True),
    "set_transaction_tags": ("Set Transaction Tags", False, False, False, True),
    "get_transaction_tags": ("List Transaction Tags", True, False, True, False),
    "create_transaction_tag": ("Create Transaction Tag", False, False, False, True),
    "add_transaction_tag": ("Add Tag to Transaction", False, False, True, True),
    "get_transaction_rules": ("List Transaction Rules", True, False, True, False),
    "create_transaction_rule": ("Create Transaction Rule", False, False, False, True),
    "update_transaction_rule": ("Update Transaction Rule", False, False, False, True),
    "delete_transaction_rule": ("Delete Transaction Rule", False, True, False, True),
    "get_transaction_categories": ("List Transaction Categories", True, False, True, False),
    "get_transaction_category_groups": ("List Category Groups", True, False, True, False),
    "create_transaction_category": ("Create Transaction Category", False, False, False, True),
    "update_category": ("Update Transaction Category", False, False, False, True),
    "get_category_details": ("Get Category Details", True, False, True, False),
    "get_cashflow_by_month": ("Get Monthly Cashflow by Category", True, False, True, False),
    "get_budgets": ("Get Budgets", True, False, True, False),
    "set_budget_amount": ("Set Budget Amount", False, False, False, True),
    "get_cashflow": ("Analyze Cashflow", True, False, True, False),
    "get_net_worth": ("Get Net Worth History", True, False, True, False),
    "get_net_worth_by_account_type": ("Break Down Net Worth by Account Type", True, False, True, False),
    "get_merchant": ("Get Merchant Details", True, False, True, False),
    "update_merchant": ("Update Merchant Recurring Settings", False, False, False, True),
    "review_recurring_stream": ("Review Recurring Stream", False, False, True, True),
}


def apply_tool_metadata(server: Any) -> None:
    """Apply the catalog and fail fast if a tool is missing from it."""
    registered = server._tool_manager.list_tools()
    registered_names = {tool.name for tool in registered}
    catalog_names = set(TOOL_METADATA)
    missing = registered_names - catalog_names
    stale = catalog_names - registered_names
    if missing or stale:
        raise RuntimeError(
            "Tool metadata catalog is out of sync: "
            f"missing={sorted(missing)}, stale={sorted(stale)}"
        )

    for tool in registered:
        title, read_only, destructive, idempotent, open_world = TOOL_METADATA[tool.name]
        tool.title = title
        tool.annotations = ToolAnnotations(
            title=title,
            readOnlyHint=read_only,
            destructiveHint=destructive,
            idempotentHint=idempotent,
            openWorldHint=open_world,
        )


def tool_catalog(server: Any) -> list[dict[str, Any]]:
    """Return safe, human-readable metadata for the setup dashboard."""
    catalog = []
    for tool in server._tool_manager.list_tools():
        annotations = tool.annotations
        catalog.append(
            {
                "name": tool.name,
                "title": tool.title or tool.name,
                "description": " ".join(tool.description.split()),
                "read_only": bool(annotations and annotations.readOnlyHint),
                "destructive": bool(annotations and annotations.destructiveHint),
            }
        )
    return catalog
