import casbin
from casbin_sqlalchemy_adapter import Adapter
from tabulate import tabulate
import json

def get_api_keys(enforcer):
    """Extract API keys (users) from grouping policies"""
    grouping_policies = enforcer.get_grouping_policy()
    api_keys = []
    for policy in grouping_policies:
        if len(policy) >= 2:
            api_key = policy[0]
            if api_key not in api_keys:
                api_keys.append(api_key)
    return api_keys

def get_tools_from_g2_resources(enforcer):
    """Extract tools from g2 type resources (grouping policies)"""
    g2_policies = enforcer.get_filtered_named_grouping_policy("g2", 0)
    tools = []
    for policy in g2_policies:
        if len(policy) >= 2:
            resource = policy[0]
            if resource.startswith("tool") and resource not in tools:
                tools.append(resource)
    return sorted(tools)

def build_hierarchy_from_db(enforcer):
    # Retrieve all `g2` grouping policies from the database
    grouping_policies = enforcer.get_filtered_named_grouping_policy("g2", 0)

    # Initialize the hierarchy dictionary
    hierarchy = {}

    # Build the hierarchy
    for child, parent in grouping_policies:
        if parent not in hierarchy:
            hierarchy[parent] = {}
        if child.startswith("tool"):
            # Add tools as a list under their parent MCP
            for key in hierarchy:
                if parent in hierarchy[key]:
                    hierarchy[key][parent].append(child)
                    break
            else:
                hierarchy[parent] = [child]
        else:
            # Add MCPs as a dictionary under their parent agent
            if parent not in hierarchy:
                hierarchy[parent] = {}
            hierarchy[parent][child] = []

    return hierarchy


def filter_and_prettify_hierarchy(hierarchy):
    # Filter the dictionary to keep only keys containing "agent"
    filtered_hierarchy = {k: v for k, v in hierarchy.items() if "agent" in k}

    # Prettify the filtered dictionary
    pretty_hierarchy = json.dumps(filtered_hierarchy, indent=4)
    print(pretty_hierarchy)

def print_policy_table(enforcer, api_keys, tools):
    """Print policy enforcement results in a table format"""
    print("Original Policy:")
    results = []
    for api_key in api_keys:
        row = [api_key]
        for tool in tools:
            if enforcer.enforce(api_key, tool, "call"):
                row.append("✔")
            else:
                row.append("✘")
        results.append(row)

    print(tabulate(results, headers=["API Key"] + tools, tablefmt="grid"))

def print_hierarchy_policies(enforcer):
    """Print all policies with hierarchy structure"""
    print("All Policies with Hierarchy:")
    hierarchy = build_hierarchy_from_db(enforcer)
    filter_and_prettify_hierarchy(hierarchy)

def main():
    # Postgres 연결 (정책을 DB에 저장)
    adapter = Adapter("postgresql+psycopg2://rbac_user:yourpassword@localhost:5432/rbac")

    # Enforcer 생성
    e = casbin.Enforcer("rbac_model.conf", adapter)

    # -------------------------
    # 정책 추가 (DB 저장)
    # 리소스 계층 (tool → mcp → agent)
    e.add_named_grouping_policy("g2", "mcp11", "agent1")
    e.add_named_grouping_policy("g2", "mcp12", "agent1")
    e.add_named_grouping_policy("g2", "tool111", "mcp11")
    e.add_named_grouping_policy("g2", "tool112", "mcp11")
    e.add_named_grouping_policy("g2", "tool121", "mcp12")
    e.add_named_grouping_policy("g2", "tool122", "mcp12")

    # 그룹 권한
    e.add_policy("dev-group", "agent1", "call")
    e.add_policy("qa-group", "mcp11", "call")
    e.add_policy("ndy-group", "tool122", "call")

    # 사용자-그룹 매핑
    e.add_grouping_policy("alice", "dev-group")
    e.add_grouping_policy("bob", "qa-group")
    e.add_grouping_policy("ndy", "ndy-group")

    # 정책 DB에 영속
    e.save_policy()

    print("=== 초기 상태 ===")
    api_keys = get_api_keys(e)
    tools = get_tools_from_g2_resources(e)
    print_policy_table(e, api_keys, tools)
    print_hierarchy_policies(e)

    # 1. mcp12에 tool123 추가
    print("\n=== 1. mcp12에 tool123 추가 ===")
    e.add_named_grouping_policy("g2", "tool123", "mcp12")
    e.save_policy()
    api_keys = get_api_keys(e)
    tools = get_tools_from_g2_resources(e)
    print_policy_table(e, api_keys, tools)
    print_hierarchy_policies(e)

    # 2. mcp11에서 tool111 제거
    print("\n=== 2. mcp11에서 tool111 제거 ===")
    e.remove_named_grouping_policy("g2", "tool111", "mcp11")
    e.save_policy()
    api_keys = get_api_keys(e)
    tools = get_tools_from_g2_resources(e)
    print_policy_table(e, api_keys, tools)
    print_hierarchy_policies(e)

    # 3. new-api-key를 qa-group에 추가
    print("\n=== 3. new-api-key를 qa-group에 추가 ===")
    e.add_grouping_policy("new-api-key", "qa-group")
    e.save_policy()
    api_keys = get_api_keys(e)
    tools = get_tools_from_g2_resources(e)
    print_policy_table(e, api_keys, tools)
    print_hierarchy_policies(e)

    # 4. 새로운 그룹, API 키, agent, mcp, tools 추가
    print("\n=== 4. hello-group, hello-key, agent2, mcp21, tool211, tool212 추가 ===")
    # 새로운 리소스 계층 추가
    e.add_named_grouping_policy("g2", "mcp21", "agent2")
    e.add_named_grouping_policy("g2", "tool211", "mcp21")
    e.add_named_grouping_policy("g2", "tool212", "mcp21")

    # 새로운 그룹 권한 추가
    e.add_policy("hello-group", "agent2", "call")

    # 새로운 API 키-그룹 매핑 추가
    e.add_grouping_policy("hello-key", "hello-group")

    e.save_policy()
    api_keys = get_api_keys(e)
    tools = get_tools_from_g2_resources(e)
    print_policy_table(e, api_keys, tools)
    print_hierarchy_policies(e)

if __name__ == "__main__":
    main()