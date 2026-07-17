---
layout: post
title: Analyzing active tables, pt 2
date: 2026-07-06
tags:
    - sentinel
    - xdr
    - microsoft
    - log analytics
    - tables
    - python
    - kql
    - pandas
---
Currently Microsoft has 2 detection methods for their security platform. The first being Analytics Rules in Microsoft Sentinel, from the Azure portal. The second, and preferred method (though not fully featured), is Detection Rules in the Defender portal.  

At the time of this field note there isn't feature parity between Analytics Rules and Detection Rules.

<!--more-->

## Table of contents
- [Introduction](#introduction)
- [What's needed](#whats-needed)
- [Constraints](#constraints)
- [Dependencies](#dependencies)
- [Variables](#variables)
- [Prep Azure Management APIs](#prep-azure-management-apis)
- [Wrangle and aggregate the data](#wrangle-and-aggregate-the-data)
- [Wrap up](#wrap-up)
- [References](#references)

## Introduction
In [part 1](./001-active-tables-pt1.md) we were able to get all tables in a Log Analytics Workspace and determine the tables actively ingesting data, along with each table's plan and retention settings.

In part 2 of this series we'll look at how we can extract table names from Analytics Rules. We'll look at getting Defender tables and Custom Detection Rules in parts 3 and 4, respectively.

## What's needed
We'll need a modern Microsoft Sentinel workspace; so it should be connected to Microsoft Security/XDR portal and the lake should be enabled. 

An account with Log Analytics Reader Azure RBAC role and for this part, an Enterprise Application with Sentinel Reader role and the following API permissions:
- `CustomDetection.Read.All`
- `ThreatHunting.Read.All`

## Constraints
Most organizations are likely in a transition state between Sentinel and Defender and may have rules in both portals.

**Worth nothing:** One thing I discovered during the brainstorming/discovery of this series is that Near Real Time rules aren't surfaced through all paths. The current versions of the Azure SDK for Python and Sentinel API don't include Near Real Time Analytics Rules. We'll rely on a previous Azure Management API endpoint version. 

## Dependencies
The dependencies are inclusive of previous field notes in the series.

### Import dependencies
Import the previous note's dependencies and the dependencies below.

```python
from msal import ConfidentialClientApplication
import requests
import re
```

## Variables
The variables are inclusive of previous field notes in the series and the following. 

```python
tenant_id = os.getenv("TENANT_ID")
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
```

## Prep Azure Management APIs
With the constraints discussed above in mind, we'll use the Azure Management API to expose the `SecurityInsights` class, which allows us to interact with resources exposed by the `Microsoft.SecurityInsights` resource provider. 

We use the `2022-11-01-preview` API endpoint because it surfaces Near Real-Time rules.

### Azure Management
```python
def get_azure_mgmt_token(tenant_id, client_id, client_secret):
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}"
    )

    response = app.acquire_token_for_client(scopes=["https://management.azure.com/.default"])

    if "access_token" not in response:
        raise Exception("Could not acquire access token")
    
    return response["access_token"]

def get_analytics_rules_arm(subscription_id, resource_group_name, workspace_name):
    url = (
        f"https://management.azure.com"
        f"/subscriptions/{subscription_id}"
        f"/resourceGroups/{resource_group_name}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}"
        f"/providers/Microsoft.SecurityInsights/alertRules"
        f"?api-version=2022-11-01-preview"
    )

    token = get_azure_mgmt_token(tenant_id, client_id, client_secret)

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    return pd.json_normalize(data['value'])
```

### Additional set up
From previous notes we'll need to instantiate the `LogAnalyticsManagementClient`. This client provides access to Azure Log Analytics resources, allowing us to enumerate workspaces and retrieve workspace configuration details.

```python
log_analytics_mgmt_client = LogAnalyticsManagementClient(credentials, subscription_id)
log_query_client = LogsQueryClient(credential=credentials)
```

## Wrangle and aggregate the data
We'll first get all of the data we need then we'll aggregate it. 

### Active tables
From part 1, we can get the active tables.

```python
response = log_analytics_mgmt_client.tables.list_by_workspace(resource_group_name=rg_name, workspace_name=workspace_name)
all_tables_df = pd.json_normalize([item.serialize()["properties"] for item in response])
all_tables_df.drop("schema.columns", axis=1, inplace=True)

query = """
Usage
| distinct DataType
"""

timespan = timedelta(days=90)

results = log_query_client.query_workspace(
    workspace_id=workspace_id,
    query=query,
    timespan=timespan
)

usage_df = pd.DataFrame([item for item in results.tables[0].rows])
usage_df.columns = ["DataType"]

active_tables_df = all_tables_df[
    all_tables_df["schema.name"].
    isin(set(usage_df["DataType"].
    dropna().astype(str)))].
    reset_index(drop=True).copy()
```

### Get Analytics and Detection Rules
Using the functions defined above we can get the Analytics Rules. We'll also add a `rule_source` column to the DataFrame and populate it with the source platform, this will be useful after we look at pulling tables and rules from Defender.

```python
analytics_rules_arm_df = get_analytics_rules_arm()

analytics_rules_arm_df["rule_source"] = "Sentinel"
```

### Extract
Remember, we have 2 ways to identify tables in the Log Analytics Workspace: 

1) The Log Analytics Management Client which gives all tables in the workspace.

2) The `Usage` table which returns all tables that have ingested data within a specified period.

There are times where Analytics Rules are querying tables that haven't recently ingested data. We'll use the `all_tables_df` as our source of truth for tables in the Sentinel workspace. 

What we'll do is tokenize the query to extract identifier-like words from the query text by using a simple regex pattern, then we'll intersect that list with the names of the tables from `all_tables_df`. The lambda function applies the `extract_tables()` helper function to each query in the `properties.query` column, returning a list of known tables referenced in the query. This method is cheap and deterministic, it will only extract keywords that are known table names. 

```python
def extract_tables(query, known_tables):
    tokens = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", query))
    return sorted(tokens & known_tables)

known_tables = set(all_tables_df["name"])

analytics_rules_arm_df["tables"] = (
    analytics_rules_arm_df["properties.query"]
    .fillna("")
    .apply(lambda q: extract_tables(q, known_tables))
)
```

Now, we have a DataFrame with a `tables` column of type list and within those lists are the tables associated with that specific Analytics Rule.

### Reflect
Now we can select specific columns, like `properties.displayName`, `tables`, `kind`, and `properties.enabled` to get a quick summary of the Analytics Rules and the tables referenced.

```python
analytics_rules_arm_df[["properties.displayName", "kind", "tables", "properties.enabled"]]
```
And we'll see output similar to the following.

| Index | properties.displayName           | kind      | tables                                       | properties.enabled |
| ----- | -------------------------------- | --------- | -------------------------------------------- | ------------------ |
| 0     | Advanced Multistage Attack...    | Fusion    | []                                           | True               | 
| 1     | Risky User Sign-In               | Scheduled | [SigninLogs]                                 | True               | 
| 2     | Phishing Email                   | Scheduled | [EmailEvents, EmailUrlInfo, EmailAttachm...] | True               | 
| ...   | ...                              | ...       | ...                                          | ...                |
| 8     | Mass File Download               | NRT       | [OfficeActivity, Operation]                  | True               |
| 9     | Insider Risk - High User Risk... | Scheduled | [SecurityAlert, SecurityIncident, Watchlist] | True               |
| 10    | Failed logon attempts in auth... | Scheduled | [Syslog]                                     | False              |
| ...   | ...                              | ...       | ...                                          | ...                |

Now we're able to quickly look at all of the Analytics Rules and see if the rule is enabled and which tables the rule relies on. 

One thing to note is that Fusion rules aren't associated with a single table; Fusion is a machine learning correlation engine.

## Wrap up
Next time we'll perform similar steps for the Defender platform by getting all tables available in Advanced Hunting, all Custom Detection Rules, and extracting the tables referenced in the Detection Rules' queries. In some later field notes we'll even start to pull in rule run counts and look at how often the rules are creating alerts.

## References 
Microsoft (n.d.). Feature comparison: Microsoft Sentinel analytics rules and Microsoft Defender custom detections. Microsoft, [https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections)

Nutkevitch, N. (2025). Custom detections are now the unified experience for creating detections in Microsoft Defender. Microsoft, [https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875)

Microsoft (n.d.). Advanced multistage attack detection in Microsoft Sentinel, [https://learn.microsoft.com/en-us/azure/sentinel/fusion](https://learn.microsoft.com/en-us/azure/sentinel/fusion)