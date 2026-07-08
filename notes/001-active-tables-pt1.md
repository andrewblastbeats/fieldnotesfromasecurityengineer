---
layout: post
title: Analyzing active tables, pt 1
date: 2026-06-30
tags:
    - sentinel
    - xdr
    - microsoft
    - log analytics
    - tables
    - python
---
# Analyzing active tables, part 1
What's an active table? A Log Analytics Workspace or XDR table that:
- has data flowing into it,
- is associated with enabled Analytics or Detection Rules,
- is used regularly in threat hunting,
- is used in a SOAR workflow (so there's some Analytics/Detection Rule that fired)
- or, is just used regularly enough (such that the cost benefits of the lake aren't relevant).

Notes: The list isn't exhaustive. The last point is an edge case and would be really difficult to justify.

<!--more-->

## Introduction
In this introductory field note we will look at how to identify and catalog tables in Microsoft XDR and Sentinel. 

In part 1, we'll get data regarding all of the tables in a workspace using the `LogAnalyticsManagementClient` class. Then we'll perform a 90 day lookback on the `Usage` table to define our first collection of active tables.

## What's needed
We'll need a modern Microsoft Sentinel workspace; so it should be connected to Microsoft Security/XDR portal and the lake should be enabled. 

An account with Log Analytics Reader Azure RBAC role.

## Constraints
The biggest constraint is that XDR's schema discovery currently relies on a internal API (`security.microsoft.com/apiproxy/mtp/huntingService/schema`) that doesn't support external application consumption. The `apiproxy` appears to depend on Defender portal session context (cookies, XSRF, workspace context, and proxy rounting). 

We'll address this gap in another note.

## Dependencies
- [Azure Identity](https://learn.microsoft.com/en-us/python/api/overview/azure/identity-readme?view=azure-python)
- [Log Analytics Management Client](https://learn.microsoft.com/en-us/python/api/overview/azure/mgmt-loganalytics-readme?view=azure-python)
- [Azure Monitor Query Client](https://learn.microsoft.com/en-us/python/api/azure-monitor-query/azure.monitor.query?view=azure-python)
- [Pandas](https://pandas.pydata.org/)

https://learn.microsoft.com/en-us/python/api/overview/azure/security-insights?view=azure-python
## Import dependencies
We'll need to import the following:
```python
import os
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv
import pandas as pd
from azure.identity import DefaultAzureCredential
from aure.mgmt.loganalytics import LogAnalyticsManagementClient
from azure.monitor.query import LogsQueryClient
```

## Variables
We'll need the Azure subscription ID, resource group name, and the Sentinel workspace name.

```python
subscription_id = os.getenv("SUBSCRIPTION_ID")
rg_name = os.getenv("RESOURCE_GROUP_NAME")
workspace_name = os.getenv("WORKSPACE_NAME")
workspace_id = os.getenv("WORKSPACE_ID")

credentials = DefaultAzureCredential()
```

## Instatiate the `LogAnalyticsManagementClient` and `LogsQueryClient` classes
Now, create an instance of the `LogAnalyticsManagementClient` and the `LogsQueryClient`. The management client provides access to Log Analytics resources, allowing us to enumerate workspaces and retrieve workspace configuration details. The query class allows us to run KQL queries on Logs Analytics Workspaces.

```python
log_analytics_mgmt_client = LogAnalyticsManagementClient(credentials, subscription_id)

log_query_client = LogsQueryClient(credential=credentials)
```

## Wrangle and aggregate the data
We'll first get all of the data we need then we'll aggregate it.

### Wrangle - Log Analytics workspace
Let's get all tables in the scoped Log Analytics workspace, note there are a lot. 
```python
response = log_analytics_mgmt_client.tables.list_by_workspace(resource_group_name=rg_name, workspace_name=workspace_name)
all_tables_df = pd.json_normalize([item.serialize()["properties"] for item in response])
all_tables_df.drop("schema.columns", axis=1, inplace=True)
```

### Wrangle - `Usage`
Using the `LogsQueryClient`, we'll get all tables that have had data ingested in the last 90 days.
```python
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
```

### Reflect
At this moment, we have:
1) All tables in the Log Analytics workspace with their table plan, retention, and total retention.
2) All tables that have received data in the last 90 days.

Let's perform an inner join on these two tables by using a mask operation. Remember, an inner join returns only the rows where there is a match in both tables.

```python
active_tables_df = all_tables_df[
    all_tables_df["schema.name"].
    isin(set(usage_df["DataType"].
    dropna().astype(str)))].
    reset_index(drop=True).copy()
```

| Index | retentionInDays   | totalRetentionInDays  | plan      | schema.name     |
| ----- | ----------------- | --------------------- | --------- | --------------- |
| 0     | 31.0              | 31                    | Analytics | SecurityIncident|
| 1     | 31.0              | 31                    | Analytics | SecurityAlert   |
| ...   | ...               | ...                   | ...       | ...             |
| 9     | 31.0              | 90                    | Analytics | AlertInfo       |
| ...   | ...               | ...                   | ...       | ...             |
| ...   | ...               | ...                   | ...       | ...             |
| 53    | 31.0              | 31                    | Analytics | AzureDiagnostics|

## Wrap up
We used the `LogAnalyticsManagementClient` class to get all of the tables in the Log Analytics workspace, including their retention and play type. We'll see in subsequent field notes why having these configuration items is useful.

Next, we used the `LogsQueryClient` class to query the `Usage` table and get the tables that have ingested data in the last 90 days.

Then, we joined the two DataFrames together, but only where the table name was in both the Log Analytics workspace **and** has ingested data, to create a single DataFrame that includes the retention settings, table plan type, and table name.

**Next time:** We'll start looking at Analytics and Detection Rules and extract the tables used in the queries. 