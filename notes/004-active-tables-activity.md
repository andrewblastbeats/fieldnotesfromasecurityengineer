---
layout: post
title: Analyzing active tables, pt 4
date: 2026-07-17
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
Orginally I wanted to have this entry focus on normalization, via mapping of features, the Analytics and Detection Rule DataFrames. But after digging into the schemas of the detection tables for both Defender and Sentinel, it went from what I thought was going to be a relatively straightforward exercise to looking at an architectural concern. I was comparing different implementation of the same underlying concept: detection engineering. Microsoft has acknowledged that the features are different between detection rules in Defender and Sentinel but have not provided much context. A future series might look at this and how we might create a canonical data model for detection engineering.


<!--more-->

## Table of contents
- [Introduction](#introduction)
- [Dependencies](#dependencies)
- [Variables](#variables)
- [Define functions to get Defender and Sentinel data](#define-functions-to-get-defender-and-sentinel-data)
- [Get and aggregate data](#get-and-aggregate-data)
- [Wrap up](#wrap-up)
- [References](#references)

## Introduction
In this post we're going to look at how the detection rules in Defender and Sentinel are being used and their metrics, like how many time it ran. We'll also aggregate the detection rule runs to see how often Log Analytics and Defender tables are being used in detection rules.

One thing to note, is that 

Pulling from the recap from [part 3](./003-active-tables-xdr.md), we have the following DataFrames:

1) `analytics_rules_arm_df`

2) `detection_rules_df`

3) `all_tables_df` (we will rename this to `la_tables_df`)

4) `hunting_schema_df`

And we'll look at creating a single `tables_df` DataFrame and a normalized `detection_rules_df` DataFrame.

## Dependencies
Import the necessary dependencies from the previous notes. 

We'll use the `LogsQueryClient` class from the Azure SDK for Python, `numpy`, and the `timezone` class.

Lastly, we'll make sure we have appropriate permissions and health monitoring configured on the workspace. 

### Import dependencies
```python
from azure.monitor.query import LogsQueryClient
from datetime import datetime, timedelta, timezone
import numpy as np
```

### API permissions
The identity being used must have the `SecurityAlert.Read.All` API claim value to read Defender Alerts.

### Sentinel health
The Sentinel workspace must have auditing and health monitoring enabled and we'll rely on the `SentineHealth` table.

## Variables
The `lookback` period for Defender XDR alerts can be passed in via an OData query and the lookback period for Log Analytics query client can be passed in as a `timedelta` typed parameter, named `timespan`.

```python
lookback = 30
```

## Define functions to get Defender and Sentinel data
We need to define a new function that allows us to get alerts from Defender XDR and the run count and results of Sentinel Analytics Rules.

### Defender alerts
We'll set the default value for `lookback_days` to 30.
```python
def get_xdr_alerts(lookback_days=30):
    url = "https://graph.microsoft.com/beta/security/alerts_v2"
    token = get_graph_api_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    start_time = (datetime.now(timezone.utc) - timedelta(days=lookback_days))
    .strftime("%Y-%m-%dT%H:%M:%SZ")

    response = requests.get(
        f"{url}?filter=createdDateTime ge {start_time}",
        headers=headers,
        timeout=30,
    )

    response.raise_for_status()
    data = response.json()
    return pd.json_normalize(data["value"])
```

### Sentinel Analytics Rules runs
An instance of `log_query_client` should already be defined. If not, we'll use the `DefaultAzureCredential()` class from the Identity SDK.
```python
credentials = DefaultAzureCredential()
log_query_client = LogsQueryClient(credential=credentials)
```

Now let's setup what we need to get run information for Sentinel Analytics Rules. Again, we'll use the `SentinelHealth` table. If you look at this table's features, we have columns `OperationName` and `ExtendedProperties`. We'll use `OperationName` to only pull events relevant to Analytics Rules being run.

```python
def get_sentinel_analytics_rules_runs(lookback_days=30):
    timespan = timedelta(days=lookback_days)
    query = """
        _SentinelHealth()
        | where OperationName in ("Scheduled analytics rule run", "NRT analytics rule run")
        | extend ExtendedProps = parse_json(ExtendedProperties)
        | extend AlertsGenerated = toint(ExtendedProps.AlertsGeneratedAmount)
        | summarize TotalAlertsGenerated = sum(AlertsGenerated), RuleRunCount = count() by SentinelResourceName, SentinelResourceId
    """
    results = log_query_client.query_worksapce(workspace_id=workspace_id, query=query, timespan=timespan)
    analytics_rules_run_df = pd.DataFrame([item for item in results.tables[0].rows]).reset_index(drop=True)
    analytics_rules_run_df.columns = ["name", "id", "alert_count", "run_count"]
    analytics_rules_run_df["platform"] = "Sentinel"
    analytics_rules_run_df["alerts_per_run"] = analytics_rules_run_df["alert_count"] / analytics_rules_run_df["run_count"]
    return analytics_rules_run_df
```

### Table merging and enrichment
This function is pretty cool, it takes the workspace configurations (Log Analytics and Hunting schema), the metrics we will calculate on detection rules, and the tables associated with rules and transforms the data such that we can get metrics on the tables themselves. As we know Defender and Sentinel data have different processes and schemas, whether it's the actual tables in the workspace or getting detection rule run counts, so we need a way to address this.

```python
def enrich_tables_from_rules(
    rules_df: pd.DataFrame,
    schema_df: pd.DataFrame,
    *,
    table_col: str = "tables",
    schema_name_col: str = "name",
    rule_name_candidates = ("name", "displayName", "id"),
    run_count_col: str = "run_count",
    alert_count_col: str = "alert_count",
    output_count_col: str = "rules",
):
    work = rules_df.copy()

    rule_name_col = next((c for c in rule_name_cadidates if c in work.columns), "id")

    rules_exploded = work.explode(table_col).copy()
    rules_exploded = rules_exploded[
        rules_exploded[table_col].notna() &
        (rules_exploded[table_col].astype(str).str.strip() != "")
    ].copy()
    rules_exploded[table_col] = rules_exploded[table_col].astype(str).str.strip()

    by_table = (
        rules_exploded
        .groupby(table_col, as_index=False)
        .agg(
            **{
                output_rules_col: (rule_name_col, lambda s: sorted(set(s.dropna().astype(str)))),
                run_count_col: (run_count_col, "sum"),
                alert_count_col: (alert_count_col, "sum"),
            }
        )
        .rename(colummns={table_col: "tables"})
    )

    schema = schema_df.copy()
    schema["name"] = schema[schema_name_col].astype(str).str.strip()

    enriched = schema.merge(by_table, on="name", how="left")
    enriched[output_rules_col] = enriched[output_rules_col].apply(lambda x: x if isininstance(x, list) else[])
    enriched[run_count_col] = enriched[run_count_col].fillna(0)
    enriched[alert_count_col] = enriched[alert_count_col].fillna(0).astype(int)

    with_rules = enriched[enriched[output_rules_col].str.len() > 0].copy()

    referenced = set(rules_exploded[table_col].unique())
    schema_tables = set(schema["name"].unique())
    missing = pd.DataFrame({"name": sorted(referenced - schema_tables)})

    return enriched, with_rules, missing
```

## Get and aggregate data
We'll use the `detectorId` column from Defender, it's a feature returned by the detection rules and alert APIs, to associate alerts with detection rule that created the alert.

Let's first get the data we need. We'll need `analytics_rules_arm_df` and `detection_rules_df` from previous notes. 

```python
defender_alerts_df = get_xdr_alerts(lookback)
sentinel_alerts_df = get_sentinel_analytics_rules_run(lookback)
```

### Enrich Defender data

Now, we will enrich the Defender `detection_rules_df` DataFrame with operational metrics so we can measure, in a way, rule effectiveness. We'll count the alerts generated by each detection rule, normalize the rule frequency, identify Near Real-Time rules, calculate how many times scheduled rules ran, and calculate their efficiency.

```python
detection_rules_df["platform"] = "Defender"
alert_counts = alerts_df["detectorId"].value_counts()

detection_rules_df["alert_count"] = (
    detection_rules_df["detectorId"]
    .map(alert_counts)
    .fillna(0)
    .astype(int)
)

detection_rules_df["frequency_hours"] = (
    pd.to_timedelta(detection_rules_df["schedule.frequency"])
    .dt.total_seconds()
    .div(3600)
)

detection_rules_df["is_nrt"] = (
    detection_rules_df["schedule.frequency"] == "PT0S
)

detection_rules_df["run_count"] = np.nan

scheduled_mask = ~detection_rules_df["is_nrt"]

hours_in_lookback = lookback * 24

detection_rules_df.loc[
    scheduled_mask,
    "run_count"
] = (
    hours_in_lookback / detection_rules_df
    .loc[scheduled_mask, "frequency_hours"]
).round().astype("Int64")

detection_rules_df["alerts_per_run"] = np.nan

detection_rules_df.loc[
    scheduled_mask,
    "alerts_per_run"
] = (
    detection_rules_df.loc[scheduled_mask, "alert_count"] /
    detection_rules_df.loc[scheduled_mask, "run_count"]
).round(4)

detection_rules_df.rename(
    columns={"displayName": "name"},
    inplace=True
)
```

I recently created these detection rules, which is why  You should have something like this... Do

```python
detection_rules_df[["id", "name", "alerts_per_run", "alert_count", "run_count", "frequency_hours", "tables", "platform"]]
```
|     | id | name                    | alerts_per_run | alert_count | run_count | frequency_hours | tables      | platform |
| --- | -- | ----------------------- | -------------- | ------------| --------- | --------------- | ----------- | -------- |
| 0   | 23 | Custom detection rule 1 |  0.0556        | 40.0        |   720.0   | 1.0             | [SigninLogs]| Defender |
| 1   | 55 | Custom detection rule 2 |  0.2167        | 78.0        |   360.0   | 2.0             | [DeviceProcessEvents]| Defender |
| 2   | 41 | Custom detection rule 3 |  NaN           | 4.0         |   NaN     | 0.0             | [SigninLogs]| Defender |
| ... | ...| ...                     | ...            | ...         | ...       | ...             | ...         | ...      |

If we look closely at the third rule, we can determine that it's a type of Near Real-Time rule. We can also look at the `schedule.frequency` column in the `detection_rules_df` DataFrame.

### Enrich Sentinel data
First we'll create the `analytics_rules_run_df` DataFrame. We'll perform an outer join on the `analytics_rules_arm_df` DataFrame with the `analytics_rules_run_df` DataFrame on the Analytics Rule ID column. 

```python
analytics_rules_run_df = get_sentinel_analytics_rules_run(lookback)

analytics_rules_df = analytics_rules_arm_df.merge(analytics_rules_run_df, on=["id",], how="outer")
analytics_rules_df = analytics_rules_df.dropna(subset=["alert_count", "run_count"], how="all").reset_index(drop=True)
analytics_rules_df.drop(columns=["platform_x", "platform_y"], inplace=True)
analytics_rules_df["platform"] = "Sentinel"
analytics_rules_df["name"] = analytics_rules_df["name_y"]
analytics_rules_df.drop(columns=["platform_x", "platform_y", "name_x", "name_y"], inplace=True)
analytics_rules_df["alerts_per_run"] = analytics_rules_df["alert_count"] / analytics_rules_df["run_count"]
```

Now we have a the ids, alert counts, run counts, and table names associated with each Sentinel detection rule.

```python
analytics_rules_df[["name", "alert_count", "run_count", "tables", "platform"]]
```

|     | name                              | alerts_per_run | alert_count | run_count | tables      | platform |
| --- | --------------------------------- | -------------- | ------------| --------- | ----------- | -------- |
| 0   | Risky User Sign-In                |  0.0046        | 40          |  8644.0   | [SigninLogs]| Sentinel |
| 1   | Failed logon attempts in authpriv |  0.0           | 0.0         |  30.0     | [Syslog]    | Sentinel |
| 2   | Mass File Download                |  0.0002        | 10.0        |  42353.0  | [OfficeActivity, Operation]| Sentinel |
| 3   | Insider Risk - Risky User Access  |  0.0083        | 1.0         |  120.0    | [SigninLogs, Watchlist] | Sentinel |
| ... | ...                               | ...            | ...         | ...       | ...         | Sentinel |

## Pause
Now we have (2) DataFrames that contain enriched Sentinel and Defender data. 

For Defender, we mapped each detection rule to its generated alerts, calculated `alert_count`, estimated the `run_count` from each detection rule's frequency across the lookback window, and calculated an `alerts_per_run` per run metric. 

For Sentinel, we queried the `SentinelHealth` table to get analytics rule run activity, then merged those results with the rule inventory to unify rule metadata, alert counts, and run counts.

## Table activity
Let's look at the activity from the perspective of the tables using the `enrich_tables_from_rules` function.

```python
tables_enriched_df, tables_with_rules_df, missing_tables_df = enrich_tables_from_rules(
    analytics_rules_df,
    all_tables_df,
    table_col="tables",
    schema_name_col="schema.name",
    rule_name_cadidates=("name"),
    run_count_col="run_count",
    alert_count_col="alert_count",
    output_rules_col="analytics_rules",
)

tables_with_rules_df
```

|     | name            | alert_count | run_count | analytics_rules                                       | platform |
| --- | ----------------| ------------| --------- | ----------------------------------------------------- | -------- |
| 0   | OfficeActivity  | 10.0        |  42353.0  | [Mass File Download]                                  | Sentinel |
| 1   | Operation       | 10.0        |  42353.0  | [Mass File Download]                                  | Sentinel |
| 2   | SigninLogs      | 41.0        |  8764.0   | [Risky User Sign-In, Insider Risk - Risky User Access]| Sentinel |
| 3   | Syslog          | 0.0         |  30.0     | [Failed logon attempts in authpriv]                   | Sentinel |
| 4   | Watchlist       | 1.0         |  120.0    | [Insider Risk - Risky User Access]                    | Sentinel |
| ... | ...             | ...         | ...       | ...                                                   | Sentinel |

For now, I'll leave the enriching of the Defender data as an exercise to the reader. Let me know if you have any questions.

## Wrap up
We took a closer look at how Defender and Sentinel detection rules behave in practice by enriching their rule inventories with alert and run metrics. We were able to compare not just which rules exist, but how often they run, how many alerts they generate, and which underlying tables they depend on. We then transformed the data to view it from the perspective of the tables, which allowed us to see which workspace data sources are being used by detection engineering. 

Next time (as long as I don't think of something else) we'll normalize these tables!

## References
- Kumar, M. (2026). Anatomy of the change, https://techcommunity.microsoft.com/blog/microsoftsentinelblog/anatomy-of-the-change/4527934
- Kumar, M. (2026). Detection and automation, reimagined, https://techcommunity.microsoft.com/blog/microsoftsentinelblog/detection-and-automation-reimagined/4527933