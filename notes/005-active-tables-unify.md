---
layout: post
title: Analyzing active tables, pt 5
date: 2026-07-31
tags:
    - sentinel
    - xdr
    - microsoft
    - log analytics
    - tables
    - python
    - kql
    - pandas
    - data enrichment
    - normalization
---
This series began by identifying which Microsoft Sentinel tables are in use by associating detection rules that use those table by deterministically extracting table references from KQL queries. We then did the same for Defender XDR content, got detection rules, the number of times each rule ran, and the number of alerts generated from each detection. 

Last time, we transformed our DataFrames to view the metrics from the perspective of each table.


<!--more-->

## Table of contents
- [Introduction](#introduction)
- [Dependencies](#dependencies)
- [Merging table activity](#merging-table-activity)
- [Wrap up](#wrap-up)
- [References](#references)

## Introduction
In this note we'll normalize some columns and merge the two DataFrames into one.

We should have two DataFrames:
1) `tables_with_rules_df`
2) `defender_tables_with_rules_df`

We will quickly rename `tables_with_rules_df`:

```python
sentinel_tables_with_rules_df = tables_with_rules_df.copy()
```

## Dependencies
Import the necessary dependencies from the previous notes. 

All dependencies should be available if we run the code from all of the previous field notes.

## Merging table activity
Let's do some operations on the DataFrame to prep them for the merge.

We'll first make sure each DataFrame has the correct associated platform.

```python
sentinel_tables_with_rules_df["platform"] = "Sentinel"
defender_tables_with_rules_df["platform"] = "Defender"
```

We can view the columns in a DataFrame:


```python
sentinel_tables_with_rules_df.columns
```

We see that `sentinel_tables_with_rules_df` has the following columns:
- `retentionInDays`
- `totalRetentionInDays`
- `plan`
- `schema.name`
- `schema.displayName`
- `name`
- `analytics_rules`
- `run_count`
- `alert_count`
- `platform`

And `defender_tables_with_rules_df` has the following columns:
- `name`
- `description`
- `columns`
- `detection_rules`
- `run_count`
- `alert_count`
- `platform`

Where `name`, in both DataFrames, is the name of the tables. We do have to acknowledge that we don't have retention information for Defender XDR tables. The data exists, but it isn't available through APIs that support application permissions, making it unsuitable for unattended automation. Instead, the information is exposed through Microsoft's internal `apiproxy` endpoint, which relies on delegated (user) authentication. (Alex Kefallonitis' XDRRaiderLog shows how to essentially use a service account for these more *interactive* data gets.)

Next, we'll combine the two DataFrames by performing an outer join on the `name` column. An outer join ensures that every row is retained in the final dataset, whether it appears in Microsoft Sentinel, Microsoft Defender XDR, or both. This gives us a complete view of all tables referenced across the two platforms.

The identified `suffix` parameters are appended to any column that exist in both DataFrames. If we didn't specify it, Pandas would use its default suffixes.

```python
all_tables_with_rules_df = sentinel_tables_with_rules_df.merge(
    defender_tables_with_rules_df,
    left_on="name",
    right_on="name",
    how="outer",
    suffixes=("_sentinel", "_defender")
)
```

Now we need to sum the `run_count` and `alert_count` columns. Since we performed an outer join, some tables exist only in one of the two DataFrames. For those rows, the corresponding `run_count` or `alert_count` from the *other* DataFrame will be `NaN` (not a number). But, by replacing those missing values with `0` before summing the columns we can ensure that tables unique to either Microsoft Sentinel or Defender XDR are counted correctly. Or to be more precise, tables unique to detection rules from Sentinel or Defender XDR.

```python
all_tables_with_rules_df["run_count"] = (
    all_tables_with_rules_df["run_count_sentinel"].fillna(0) + all_tables_with_rules_df["run_count_defender"].fillna(0)
)

all_tables_with_rules_df["alert_count"] = (
    all_tables_with_rules_df["alert_count_sentinel"].fillna(0) + all_tables_with_rules_df["alert_count_defender"].fillna(0)
)
```

Next, we need to combine the `analytics_rules` and `detection_rules` columns into a single `rule` column. We'll also create a `platform` column that identifies whether the table is associated with detection rules in Sentinel, Defender, or both. Since some tables only have rules in one platform, we first replace any missing rule lists with empty lists before concatenating them.

```python
all_tables_with_rules_df["rules"] = (
    all_tables_with_rules_df["analytics_rules"].apply(lambda x: x if isinstance(x, list) else []) +
    all_tables_with_rules_df["detection_rules"].apply(lambda x: x if isinstance(x, list) else [])
)

all_tables_with_rules_df["platform"] = all_tables_with_rules_df.apply(
    lambda row: list(dict.fromkeys([
        p for p in [row["platform_sentinel"], row["platform_defender"]] if pd.notna(p)
    ])),
    axis=1
)
```

Finally, we can `drop` a few columns.

```python
all_tables_with_rules_df.drop(
    columns=["platform_sentinel", "platform_defender", "schema.name", "schema.displayName", "run_count_sentinel", "run_count_defender", "alert_count_sentinel", "alert_count_defender"],
    inplace=True
)

all_tables_with_rules_df[["name", "run_count", "alert_count", "rules", "platform]]
```

|     | name                 | alert_count | run_count | rules                                                 | platform   |
| --- | -------------------- | ----------- | --------- | ----------------------------------------------------- | ---------- |
| 0   | OfficeActivity       | 10.0        |  42353.0  | [Mass File Download]                                  | [Sentinel] |
| 1   | Operation            | 10.0        |  42353.0  | [Mass File Download]                                  | [Sentinel] |
| 2   | SigninLogs           | 85.0        |  9484.0   | [Risky User Sign-In, Insider Risk - Risky User Access, Custom detection rule 1, Custom detection rule 3] | [Sentinel, Defender] |
| 3   | Syslog               | 0.0         |  30.0     | [Failed logon attempts in authpriv]                   | [Sentinel] |
| 4   | Watchlist            | 1.0         |  120.0    | [Insider Risk - Risky User Access]                    | [Sentinel] |
| 5   | DeviceProcessEvents  | 78.0        |  720.0    | [Custom detection rule 2]                             | [Defender] |
| ... | ...                  | ...         | ...       | ...                                                   | ...        |

## Wrap up
Now we have a single DataFrame that provide a unified view of every table referenced by our detection content. For each table, we can see how many detection rules reference it, how frequently rules are executing that reference those tables, the name of the rules, and whether the table is used by detection rules in Sentinel, Defender, or both.

We get a complete picture of how our detection content depends on each table and provides the foundation for making informed decisions about data retention, ingestion routing and costs, and identifying tables that may no longer providing value.

## What's next?
I haven't fully fleshed out what I want to dive into next, but I am open to suggestions. There might be a few weeks before the next post as I have to write a final paper for my Responsible Data Science class. 

## References
Kefallonitis, A. (2026). XDRLogRaider, https://github.com/akefallonitis/xdrlograider 