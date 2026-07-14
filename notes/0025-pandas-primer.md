---
layout: post
title: Analyzing active tables, pt 2.5 - quick Pandas primer
date: 2026-07-14
tags:
    - pandas
    - python
---

# Analyzing active tables, part 2.5... making sense of the metadata and Pandas
I jumped right into writing these field notes without much primer. I don't show trivial configurations, like creating environmental variables and Entra Enterprise Applications, because there's plenty of available material that does.

I do want to take a quick pause to actually look at what we're doing with Pandas, as it'll be heavily used throughout this series on Sentinel and XDR. 

## Introduction
Through this series, and likely others, Pandas is going to show up and be used a lot. We'll use it to organize API responses, compare configurations, summarize telemetry, identify trends, and make larger datasets easier to reason about. 

Pandas is a Python library used for data analysis and manipulation.

Pandas is easy to use without actually understanding what it's truly capable of; the goal of this post is to showcase some of Pandas features and capabilities.

Pandas has (2) core data structures that almost every function and method is built around: Series and DataFrames. Understanding these two objects goes a long way toward understanding Pandas. We'll spend most of our time using DataFrames but we'll still introduce Series.

## Import dependencies
Pandas is usually imported as an alias, `pd`.

```python
import pandas as pd
```

## Series
A Pandas Series is a one-dimensional `ndarray` (n-dimensional) of data, which can be of any type. The Series is indexed and can be created from various data structures like lists, dictionaries, or scalar values.

```python

data = [1, 2, 3, 4, 5]
series = pd.Series(data)
print(series)

0    1
1    2
2    3
3    4
4    5
dtype: int64
```

Individual values can be referenced by using its index.
```python
print(series[1])

2
```

## Data in, DataFrame out
A DataFrame is a tabular data structure where each column is itself a Series. We can create DataFrames from Series, by importing various file types like CSV and JSON, or from dictionaries. 

Create a DataFrame from (2) Series and define the column names with a dictionary.

```python
incident_names_series = pd.Series(["Incident 1", "Incident 2", "Incident 3", "Incident 4", "Incident 5"])

severity_series = pd.Series(["High", "Moderate", "High", "Low", "Informational"])

incidents_df = pd.DataFrame({
    "Incident Name": incident_names_series,
    "Severity": severity_series
})

print(incidents_df)

  Incident Name       Severity
0    Incident 1           High
1    Incident 2       Moderate
2    Incident 3           High
3    Incident 4            Low
4    Incident 5  Informational
```

## DataFrame from dictionaries
DataFrames can be created from dictionaries, with each unique key in the dictionary representing a column.

```python
incidents_list = [
    {
        "Incident Name": "Incident 1",
        "Severity": "High",
        "UPN": "user01@company.com",
        "Details": {
            "Location": "DE",
            "MFA": "failure"
        }
    },
    {
        "Incident Name": "Incident 2",
        "Severity": "Moderate",
        "UPN": "user01@company.com",
        "Details": {
            "Location": "US",
            "MFA": "success"
        }
    },
    {
        "Incident Name": "Incident 3",
        "Severity": "High",
        "UPN": "user10@company.com",
        "Details": {
            "Location": "US",
            "MFA": "success"
        }
    },
    {
        "Incident Name": "Incident 4",
        "Severity": "Low",
        "UPN": "user55@company.com",
        "Details": {
            "Location": "US",
            "MFA": "success"
        }
    },
    {
        "Incident Name": "Incident 5",
        "Severity": "Informational",
        "UPN": "user29@company.com",
        "Details": {
            "Location": "US",
            "MFA": "success"
        }
    }
]

incidents_df = pd.DataFrame(incidents_list)
```

### `pd.json_normalize()
Often times we'll get nested dictionaries in the responses. 

| Index | Incident Name | Severity | UPN | Details |
|------ | ------------  | -------- | --- | ------- |
| 0	| Incident 1 | High	| user01@company.com | {'Location': 'DE', 'MFA': 'failure'} |

The `json_normalize()` Pandas function flattens nested dictionaries into a tablular structure that can be represented in a DataFrame. I generally do this out of habit, to expose all potential features. There are times when it's not needed. 

| Index | Incident Name | Severity | UPN | Details.Location | Details.MFA | 
|------ | ------------  | -------- | --- | ---------------- | ----------- |
| 0	| Incident 1 | High	| user01@company.com | 'DE' | 'failure' |

### API response to DataFrame
In the first note we used the Log Analytics Management Client to get the workspace's table configuration but had to manipulate the response we got from the SDK. The response is of type `azure.core.paging.ItemPaged`, which is an iterator that abstracts paging operations. 

We iterated through the `response`, serialized each item into a dictionary and extracted the data under the `properties` key, to create a list of dictionaries through a list comprehension.

At this point we have a list of dictionaries and Pandas can create dictionaries from many dictionary structures. We invoke the `json_normalize()` Pandas function to flatten any nested dictionaries.

```python
response = log_analytics_mgmt_client.tables.list_by_workspace(resource_group_name=rg_name, workspace_name=workspace_name)
all_tables_df = pd.json_normalize([item.serialize()["properties"] for item in response])
```

## Accessing data in a DataFrame
Through various methods and function we can easily access data in a DataFrame. We saw `usage_df["DataType"]` used in the inner join that created the `active_tables_df` DataFrame.

```python
incidents_df["Severity"]

0             High
1         Moderate
2             High
3              Low
4    Informational
Name: Severity, dtype: str
```

## Removing data
Columns and rows can be dropped from DataFrames using the `drop()` method. We dropped `schema.columns` from the DataFrame because we don't need it for this series.

The `axis=1` parameter instructs the method to operate on columns labeled `schema.columms`. Finally, `inplace=True` updates the specified DataFrame.

## Wrap up
Next time we'll look at interacting with the Advanced Hunting tables in Defender.

## References
Pydata. API reference, https://pandas.pydata.org/docs/reference/index.html
Microsoft Learn. itemPaged Class, https://learn.microsoft.com/en-us/python/api/azure-core/azure.core.paging.itempaged?view=azure-python