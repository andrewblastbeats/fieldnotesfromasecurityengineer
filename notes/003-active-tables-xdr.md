---
layout: post
title: Analyzing active tables, pt 3
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
# Analyzing active tables, part 3
So far we've only looked at pulling data from Microsoft Sentinel and Log Analytics. We have been able to pull configuration information from the management plane via the Log Analytics Management Client and Azure Management API.

<!--more-->

## Introduction
In this field note we'll get the Advanced Hunting Schema and the Custom Detection Rules from the Graph Security API.

## Import dependencies
Import the necessary dependencies from the previous notes.

## Variables
The variables are inclusive of previous field notes in the series.

## Define functions
We'll define (3) functions to assist in getting the schema:

1) `get_graph_api_token()`

2) `get_hunting_schema()`

3) `get_detection_rules()`

### Get Graph API token
```python
def get_graph_api_token():
    tenant_id = os.getenv("TENANT_ID")
    client_id = os.getenv("CLIENT_ID")
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}"
    )

    response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

    if "access_token" not in response:
        raise Exception("Could not acquire access token")
    
    return response["access_token"]
```

### Get hunting schema

```python
def get_hunting_schema():
    url = "https://graph.microsoft.com/beta/security/getHuntingSchema"
    token = get_graph_api_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()
    return pd.json_normalize(data["tables"])
```

### Get detection rules
```python
def get_detectio_rules():
    url = "https://graph.microsoft.com/beta/security/detectionRules"
    token = get_graph_api_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    response = requests.get(
        url,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()
    return pd.json_normalize(data["value"])
```

## Wrangle the data
Now we'll use the functions to get the tables available in Defender XDR and the Custom Detection Rules. 

```python
hunting_schema_df = get_hunting_schema()
detection_rules_df = get_detection_rules()
```

To see all of the available columns in a DataFrame use the `columns` property: `detection_rules_df.columns`. We'll see see a column named `queryConditions.queryText`, which gives us the query associated with that detection rule, similar to the `properties.query` column from the `analytics_rules_arm_df` DataFrame in [part 2](./002-extract-tables.md).

As an example if we `print(detection_rules_df["queryConditions.queryText"][1])` we might see something like this:

```kql
DeviceEvents
| where ingestion_time() > ago(1d)
| where ActionType == "AntivirusDetection"
| summarize (Timestamp, ReportId)=arg_max(Timestamp, ReportId), count() by DeviceId
| where count_ > 5
```

### Extract tables from rules
We'll use the `extract_tables` function from [part 2](./002-extract-tables.md) to tokenize and extract identifier-like words, the tables.

```python
detection_rules_df["tables"] = (
    detection_rules_df["queryConditions.queryText"]
    .fillna("")
    .apply(lambda q: extract_tables(q, set(hunting_schema_df["name"])))
)
```

### Reflect
At this point we have:
- Tables from Defender XDR and Log Analytics
- Detection rules from Defender XDR and Sentinel
- Tables associated with Sentinel rules
- Tables associated with Defender XDR rules
- Tables and their configuration (retention and plan) from Log Analytics

## Wrap up
Next time we'll look at normalizing our table DataFrames so that we have one DataFrame for all detection rules and one DataFrame for all tables.

## References
Microsoft (2026). Create custom detection rules in Microsoft Defender XDR. Microsoft, https://github.com/MicrosoftDocs/defender-docs/blob/public/defender-xdr/custom-detection-rules.md

