---
layout: post
title: Analyzing active tables, pt 6
date: 2026-08-07
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
    - data dictionary
---
I stated that [note 5](./005-active-tables-unify.md) was the last note in this series, but it's not. I'm nearing the end of a responsible data science class and thought this would be a good opportunity to put some ideas into practice. Throughout the course we've discussed how documentation supports the principles of responsible data science; those principles being accountability, fairness, nonmaleficence, privacy, and transparency. 

Data dictionaries, I feel, have the best fit to help wrap up this series by giving the reader a defined data set.

## Table of contents
- [Introduction](#introduction)

## Introduction
A data dictionary defines every field in a dataset, for each column, the dictionary describes what the field is, the field's data type, allowed or expected values, and units. It acts as a reference key that informs users of what the data actually is.

I'm going to define what the Sentinel and Defender DataFrames are going to look like to support my next series of notes; they'll focus on mapping and visualizing the Mitre ATT&CK framework to the detection rules. The data is already in the larger DataFrames and in the next series we'll distill down to these fields. The `all_tables_with_rules_df` DataFrame likely won't change from [post 5](./005-active-tables-unify.md).

## Active tables data dictionary
Here's the data dictionary for the `all_tables_with_rules_df` DataFrame from the end of [post 5](./005-active-tables-unify.md).

| field          | type          | description                                                 | example             |
| -------------- | ------------- | ----------------------------------------------------------- | ------------------- |
| name           | string        | Name of the Sentinel or XDR table referenced by a detection | DeviceProcessEvents |
| platform       | list[string]  | Source platform                                             | Sentinel, Defender  |
| rules          | list[string]  | Name(s) of the detection rule(s) associated with the table  | [Suspicious PowerShell, C-2 NamedPipe] |
| run_count      | float64       | The number of times rules associated with the table have been run | 720.0 |
| alert_count    | float64       | The number of alerts created as a result of rules being run referencing the table | 1.0 |

## Sentinel analytics rule data dictionary 
Here's the data dictionary to support the `analytics_rules_df` DataFrame from [post 4](./004-active-tables-activity.md)/

| field              | type      | description                                                 | example                 |
| ------------------ | --------- | ----------------------------------------------------------- | ----------------------- |
| tables             | list[str] | The tables used in the rule query                           | AzureActivity           |
| name               | string    | Rule display name                                           | New CloudShell User     |
| severity           | string    | The severity of the alert created from the rule             | Informational           |
| run_count          | float64   | The number of alerts the rule generates each run            | 720.0                   |
| alert_count        | float64   | The number of alerts created as a result of rules being run referencing the table | 1.0 |
| tactics            | list[str] | The Mitre ATT&CK tactics that are covered by the rule       | [Discovery, Collection] |
| techniques         | list[str] | The Mitre ATT&CK techniques that are covered by the rule    | [T1595, T1134]          |
| platform           | list[str] | Source platform                                             | Sentinel                |


## Defender custom detections data dictionary 
The Defender custom detections data dictionary is based on the featured columns in the `detection_rules_df` DataFrame.

| field              | type      | description                                                 | example                 |
| ------------------ | --------- | ----------------------------------------------------------- | ----------------------- |
| tables             | list[str] | The tables used in the rule query                           | DeviceNetworkEvents     |
| name               | string    | Rule display name                                           | 3rd Party Apps          |
| severity           | string    | The severity of the alert created from the rule             | Informational           |
| run_count          | float64   | The number of alerts the rule generates each run            | 720.0                   |
| alert_count        | float64   | The number of alerts created as a result of rules being run referencing the table | 1.0 |
| tactics            | list[str] | The Mitre ATT&CK tactics that are covered by the rule       | [Discovery, Collection] |
| techniques         | list[str] | The Mitre ATT&CK techniques that are covered by the rule    | [T1595, T1134]          |
| platform           | list[str] | Source platform                                             | Defender                |

## Lineage 
The lineage documents from which each canonical field was derived. 

| Canonical Field   | Defender Field                                | Sentinel Field         |
| ----------------- | --------------------------------------------- | ---------------------- |
| tactics           | detectionAction.alertTemplate.tactics         | properties.tactics     |
| techniques        | detectionAction.alertTemplate.mitreTechniques | properties.techniques  |
| name              | displayName                                   | properties.displayName |
| severity          | detectionAction.alertTemplate.severity        | properties.severity    |


## Wrap up
I know this was a short one, but the next few should be pretty cool. We're going to create a graph network to visualize what our Mitre ATT&CK coverage looks like. We'll also start to extract some insights from this coverage, like looking at the risks of having one table solely or largely responsible for coverage for a single tactic. 