# Graph-Based ML for Lateral Movement Detection

This project is a cybersecurity machine learning proof-of-concept that uses graph-based features to detect possible lateral movement in enterprise networks.

The project uses `wls_day-01.bz2` from the LANL Unified Host and Network Dataset. The dataset contains de-identified Windows host event logs from an enterprise environment. For this project, authentication-related events are used to build a directed graph of host-to-host activity.

## Problem

Lateral movement is difficult to detect because attackers often use valid credentials and normal internal systems. A single authentication event may look harmless, but a sequence of movements across multiple hosts can reveal suspicious behavior.

## Approach

This project follows these steps:

1. Load LANL Windows host event logs.
2. Filter authentication-related events.
3. Build a directed graph using source and destination hosts.
4. Extract graph-based features.
5. Use Isolation Forest anomaly detection.
6. Save suspicious events and graph visualization.

## Dataset

Dataset used:

- LANL Unified Host and Network Dataset
- File: `wls_day-01.bz2`

The raw dataset file is not included in this repository due to size. Users should download the dataset separately and place it in the `data/` folder.

Expected path:

```text
data/wls_day-01.bz2
```

Dataset source: LANL Unified Host and Network Dataset  
Link: https://csr.lanl.gov/data/2017/

## Event IDs Used

This project focuses on authentication-related Windows event IDs:

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon attempted using explicit credentials |
| 4672 | Special privileges assigned |

## Graph Construction

The LANL host events are converted into a directed graph.

- Nodes represent hosts/systems.
- Edges represent authentication activity between source and destination hosts.
- Red edges in the visualization represent events flagged as suspicious by the anomaly detection model.

Self-loops, where the source and destination are the same host, can be removed to focus more clearly on host-to-host movement.

## Features Used

The anomaly detection model uses graph-based and event-based features such as:

- Edge frequency
- Unique destinations per user
- Unique sources per user
- Source host out-degree
- Destination host in-degree
- Failed logon indicator
- Explicit credential logon indicator
- Special privilege indicator

## Model

This project uses an Isolation Forest model to detect unusual authentication patterns.

Isolation Forest is useful for this proof-of-concept because the dataset does not provide direct labels for every suspicious event. Instead of classifying events as malicious or benign, the model identifies events that look unusual compared to normal authentication activity.

## Results

The project successfully processed LANL Windows host authentication events and created a directed graph of host-to-host authentication activity.

The graph visualization highlights suspicious edges in red. These red edges represent source-to-destination authentication patterns that were flagged as anomalous by the Isolation Forest model.

![LANL Host Authentication Graph](outputs/network_graph.png)

From the generated graph, the model identified several unusual authentication patterns, such as:

- Rare source-to-destination authentication edges
- Hosts connecting to multiple different destination hosts
- Events involving failed logons, explicit credential use, or special privilege assignment
- High-degree nodes that may represent unusual movement behavior or administrative activity

The results show that graph-based features can help identify abnormal authentication behavior that may be related to lateral movement.

However, these alerts are not confirmed attacks. They should be treated as suspicious events that require further analyst investigation in a real SOC or threat hunting workflow.

## Technologies Used

- Python
- Pandas
- NetworkX
- Scikit-learn
- Matplotlib
- Isolation Forest

## Project Structure

```text
graph-based-lateral-movement-detection/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── data/
│   └── wls_day-01.bz2
│
├── src/
│   ├── main.py
│   └── inspect_dataset.py
│
└── outputs/
    ├── anomaly_results.csv
    ├── processed_auth_events.csv
    └── network_graph.png
```

## How to Run

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Place the LANL dataset file in the `data/` folder:

```text
data/wls_day-01.bz2
```

Run the project:

```bash
python src/main.py
```

## Outputs

After running the project, the following files are generated:

| Output File | Description |
|---|---|
| `outputs/processed_auth_events.csv` | Filtered authentication-related LANL events |
| `outputs/anomaly_results.csv` | Events with anomaly scores and suspicious labels |
| `outputs/network_graph.png` | Graph visualization with suspicious edges highlighted |

## Future Improvements

- Use multiple days of LANL host event data.
- Add time-window based graph analysis.
- Remove or separately analyze self-loop authentication events.
- Add GraphSAGE or another Graph Neural Network model.
- Compare different anomaly detection models.
- Build a simple dashboard for analyst review.
- Add SIEM-style alert explanations.

## Disclaimer

This project is for academic and portfolio purposes only. The dataset is de-identified, and this project does not attempt to re-identify users, hosts, or systems.

The suspicious events detected by the model are not confirmed attacks. They are anomaly-based alerts that would require further investigation by a security analyst.